// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
)

// setRethIPv6Knobs writes the per-interface IPv6 procfs knobs for a RETH
// member: disable DAD (the virtual MAC may still collide with the peer on
// some deployments) and suppress kernel-generated link-locals (which else
// trigger continuous MLDv2 reports on the L2 segment; VIPs are managed
// explicitly). These are BestEffortKernelKnob procfs writes — a rename(2)
// is impossible on procfs, so they stay direct os.WriteFile. Extracted from
// applyConfigLocked (#1916 §2.D) so the giant apply function is never
// allowlisted in the fsatomic canary; this single-purpose helper is.
func setRethIPv6Knobs(iface string) {
	dadPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", iface)
	os.WriteFile(dadPath, []byte("0"), 0644)
	addrGenPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", iface)
	os.WriteFile(addrGenPath, []byte("1"), 0644)
}

// setVLANSubAddrGenMode suppresses kernel-generated link-locals on a VLAN
// sub-interface (addr_gen_mode=1). BestEffortKernelKnob procfs write,
// extracted from applyConfigLocked (#1916 §2.D) so it can be allowlisted
// without exempting the whole apply function.
func setVLANSubAddrGenMode(iface string) {
	subAddrGen := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", iface)
	os.WriteFile(subAddrGen, []byte("1"), 0644)
}

// applyConfig applies a compiled config to the dataplane / kernel.
// Wraps applyConfigLocked under the apply semaphore for non-context
// callers (DHCP callbacks, config-poll, dynamic feeds, event engine,
// in-process CLI commits, CLI auto-rollback, cluster sync recv).
// Always succeeds in acquiring the lock because Background never
// cancels.
//
// #846: HTTP/gRPC commit handlers go through commitAndApply /
// commitConfirmedAndApply instead, which take the same semaphore
// with a request-bound context so a slow lock holder surfaces 503
// to the client rather than hanging the request.
func (d *Daemon) applyConfig(cfg *config.Config) {
	_ = d.applySem.Acquire(context.Background(), 1)
	defer d.applySem.Release(1)
	// Boot / DHCP-callback / feed / config-poll applies must always run to
	// completion (they are not request-bound and there is no operator waiting
	// to cancel them), so the heavy pipeline is driven with a non-cancellable
	// context — byte-identical to the pre-#2926 behavior.
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		slog.Warn("apply config failed", "err", err)
		return
	}
	// #4957: the active config completed a full apply through the boot /
	// background (DHCP callback, feed, config-poll, in-process CLI commit,
	// rollback) path. Stamp it applied so a peer config-sync of the same text
	// takes handleConfigSync's converged shortcut instead of pointlessly
	// re-applying an already-live config on every reconnect (the config
	// high-water resets on reconnect, so the primary re-pushes the current
	// generation even when nothing changed). A FAILED apply above returns
	// early and leaves the prior digest, so a config that never converged is
	// never marked applied — the same #4957 invariant handleConfigSync relies on.
	if d.store != nil {
		d.store.MarkActiveApplied()
	}
}

// applyConfigResult applies cfg exactly like applyConfig — under the apply
// semaphore with a non-cancellable context — but RETURNS the apply error
// instead of only logging it. The feed onUpdate publication path (#5646) uses
// the returned result to decide whether the feed content was ACCEPTED: the feed
// manager advances its per-feed published-hash only on a nil return, so a
// rejected apply leaves publication debt that the next identical refetch
// retries (rather than committing the content hash and suppressing retry
// forever, the pre-#5646 bug). The returned error is still logged — by
// feeds.installSnapshot's reject branch (feeds side), not by this function.
func (d *Daemon) applyConfigResult(cfg *config.Config) error {
	_ = d.applySem.Acquire(context.Background(), 1)
	defer d.applySem.Release(1)
	return d.applyConfigLocked(context.Background(), cfg)
}

// applyCancelCtx returns the context whose cancellation aborts the heavy apply
// pipeline (applyConfigLocked) at its coarse step boundaries (#2926). It is the
// dedicated DAEMON-STOP context (d.applyCancelContext), deliberately NOT the
// request/commit context AND deliberately NOT d.daemonCtx:
//
//   - A daemon stop MUST abort an in-flight commit/remediation apply at the
//     next boundary so termination is not blocked behind netlink + an FRR
//     reload + a Rust control-socket sync (the #2914/#2868 follow-up). On the
//     next boot the daemon re-applies the active config in full, so skipping
//     the tail of an apply during shutdown always converges.
//   - A mere request cancellation (an HTTP/gRPC client disconnect, or a CLI
//     commit whose context is canceled) MUST NOT abort the apply. By the time
//     applyConfigLocked runs, store.Commit() has already promoted+persisted the
//     new config; aborting the apply on a still-running daemon would leave the
//     store ahead of the dataplane/FRR with no automatic re-apply to converge —
//     a silent forwarding/policy divergence strictly worse than today. The
//     request context still governs the contended applySem wait in the commit
//     wrappers (a slow lock holder surfaces 503), exactly as before.
//
// Why a dedicated context and not d.daemonCtx: in production cmd/xpfd passes
// context.Background() into Run, so d.daemonCtx is never cancelled — returning
// it here would make the C1/C2/C3 boundary checks dead code on a real
// `systemctl stop` (the original #2926 wiring bug). Run creates
// d.applyCancelContext as a child of the SIGTERM/SIGINT signal context, so a
// real daemon stop cancels it; keeping it separate from d.daemonCtx leaves the
// other daemonCtx-derived background goroutines (flow-export, RPM, scheduler,
// cluster comms, the dp.Start dataplane runtime) on their explicit-teardown
// lifetimes, which the orderly shutdown sequence still needs live.
//
// When d.applyCancelContext is unset (early boot, unit tests with no wiring) it
// falls back to a non-cancellable context, so the apply never aborts spuriously.
func (d *Daemon) applyCancelCtx() context.Context {
	if d.applyCancelContext != nil {
		return d.applyCancelContext
	}
	return context.Background()
}

// applyConfigLocked runs the actual reconcile pipeline. MUST be
// called with d.applySem held.
//
// ctx is honored at the coarse phase boundaries marked below (#2926): when it
// is canceled the apply returns ctx.Err() at the NEXT boundary rather than
// completing the netlink + FRR reload + Rust control-socket sync. This lets a
// daemon stop abort an in-flight commit/remediation apply once it is past the
// applySem (the pre-semaphore wait was already cancelled by #2914). The
// boundaries are chosen so a bail leaves a consistent, restart-recoverable
// state — each major side-effecting phase is allowed to finish once started
// (no abort mid-phase), and the next boot re-applies the active config in full.
// Commit callers pass the daemon-lifetime context (applyCancelCtx); the boot /
// DHCP / feed and confirmed-rollback callers pass a non-cancellable context so
// their applies always complete (see applyConfig / executeConfirmedRollback).
func (d *Daemon) applyConfigLocked(ctx context.Context, cfg *config.Config) error {
	if d.applyBodyForTest != nil {
		d.applyBodyForTest(cfg)
		return d.applyErrForTest
	}

	// Defensive nil guard (AGY r2 Low): no production caller passes a nil
	// compiled config (commitAndApply / syncAndApply / the boot apply all
	// nil-check first), but the bootstrap-exit block below reads cfg, and
	// the historical body dereferences cfg.Warnings — make the contract
	// explicit so a future caller cannot panic the reconcile.
	if cfg == nil {
		return nil
	}

	// #5281 defense-in-depth: refuse to reconcile once a factory reset has
	// entered the terminal reset generation. The commit / sync / rollback entry
	// points already reject before persisting, so in practice nothing reaches
	// here during the wipe→stop window; this guards any other applyConfigLocked
	// caller (a boot-time apply, a future path) from re-rendering the erased
	// secrets (frr.conf/swanctl/Kea/login) from the still-resident in-memory
	// ActiveConfig.
	if d.isResetting() {
		return errDaemonResetting
	}

	// Reconcile the whole SNMP subsystem FIRST (#2008 H17, Codex r2; extended
	// to full lifecycle reconcile in #3967). reconcileSNMP matches the running
	// agent + trap-group monitor to the committed config on EVERY commit:
	//   - enable a previously-disabled agent (start the UDP/161 listener),
	//   - disable a running agent (stop the listener),
	//   - swap community authorization / v3 users / trap targets in place on a
	//     still-enabled agent (no listener bounce),
	//   - and start the link-state trap monitor when trap groups appear.
	// Before #3967 only the in-place authorization swap existed and only when
	// SNMP was already enabled at boot — enabling SNMP or adding a trap target
	// day-2 sat inert in the config until a daemon restart.
	//
	// This MUST run before any reconcile step that can abort applyConfigLocked
	// early — specifically the dataplane apply below, which returns early on a
	// required userspace protocol-gate error (compileErrorMustAbortApply:
	// policy-scheduler OR persistent-source-NAT protocol incompatibility, #2138).
	// Store.Commit() has ALREADY promoted and persisted this compiled config
	// before applyConfigLocked runs, so the committed authorization is live
	// regardless of whether the later dataplane apply succeeds. Reconciling
	// only at the tail would leave a committed-downgraded community serving
	// the OLD (read-write) gate on an apply that aborts early. Placed here it
	// is unconditionally before every early-return path in the body (the only
	// aborting one is the dataplane apply at compileErrorMustAbortApply).
	//
	// reconcileSNMP is idempotent: an unchanged SNMP stanza is a no-op (no
	// listener bounce). The in-place swap holds the agent's cfgMu so the UDP
	// listener and in-flight polls are not interrupted. During the boot apply
	// it no-ops the start (snmpBootReady is still false) so the boot block
	// owns the first start, which honors config-only / bootstrap suppression.
	d.reconcileSNMP(cfg)

	// #5866: reconcile the live management HTTP/HTTPS listener + authentication
	// snapshot against the committed web-management config, for the SAME reason
	// and with the SAME early placement as reconcileSNMP above. The management
	// server was constructed once at boot and never reconciled, so a committed
	// bind/port/TLS/api-auth change (e.g. a REVOKED credential) sat inert until a
	// daemon restart. Placed before the dataplane apply so a committed
	// credential revocation is enforced even on an apply that aborts early. A
	// bind-replacement failure is fail-safe (the old listener is retained) and
	// only logged as retry debt — like reconcileSNMP it does not brick an
	// otherwise-successful commit.
	if err := d.reconcileWebManagement(cfg); err != nil {
		slog.Warn("web-management listener reconcile did not converge; retrying on next commit",
			"err", err)
	}

	// #1922 Item 2 bootstrap exit: the FIRST apply of a non-empty config
	// (an interface-claiming confirmed commit, or a cluster SyncApply from
	// the primary) leaves bootstrap mode and runs the one-time startup
	// takeover steps that were suppressed at boot — interface rename, IP
	// forwarding, dataplane arm — BEFORE the reconcile below wires the
	// config onto them. Exit is one-way for the daemon's lifetime. An empty
	// config (no interfaces) does NOT exit bootstrap (a confirmed-but-empty
	// commit is not a takeover). Runs under d.applySem (the caller holds it).
	if d.inBootstrap() && cfg != nil && len(cfg.Interfaces.Interfaces) > 0 {
		d.exitBootstrapMode("first non-empty config applied")
		d.runBootstrapExitStartup(cfg)
	}

	// #4179 config-arrival re-naming: a config-less HA node (node-id present,
	// no committed config at boot) is NOT in bootstrap mode, so the block above
	// never fires for it. That node named its NICs STANDALONE at boot; the
	// first non-empty config to arrive (a cluster SyncApply from the primary,
	// or a local commit) finally supplies its cluster identity, so re-run
	// startup naming here — BEFORE the reconcile below wires the config onto
	// the interfaces — to reconcile them to the node's cluster names. One-shot;
	// a no-op on a standalone config or any later commit.
	d.maybeReapplyConfigArrivalNaming(cfg)

	// Reset VIP warning suppression so new config gets fresh warnings.
	d.vipWarnedIfaces = nil

	// Log config validation warnings
	for _, w := range cfg.Warnings {
		slog.Warn("config validation", "warning", w)
	}

	ctxErr, vrfErr := d.applyVRFReconcile(ctx, cfg)
	if ctxErr != nil {
		// #5643 Gap B: the #2926 C1 boundary lives inside applyVRFReconcile and
		// returns ctx.Err() before the netlink phase. Store.Commit already
		// promoted UPSTREAM, so a daemon-stop cancel landing here is post-
		// promotion too — funnel it through the same host-authorization closeout
		// as C2/C3 so the committed nft/login/root-auth tightening is enforced
		// even when the apply is abandoned at the earliest boundary.
		return d.closeoutHostAuthOnCancel(ctxErr, cfg)
	}
	// #5700: vrfErr is the DEFERRED VRF-device-setup failure (a genuine, non-
	// cancellation ReconcileVRFs error). The rest of the apply still runs; it is
	// threaded into the tail commit-error join below so the commit fails closed
	// (with a retry owner) instead of reporting a VRF configured while its device
	// is absent — exactly like ifaceErr/routeLeakErr/routingRuleErr.

	// #5867: program the DHCP-learned management-VRF routes and capture the
	// RouteReplace / cleanup failure as a DEFERRED error. A route whose
	// destination stayed but whose gateway/output-interface changed and then
	// failed to replace no longer leaves the stale route protected (the reconcile
	// keys the protect-set on the full route identity, so the stale route is
	// cleaned up) — and the failure is threaded into the tail commit-error join
	// below so the commit fails closed instead of acknowledging a management
	// route pinned to a stale/de-authorized gateway. Deferred (not fatal here)
	// exactly like ifaceErr/routeLeakErr/routingRuleErr: the rest of the apply
	// still runs.
	mgmtRouteErr := d.applyMgmtVRFRoutes()

	// #5310: capture the interface-reconcile failure (xfrmi/bond/tunnel/legacy-
	// reth) and thread it into the tail commit-error join so a genuine reconcile
	// failure (e.g. a route-based VPN's xfrmi that could not be created) fails
	// the commit closed instead of reporting false success. All later reconcile
	// steps still run — the error is deferred to the tail exactly like
	// networkdErr/hostInboundErr/lo0Err (fail-closed but complete).
	ifaceErr := d.applyInterfaceReconcile(cfg)

	d.applyFabricIPVLAN(cfg)

	// 1.9–2.7. Dataplane apply + RETH-MAC/VIP/worker-rebind critical section
	// (#4407). Returns the ip-monitoring commit overlay and the captured
	// networkd write error for the routing rules + tail reconcile below; an
	// error (a #2926 context abort or an ApplyConfig compile abort) bails
	// before the tail.
	commitOverlay, networkdErr, applyErr, err := d.applyDataplaneAndHACore(ctx, cfg)
	if err != nil {
		// #5643 (M35): applyDataplaneAndHACore bailed at a #2926 ctx-cancellation
		// boundary (C2 before the dataplane apply, or C3 after it) because the
		// daemon is stopping mid-apply. Store.Commit ALREADY promoted+persisted
		// this config UPSTREAM of applyConfigLocked, so the durable config has
		// advanced, and at C3 the Rust dataplane may already enforce it — but the
		// nft host-authorization + login/credential tail (applyTailReconciles) has
		// NOT run. Unlike FRR/IPsec/DHCP/RA/VRRP/syslog/exporters, those owners do
		// NOT converge on the next boot while the daemon stays intentionally
		// stopped: the kernel xpf_lo0/xpf_hostinbound nft tables and the OS
		// login/sudo/root-SSH/root-authentication credentials persist on the box
		// independent of xpfd. Skipping them here would leave the OLD, more-
		// permissive host authorization live for the entire stop window — a
		// monotonic-revocation violation (a committed management-access tightening
		// silently deferred by the cancel). closeoutHostAuthOnCancel runs just
		// those security-critical owners to completion — bounded (two nft loads +
		// local credential reconciles, no FRR/netlink reload) and non-cancellable
		// — against the committed config before propagating the cancellation. A
		// non-cancellation error (an ordinary compile-abort) returns unchanged.
		// The non-security tail is intentionally left to next-boot convergence
		// (the #2926 C3 contract).
		return d.closeoutHostAuthOnCancel(err, cfg)
	}

	// #5844: applyRoutingRules RETURNS the joined next-table / rib-group / PBR
	// ip-rule reconcile failures (a partial clear/add left stale-or-missing
	// cross-VRF policy in the kernel). Capture it as a DEFERRED error — the
	// snapshot republish below still runs (so it is not left stale), and the
	// failure is threaded into the tail commit-error join so the commit fails
	// closed instead of being acknowledged after a partial reconcile.
	routingRuleErr := d.applyRoutingRules(cfg, commitOverlay)

	// #5642: the full dataplane apply (applyDataplaneAndHACore → d.dp.ApplyConfig)
	// ran BEFORE applyRoutingRules and built its userspace route snapshot from the
	// PRE-reconcile kernel ip-rule table (buildRouteSnapshots enumerates the live
	// ip-rules via netlink.RuleList). On a rib-group / next-table transition —
	// notably the final rib-group removal handled just above — applyRoutingRules
	// has now deleted (or added) the synthetic leak ip-rule, so the snapshot
	// ApplyConfig already published is stale. Rebuild + republish the routes-only
	// snapshot against the now-reconciled kernel rules so the userspace FIB does
	// not retain a deleted-VRF inter-VRF leak. A no-op (content-hash duplicate
	// skip) when the route set did not move. #5696 (M19): a genuine republish /
	// FIB-bump failure is a DEFERRED error threaded into the tail errors.Join —
	// this reconcile has no dirty-retry owner, so a swallowed failure would keep
	// the stale leak on a "successful" commit.
	routeLeakErr := d.reconcileRouteLeakSnapshot(cfg, commitOverlay)

	ipsecErr, dhcpServerErr := d.applyServicesReconcile(cfg)

	// Steps 8–21: tail reconcile dispatches (VRRP, system config, syslog,
	// login/SSH, archival, observability, cluster runtime, host tunables).
	// Extracted into applyTailReconciles (#4407 Phase A). The head above
	// is decomposed into named phase methods (#4407): the decoupled
	// setup/reconcile phases (loadable independently) — applyVRFReconcile,
	// applyInterfaceReconcile, applyFabricIPVLAN, applyRoutingRules,
	// applyServicesReconcile — and the ordering-entangled dataplane-apply /
	// RETH-MAC core that stays inline (it threads applyResult / rethMACPending
	// / the deferred errors). The tail is independent per-subsystem dispatch
	// reading only cfg (+ nil-guarded managers), so grouping it here is a
	// behavior-preserving mechanical move. The five head-produced deferred
	// errors (networkdErr/applyErr/dhcpServerErr/ipsecErr/ifaceErr) are threaded
	// in — applyErr is the #5679 ordinary (non-abort) dataplane-apply failure
	// that must fail the commit without disarming/aborting; routeLeakErr is the
	// #5696 route-leak republish/FIB-bump failure; routingRuleErr is the #5844
	// next-table/rib-group/PBR ip-rule reconcile failure (a partial kernel
	// policy-routing clear/add); the helper creates lo0Err/hostInboundErr and
	// returns the joined errors.
	return d.applyTailReconciles(cfg, networkdErr, applyErr, dhcpServerErr, ipsecErr, ifaceErr, routeLeakErr, routingRuleErr, mgmtRouteErr, vrfErr)
}

// applyHostAuthorizationCloseout runs ONLY the security-critical host-
// authorization owners of the apply tail — the kernel nft lo0/host-inbound
// filters and the OS login/sudo/root-SSH/root-authentication credential
// reconciles — against cfg. It is the bounded, non-cancellable closeout invoked
// from applyConfigLocked (via closeoutHostAuthOnCancel) when an apply is
// abandoned at a #2926 ctx-cancellation boundary AFTER Store.Commit promoted the
// config (#5643 / M35).
//
// These owners are singled out from the rest of applyTailReconciles because,
// unlike FRR/IPsec/DHCP/RA/VRRP/syslog/exporters (which the next boot re-renders
// from the active config, so the #2926 skip converges), they persist on the box
// independently of xpfd and therefore do NOT converge while the daemon is
// intentionally stopped: the kernel xpf_lo0/xpf_hostinbound tables keep enforcing
// whatever generation was last loaded, and a removed login user / revoked sudo
// grant / re-enabled root SSH / stale root password + /root/.ssh/authorized_keys
// stays on disk. Leaving them at the pre-cancel (more permissive) generation
// after a committed tightening is the monotonic-revocation violation M35
// identifies.
//
// The steps mirror applyTailReconciles' step 9.5–13 order exactly. Both nft
// applies fail closed (#3392/#3333). #5874: the login/credential reconcilers
// (applySystemLogin, reconcileSudoers, reconcileAbsentLoginUsers, applySSHConfig
// and applyRootAuth — the SOLE manager of root's /etc/shadow password and
// /root/.ssh/authorized_keys) were previously best-effort VOIDS here, so a
// failure to reconcile a credential to the cancelled/target state was silently
// DISCARDED and the cancel reported clean. They now return their accumulated
// failures, this closeout COLLECTS a per-owner outcome and SURFACES every
// failure, and the "bounded" claim is now an ENFORCED wall-clock budget
// (hostAuthCloseoutBudget) rather than an unbounded best-effort sequence: a
// wedged reconciler is reported timed-out instead of hanging the daemon-stop
// path. Still safe to run non-cancellably — no FRR/netlink reload.

// applyDataplaneAndHACore runs the ordering-entangled dataplane-apply and
// RETH-MAC / VRRP-VIP / AF_XDP-worker-rebind critical section of a config
// apply (#4407). Extracted verbatim from applyConfigLocked; the head-produced
// state that the earlier decoupled phases do not touch stays local here —
// rethMACPending and the deferred-worker-startup flag/defer are self-contained
// — and the two values the tail still needs are returned: the ip-monitoring
// commit overlay (fed to applyRoutingRules and the FRR render), the captured
// networkd write error, and the DEFERRED ordinary dataplane-apply error
// (#5679) — both threaded into applyTailReconciles' Join. The three early
// error returns — the two #2926 context-abort boundaries (ctx.Err() before
// ApplyConfig and before the FRR reload) and the compileErrorMustAbortApply
// dataplane abort on an ApplyConfig failure — are preserved; the caller bails
// (via the terminal `err` return) without running the routing / service / tail
// reconciles, exactly as the inline `return err` did.
//
// applyErr (#5679) is DISTINCT from that terminal `err`: an ORDINARY (non-abort
// -class) ApplyConfig failure does NOT disarm the dataplane — the OLD compiled
// config stays live and forwarding — so the tail reconciles MUST still run
// (fail-closed but complete, exactly like networkdErr / ifaceErr). It is
// returned as a deferred error the caller joins at the tail so the commit
// reports FAILURE rather than silently succeeding against the stale policy,
// instead of aborting the rest of the apply. commitOverlay, networkdErr, and
// applyErr are named returns so the pre-networkd boundaries can return them
// (nil) before the networkd / apply phases assign them. Runs in the same slot,
// after the fabric-IPVLAN reconcile and before the routing rules.
func (d *Daemon) applyDataplaneAndHACore(ctx context.Context, cfg *config.Config) (commitOverlay []config.RouteOverlayEntry, networkdErr error, applyErr error, err error) {
	// 1.9. Pre-check: will RETH MAC programming require a link cycle?
	// If yes, tell the userspace DP to skip initial worker startup during
	// ApplyConfig(). Workers will be started by NotifyLinkCycle() after MAC
	// programming is done. This avoids the double-bind that causes EBUSY
	// on mlx5 zero-copy queues.
	rethMACPending := false
	deferWorkersActive := false
	var clearDeferWorkers func()
	if d.cluster != nil && cfg.Chassis.Cluster != nil && d.dp != nil {
		cc := cfg.Chassis.Cluster
		for rethName, physName := range cfg.RethToPhysical() {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg == nil || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			link, err := netlink.LinkByName(linuxName)
			if err != nil {
				continue
			}
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			if !bytes.Equal(link.Attrs().HardwareAddr, mac) {
				rethMACPending = true
				break
			}
		}
		if rethMACPending {
			d.setDataplaneDeferWorkers(true)
			deferWorkersActive = true
			clearDeferWorkers = func() {
				d.setDataplaneDeferWorkers(false)
			}
			defer func() {
				if deferWorkersActive {
					clearDeferWorkers()
				}
			}()
		}
	}

	policySchedulerApplyTime := time.Now()
	policySchedulerActiveState := d.policySchedulerActiveStateForApplyLocked(cfg, policySchedulerApplyTime)
	d.seedPolicySchedulerActiveStateLocked(policySchedulerActiveState)

	// 1.95. Refresh the dataplane's ip-monitoring overlay cache from
	// the engine BEFORE the full snapshot build (#1827, AGY r2-2): an
	// operator commit while a policy is FAILED must rebuild routes
	// with the active overlay instead of wiping the injected failover
	// route until the next engine tick. The overlay is filtered
	// against the INCOMING config (Codex PR #1843 HIGH-1) so a commit
	// that removes or edits a policy never republishes the stale
	// entries; the same filtered view feeds the FRR render in step 3.
	commitOverlay = d.commitOverlayForConfig(cfg)
	if setter, ok := d.dp.(routeOverlaySetter); ok {
		setter.SetRouteOverlay(commitOverlay)
	}

	// 1.95. Reconcile the running dynamic-address feed-producer set against
	// this config generation BEFORE reading its overlay (#5036). This is what
	// makes a day-2 feed-server add/remove/edit take effect: the feed manager
	// is constructed unconditionally at boot, and this hash-gated Apply starts
	// the replacement producers (and joins removed ones) whenever the
	// feed-server config changes. A feed CONTENT refresh leaves the hash
	// unchanged, so it does not restart the fetchers. Must run before the
	// SetFeedSnapshots overlay push below so the overlay reflects the
	// reconciled generation (the fresh snapshot lands asynchronously and its
	// onUpdate re-applies, exactly as at boot).
	d.reconcileFeeds(cfg)

	// 1.96. Refresh the dataplane's dynamic-address feed overlay from the
	// feed manager BEFORE the full snapshot build (#2049). The feed manager
	// fetches threat-feed/allowlist prefixes and its onUpdate callback
	// re-enters applyConfig against the SAME *config.Config; without this
	// hand-off the address book the helper enforces would never see the
	// feed prefixes (the never-enforced gap #2049 closes). The overlay is
	// joined against the INCOMING config's bindings so a commit that removes
	// a binding stops enforcing its feed. Mirrors SetRouteOverlay above.
	if setter, ok := d.dp.(feedSnapshotSetter); ok {
		setter.SetFeedSnapshots(d.feedSnapshotsForConfig(cfg))
	}

	// #2926 boundary C2: before the dataplane apply (the Rust control-socket
	// sync push). The fabric-IPVLAN / VRF / tunnel / bond netlink reconciles
	// above are idempotent and have each run to completion, so bailing here
	// leaves a consistent kernel state with the dataplane untouched. Once
	// d.dp.ApplyConfig and the RETH MAC / VIP / worker-rebind sequence that
	// follows it begin, they run as one unit (no mid-sequence abort) — the
	// next boundary is before the FRR reload.
	if err := ctx.Err(); err != nil {
		return commitOverlay, networkdErr, nil, err
	}

	// 2. Apply dataplane config through the runtime config sink.
	var applyResult *dataplane.ApplyResult
	if d.dp != nil {
		var err error
		if applyResult, err = d.dp.ApplyConfig(context.Background(), cfg); err != nil {
			d.recordCompileFailure(err)
			if compileErrorMustAbortApply(err) {
				return commitOverlay, networkdErr, nil, err
			}
			// #5679: an ORDINARY (non-abort-class) full-apply failure does
			// NOT disarm the dataplane — d.dp.ApplyConfig leaves the OLD
			// compiled policy live and forwarding while store.Commit has
			// already promoted+persisted the NEW config. Left unhandled the
			// commit reported SUCCESS against stale enforcement (a tightening
			// commit — e.g. a new deny — appeared applied while the looser old
			// policy was still on the wire), a fail-open-to-stale on the main
			// config-apply path. Capture the failure as a DEFERRED commit error
			// (threaded into the tail Join, fail-closed but complete like
			// networkdErr / ifaceErr) so the operator sees the commit fail; the
			// applied config never advanced, so an identical re-commit / the
			// feed onUpdate retry (#5646, via applyConfigResult) re-applies and
			// self-heals a transient helper / control-socket error.
			applyErr = err
		} else {
			d.recordCompileSuccess()
		}
	}
	policySchedulerActiveState = d.reconcilePolicySchedulerLockedAt(cfg, policySchedulerApplyTime)
	d.publishInitialPolicySchedulerStateLocked(cfg, policySchedulerActiveState, applyResult)

	// Clear defer flag after ApplyConfig so subsequent applies (where MAC
	// is already set) don't skip workers.
	if deferWorkersActive {
		clearDeferWorkers()
		deferWorkersActive = false
	}

	// 2.1. Wire aggressive session aging config to GC.
	if d.gc != nil {
		d.gc.SetAgingConfig(
			cfg.Security.Flow.AgingEarlyAgeout,
			cfg.Security.Flow.AgingHighWatermark,
			cfg.Security.Flow.AgingLowWatermark,
		)

		// Enable per-IP session counting if any screen profile has session limits.
		sessionLimitEnabled := false
		for _, sp := range cfg.Security.Screen {
			if sp.LimitSession.SourceIPBased > 0 || sp.LimitSession.DestinationIPBased > 0 {
				sessionLimitEnabled = true
				break
			}
		}
		d.gc.SetSessionLimitEnabled(sessionLimitEnabled)
	}

	// 2.2. Build zone→RG map for per-RG session sync.
	if ss := d.getSessionSync(); ss != nil && applyResult != nil {
		ss.SetZoneRGMap(buildZoneRGMap(cfg, applyResult.ZoneIDs))
	}

	// 2.45. #1956 V-4: managed->unmapped teardown MUST run BEFORE
	// networkd.Apply so its stale-file sweep has nothing to half-clean.
	// No-op idempotent when nothing transitioned (zero churn on an
	// unrelated commit).
	//
	// A genuine teardown failure (rename-back EBUSY/collision or networkctl
	// reload failure) is now RETURNED and RETAINS the durable .link/.network
	// markers (#5309). It is captured into networkdErr (the interface-management
	// error already threaded into the tail commit join) so the commit fails
	// CLOSED instead of reporting success while the wrong live interface name
	// persists and the retry debt is destroyed. errors.Join preserves any error
	// the later networkd.Apply also records.
	if cfg.Chassis.DeviceMap.Active() {
		if err := teardownUnmappedManaged(cfg.Chassis.DeviceMap, protectedForConfig(cfg)); err != nil {
			slog.Warn("device-map teardown failed; retaining durable state, failing commit closed",
				"err", err)
			networkdErr = errors.Join(networkdErr, err)
		}
	}

	// 2.5. Write systemd-networkd config for managed interfaces.
	//
	// An empty ManagedInterfaces set is NOT a no-op (#2988): when the last
	// xpf-managed interface is removed, networkd.Apply must still run so its
	// stale `10-xpf-*` sweep cleans the now-orphaned .network/.link/.netdev
	// snippets (otherwise the next reload resurrects stale addresses/bonds/
	// renames). The previous `len(...) > 0` guard shadowed the sweep, leaving
	// the library fix dead on the live reconcile path. The lifeline is still
	// protected end-to-end: SetProtectedResolver (daemon_run.go) feeds
	// resolveProtectedInterfaces, which derives the mgmt set from
	// ActiveConfig independently of ManagedInterfaces, so the empty-set sweep
	// preserves the management NIC's files. The `applyResult != nil` guard
	// stays — a nil result (no dataplane) means there is nothing to reconcile
	// and the daemon's own startup/Clear paths own the files.
	//
	// A write failure is captured (not swallowed, #2987) and returned at the
	// tail of applyConfigLocked so the commit reports failure (fail-closed),
	// mirroring dhcpServerErr: every downstream reconcile step still runs so a
	// networkd write error does not skip RETH MAC programming, VRRP VIP
	// reconcile, FRR, RA, IPsec, etc. and leave HA state half-applied.
	if d.networkd != nil && applyResult != nil {
		if err := d.networkd.Apply(applyResult.ManagedInterfaces); err != nil {
			slog.Warn("failed to apply networkd config", "err", err)
			// errors.Join (not assignment) so a device-map teardown failure
			// recorded just above (#5309) is not clobbered — both fail-closed.
			networkdErr = errors.Join(networkdErr, fmt.Errorf("apply networkd config: %w", err))
		}
	}

	// 2.6. Program deterministic virtual MACs on RETH member interfaces.
	// Each node gets a per-node MAC (02:bf:72:CC:RR:NN) to avoid FDB conflicts
	// when both nodes' members are on the same L2 domain. VRRP + gratuitous NA
	// handle failover; RA goodbye packets handle IPv6 default gateway transitions.
	// Must run AFTER networkd.Apply() so .link renames are applied first.
	needLinkCycleRecovery := false
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		rethToPhys := cfg.RethToPhysical()

		// PrepareLinkCycle is called on-demand after programRethMAC reports
		// an actual link DOWN/UP cycle. Most drivers (mlx5, virtio) support
		// IFF_LIVE_ADDR_CHANGE so no cycle is needed and workers keep running.

		for rethName, physName := range rethToPhys {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg == nil || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			// If the interface doesn't exist under its config name,
			// find it by RETH virtual MAC and rename it.
			if _, err := netlink.LinkByName(linuxName); err != nil {
				mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
				if oldName := renameRethMember(linuxName, mac); oldName != "" {
					slog.Info("renamed RETH member interface",
						"from", oldName, "to", linuxName)
					fixRethLinkFile(linuxName, oldName)
				}
			}
			// Ensure the .link file uses OriginalName= (not MACAddress=)
			// for stable matching across reboots. The bootstrap .link
			// files may use MACAddress= which breaks after virtual MAC
			// programming — the interface reboots with physical MAC but
			// the MACAddress= line might reference the wrong one.
			ensureRethLinkOriginalName(linuxName)
			setRethIPv6Knobs(linuxName)
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			linkCycled, err := programRethMAC(linuxName, mac)
			if err != nil {
				slog.Warn("failed to set RETH MAC", "iface", linuxName, "mac", mac, "err", err)
			}
			if linkCycled && !needLinkCycleRecovery {
				// First link cycle — stop workers NOW (they may have
				// been accessing UMEM during the DOWN/UP). The rebind
				// in NotifyLinkCycle will restart them.
				if d.dp != nil {
					slog.Info("userspace: stopping workers after RETH MAC link cycle")
					d.dp.Link().PrepareLinkCycle()
				}
			}
			needLinkCycleRecovery = needLinkCycleRecovery || linkCycled
			clearDadFailed(linuxName)
			removeAutoLinkLocal(linuxName)
			// Re-add link-local if this parent interface has IPv6 on unit 0.
			// NDP Neighbor Solicitation requires a link-local source address.
			if rethUnitHasIPv6(rethCfg, 0) {
				ensureRethLinkLocal(linuxName)
			}

			// Re-disable VLAN RX offload after MAC programming.
			// The iavf VF driver resets ethtool features (including
			// rx-vlan-offload) during the link down/up cycle that
			// programRethMAC requires. Without this, XDP cannot see
			// VLAN tags in the packet data and drops VLAN traffic.
			if out, err := runCommandTimeout("ethtool", "-K", linuxName, "rxvlan", "off"); err != nil {
				slog.Warn("failed to re-disable rxvlan after RETH MAC",
					"interface", linuxName, "err", err, "output", strings.TrimSpace(string(out)))
			} else {
				slog.Info("re-disabled VLAN RX offload after RETH MAC", "interface", linuxName)
			}

			// Propagate MAC change to VLAN sub-interfaces.
			// Linux VLAN sub-interfaces don't always inherit the
			// parent's MAC change after link down/up.
			if parentLink, err := netlink.LinkByName(linuxName); err == nil {
				parentIdx := parentLink.Attrs().Index
				links, _ := netlink.LinkList()
				for _, l := range links {
					if l.Attrs().ParentIndex != parentIdx {
						continue
					}
					subName := l.Attrs().Name
					// Suppress auto link-local on VLAN sub-interfaces too.
					setVLANSubAddrGenMode(subName)
					if !bytes.Equal(l.Attrs().HardwareAddr, mac) {
						if err := netlink.LinkSetHardwareAddr(l, mac); err != nil {
							slog.Warn("failed to propagate MAC to VLAN sub-interface",
								"iface", subName, "err", err)
						} else {
							slog.Info("propagated RETH MAC to VLAN sub-interface",
								"iface", subName, "mac", mac)
						}
					}
					removeAutoLinkLocal(subName)
					// Re-add link-local if this VLAN sub-interface has IPv6.
					// Extract VLAN ID from sub-interface name (e.g. "ge-7-0-1.100").
					if dotIdx := strings.LastIndex(subName, "."); dotIdx >= 0 {
						if vid, err := strconv.Atoi(subName[dotIdx+1:]); err == nil {
							if rethUnitHasIPv6(rethCfg, vid) {
								ensureRethLinkLocal(subName)
							}
						}
					}
				}
			}
		}
	}

	// 2.6b. Reconcile VRRP VIPs and stable link-locals after RETH MAC
	// programming. Only needed when programRethMAC had to bring the
	// interface DOWN/UP (link cycle), which removes all addresses
	// including VRRP VIPs and stable link-locals.
	if needLinkCycleRecovery && d.isNoRethVRRP() {
		// Direct mode: re-add VIPs + stable link-locals for each RG
		// where we are primary.
		if d.cluster != nil {
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				if d.cluster.IsLocalPrimary(rg.ID) {
					d.directAddVIPs(rg.ID)
					d.addStableRethLinkLocal(rg.ID)
					d.scheduleDirectAnnounce(rg.ID, "link-cycle-recovery")
				}
			}
		}
	} else if needLinkCycleRecovery && d.vrrpMgr != nil {
		d.vrrpMgr.ReconcileVIPs()
		// Re-add stable link-locals for active RGs after MAC bounce.
		if d.cluster != nil && cfg.Chassis.Cluster != nil {
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				s := d.getOrCreateRGState(rg.ID)
				if s.IsActive() {
					d.addStableRethLinkLocal(rg.ID)
				}
			}
		}
	}

	// 2.6b2. Rebind AF_XDP sockets after RETH MAC programming.
	// Only needed when PrepareLinkCycle was called (macChangeNeeded=true
	// or rethMACPending=true). Calling NotifyLinkCycle without a prior
	// PrepareLinkCycle causes a spurious rebind that gets EBUSY on mlx5
	// zero-copy queues because the first bind is still in progress.
	if d.dp != nil && needLinkCycleRecovery {
		// Actual link DOWN/UP occurred — old XSK sockets are dead.
		// Rebind to create fresh sockets on the reinitialized queues.
		d.dp.Link().NotifyLinkCycle()
		if d.ra != nil {
			d.ra.ResendBurst()
		}
	} else if d.dp != nil && rethMACPending && !needLinkCycleRecovery {
		// MAC set live (no link cycle) but workers were deferred.
		// Trigger a re-apply to start workers with the now-correct MAC.
		// This is cheaper than NotifyLinkCycle (no stop_workers/rebind).
		d.reapplyAfterDeferredMAC(cfg)
	}

	// NOTE: stable link-local cleanup for secondary RGs is handled by
	// the reconcile loop (reconcileRGState) after election settles,
	// not here — we don't know who's primary during config apply.

	// 2.6c. Reconcile proxy ARP/NDP entries for NAT addresses. Factored into
	// reconcileProxyARP so the always-on periodic re-assert loop (#2197 item
	// 2) can re-run the identical reconcile after a non-commit link cycle.
	d.reconcileProxyARP(cfg)

	// 2.7. Re-bind management VRF interfaces after networkd.Apply().
	// networkctl reconfigure strips VRF master bindings because networkd
	// considers the daemon-created vrf-mgmt device "unmanaged" and ignores
	// the VRF= directive. Re-bind here to restore VRF membership. This is the
	// AUTHORITATIVE management-VRF bind (post-networkd): #5700 surfaces its
	// failure into commit truth (joined into networkdErr — mirroring the #1956
	// device-map-teardown joins above) instead of swallowing at WARN, so a
	// genuine bind failure fails the commit closed rather than reporting the
	// management VRF configured while the interface carries no VRF membership.
	// The management interfaces (fxp*/fab*/em*) exist by this phase, so the bind
	// is transient-free (unlike the pre-networkd best-effort bind and the
	// routing-instance tunnel-member binds in applyVRFReconcile).
	if mgmtSet := d.mgmtVRFIfaceSet(); d.routing != nil && len(mgmtSet) > 0 {
		if err := d.rebindManagementVRFIfaces(); err != nil {
			networkdErr = errors.Join(networkdErr, err)
		}
		// Restart heartbeat after VRF rebind — networkd reconfigure moves
		// the control interface (em0) out of vrf-mgmt temporarily, which
		// invalidates the heartbeat UDP sockets. Without this restart,
		// the recovering node stops receiving peer heartbeats and declares
		// split-brain after the grace period expires.
		if d.cluster != nil {
			d.cluster.RestartHeartbeat()
		}
	}

	// #2926 boundary C3: before the FRR reload. The dataplane apply and the
	// RETH MAC / VIP / worker-rebind sequence above have completed; FRR still
	// holds the previous render. Bailing here skips the FRR reload and the
	// remaining service reconciles (IPsec, DHCP, RA, VRRP, syslog, exporters);
	// on the next boot the boot-time apply re-renders FRR and re-runs every
	// service step against the active config, so the skip converges. (After
	// store.Commit the store already holds the new config, so this is a clean
	// "apply the rest on next start" boundary, not a divergence.)
	if err := ctx.Err(); err != nil {
		return commitOverlay, networkdErr, nil, err
	}

	return commitOverlay, networkdErr, applyErr, nil
}

// applyServicesReconcile runs the per-service reconcile phases of a config
// apply that are decoupled from the dataplane-apply / RETH-MAC state: proactive
// neighbor resolution, RA sender config, IPsec config, the Kea DHCP server, and
// DHCP clients. Extracted verbatim from applyConfigLocked (#4407); no early
// return and no crossing input beyond cfg. It produces the IPsec and
// DHCP-server deferred errors (recorded, not returned early, so a later
// per-subsystem failure does not abort the apply) and returns them (ipsecErr,
// dhcpServerErr) for the tail reconcile's six-way errors.Join. Runs in the
// same slot, after the routing rules and before the tail reconciles.
func (d *Daemon) applyServicesReconcile(cfg *config.Config) (error, error) {
	// 4. Proactive neighbor resolution for all known next-hops/gateways.
	// This ensures bpf_fib_lookup returns SUCCESS (with valid MACs)
	// instead of NO_NEIGH for the first forwarded packet.
	// In cluster mode, skip here — RETH VIPs are not yet installed (VRRP
	// hasn't become MASTER), so RouteGet() for WAN next-hops may fail.
	// resolveNeighbors() is triggered on VRRP MASTER in watchVRRPEvents.
	if cfg.Chassis.Cluster == nil {
		d.resolveNeighbors(cfg)
	}

	// 5. Apply RA config (Router Advertisements)
	// In cluster mode, RA/kea are managed by watchVRRPEvents — only
	// the MASTER runs these services to prevent dual-RA / dual-DHCP.
	// The VRRP event fires shortly after startup and calls applyRethServices().
	isCluster := cfg.Chassis.Cluster != nil
	raConfigs := d.buildRAConfigs(cfg)
	if !isCluster {
		if d.ra != nil && len(raConfigs) > 0 {
			if err := d.ra.Apply(raConfigs); err != nil {
				slog.Warn("failed to apply RA config", "err", err)
			}
		} else if d.ra != nil {
			// No RA configs remain — the operator removed all RA. Gracefully
			// WITHDRAW any previous senders (final lifetime-0 goodbye, #5092)
			// instead of a hard Clear, so hosts drop this router immediately
			// rather than holding the stale default route until Router Lifetime
			// (default 1800s) expires. Withdraw is a no-op when no senders exist.
			if err := d.ra.Withdraw(); err != nil {
				slog.Warn("failed to withdraw RA config", "err", err)
			}
		}
	}
	// Cluster startup: goodbye RAs for stale routes are handled by the
	// reconcile loop (reconcileRGState) after VRRP election settles.
	// Each RETH node has a different virtual MAC (hence different
	// link-local), so both nodes appear as separate routers to hosts.
	// Only the primary sends RAs (via applyRethServicesForRG on MASTER);
	// the reconcile loop sends goodbye RAs for inactive RGs.
	//
	// Stable link-local cleanup: handled by reconcile after election.
	//
	// #5861: a day-2 RA edit on an RG that stays MASTER never fires a VRRP
	// event, so pre-#5861 the primary kept advertising the OLD prefixes/
	// lifetimes/options until failover/restart. Reconcile the cluster RA
	// senders against the union of buildRAConfigs for the RGs this node is
	// CURRENTLY the active owner for — owner-gated + serialized so a commit
	// racing a demotion can't re-arm RA on a now-inactive node. Hash-gated:
	// a no-op when the effective RA set for the owned RGs did not change.
	if isCluster {
		d.reconcileClusterRAServices("commit")
	}

	// 6. Apply IPsec config
	// Always call Apply so stale swanctl config is removed when VPNs are
	// deleted from config.
	//
	// #4433: a swanctl render/reload failure must fail the commit closed
	// rather than be swallowed at WARN — otherwise the OLD tunnels stay
	// active (swanctl --load-all leaves the previously-loaded config in
	// place on failure) while a NEW config is reported committed, so the
	// enforced IPsec runtime silently diverges from the committed policy.
	// The error is joined into the commit result at the tail (alongside
	// networkdErr / dhcpServerErr / hostInboundErr / lo0Err); the remaining
	// apply steps still run and the config stays promoted + peer-synced, so
	// the operator SEES the degraded IPsec state instead of a false success.
	var ipsecErr error
	if d.ipsec != nil {
		if err := d.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
			slog.Warn("failed to apply IPsec config", "err", err)
			ipsecErr = fmt.Errorf("apply IPsec config: %w", err)
		}
	}

	// 7. Reconcile DHCP server (Kea DHCPv4 + DHCPv6) against actual
	// systemd unit state (#1778).
	//
	// Standalone: Apply runs UNCONDITIONALLY — removing the
	// dhcp-server stanza (or restarting xpfd over a stale Kea left by
	// a previous daemon) stops the units; the pre-#1778 nil-config
	// gate skipped Apply entirely and leaked the old server.
	//
	// Cluster (#1835 F3): VRRP MASTER/BACKUP transitions own
	// start/stop (applyRethServicesForRG / clearRethServicesForRG via
	// ApplyAsync), but a config COMMIT must still reach the running
	// Kea — pre-F3 a dhcp-server change was invisible until the next
	// VRRP transition. Every commit regenerates the config files,
	// filtered to the RGs this node is currently MASTER for (the same
	// shape the VRRP path writes; nil when none match → authoritative
	// clear-if-active), and restarts only units that are currently
	// active (active == this node is serving). Inactive units pick up
	// the fresh config at the next VRRP MASTER transition.
	//
	// Fail-closed on commit (#1778/#1835 F3): restart/stop failures
	// are recorded into dhcpServerErr and returned at the tail of this
	// function, so commitAndApply surfaces them to the operator while
	// the remaining reconcile steps still run. The boot path stays
	// lenient: Run() reaches this via applyConfig(), which only logs
	// the returned error — an unavailable Kea binary cannot brick
	// daemon boot.
	var dhcpServerErr error
	if d.dhcpServer != nil {
		// #2239: gate the Kea control-socket + lease_cmds hook on the cluster
		// `dhcp-lease-synchronization` knob so the generated config carries the
		// read/seed surface only when lease sync is configured. Standalone or
		// knob-off renders bit-identical to pre-#2239. Set BEFORE the apply so
		// the regenerated config reflects the current knob.
		d.dhcpServer.SetLeaseSyncEnabled(d.dhcpLeaseSyncEnabled(cfg))
		if !isCluster {
			// Resolve RETH interface names for Kea (needs real Linux names)
			resolveDHCPRethInterfaces(&cfg.System.DHCPServer, cfg)
			if err := d.dhcpServer.Apply(&cfg.System.DHCPServer); err != nil {
				slog.Warn("failed to apply DHCP server config", "err", err)
				dhcpServerErr = fmt.Errorf("apply DHCP server config: %w", err)
			}
		} else {
			var dhcpCfg *config.DHCPServerConfig
			if cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil {
				// filterDHCPConfigForMasterRGs copies the config and
				// resolves RETH interface names internally.
				dhcpCfg = d.filterDHCPConfigForMasterRGs(cfg)
			}
			if err := d.dhcpServer.ApplyClusterCommit(dhcpCfg); err != nil {
				slog.Warn("failed to reconcile DHCP server (cluster commit)", "err", err)
				dhcpServerErr = fmt.Errorf("apply DHCP server config: %w", err)
			}
		}
	}

	// #1387 inc-2: nudge the DDNS reconcile loop so a commit that changes the
	// dynamic-dns policy (enable/disable, backend, zone, TSIG) takes effect
	// immediately rather than waiting up to one poll interval. The nudge is a
	// non-blocking depth-1 send (no control-socket call here — the loop does
	// file I/O + DNS only), so it never blocks the apply path. A
	// disabled/removed block drives withdrawAllLocked on the next pass.
	d.nudgeDDNSReconcile()
	// #2691 P2: a commit may add/remove a Surface A binding or change a
	// provider — nudge the Surface A loop to converge immediately too.
	d.nudgeSurfaceADDNSReconcile()

	// #2239: nudge an immediate lease-sync push so a commit that changes the
	// DHCP-server config (and thus the lease set / serving interfaces) is
	// replicated to the peer within one pass rather than waiting a heartbeat.
	// Non-blocking depth-1 send; the loop's gate decides if this node pushes.
	d.nudgeDHCPLeaseSync()

	// 7b. Reconcile DHCP clients (#1793): start clients for units that
	// gained dhcp/dhcpv6 in this commit, stop clients for units that
	// lost it, restart clients whose options changed. The diff keys on
	// config identity only (interface, family, options) — never lease
	// state — so the DHCP lease-change callback re-entering applyConfig
	// (onDHCPAddressChange) cannot restart clients in a loop. Runs after
	// the dataplane compile (step 2) so HOST_INBOUND_DHCP flags are
	// active before a newly started client puts DHCP packets on the wire.
	d.reconcileDHCPClients(cfg)
	return ipsecErr, dhcpServerErr
}

// applyRoutingRules applies the routing-rules layer during a config apply:
// the FRR config (static + dynamic protocols, best-effort — the error is
// consumed only by the async reconciler), next-table policy-routing rules,
// rib-group route-leaking rules, and firewall-filter policy-based routing (PBR)
// rules. Extracted verbatim from applyConfigLocked (#4407); all steps are
// idempotent ip-rule/FRR reconciles that log-and-continue, so the block has no
// early return. commitOverlay is the ip-monitoring route overlay folded into
// the FRR assembly. Runs in the same slot, after the dataplane apply / RETH-MAC
// sequence and before proactive neighbor resolution.
func (d *Daemon) applyRoutingRules(cfg *config.Config, commitOverlay []config.RouteOverlayEntry) error {
	// #5844: the kernel policy-routing (ip rule) reconciles below —
	// next-table, rib-group, and PBR/filter-based-forwarding — each already
	// RETURN a fail-closed error: a partial clear/add leaves stale-or-missing
	// cross-VRF policy in the kernel, and the immediately-following userspace
	// route snapshot (reconcileRouteLeakSnapshot) canonizes that partial live
	// kernel state. The pre-#5844 call site LOGGED and DROPPED those returns, so
	// a commit was acknowledged after a partial reconcile. Collect them here and
	// return the joined error to applyConfigLocked, which threads it into the
	// tail commit-error join. Fail-closed BUT complete: a single rule-type
	// failure does NOT skip the others — every rule type runs, then the joined
	// error surfaces (mirroring the #5310 ifaceErr / #5696 routeLeakErr pattern).
	var routingErrs []error

	// 3. Apply all routes + dynamic protocols via FRR.
	// assembleFRRConfig is the SOLE frr.FullConfig constructor, shared
	// with the ip-monitoring routes-only actuator (#1827) — the full
	// apply consumes the same (config-filtered) overlay computed in
	// step 1.95, so an operator commit while a policy is FAILED
	// preserves a still-valid injected failover route and drops
	// removed/edited entries on the commit itself.
	if d.frr != nil {
		// The full apply path deliberately warns-and-continues on an FRR
		// reload error (a transient FRR hiccup must not fail an
		// otherwise-valid operator commit; the in-manager degraded-retry
		// loop reconverges FRR without waiting for a restart).
		// applyFRRConfig returns nil on a DEGRADED reload (#1880, the new
		// routes are already live); a non-nil return is a HARD reload
		// failure where NOTHING was applied. We do not fail the commit on
		// it, but we no longer discard it silently (#5109): the frr
		// manager has marked the generation degraded and armed its retry
		// debt (surfaced via the ReloadDegraded() health gauge), so log it
		// and continue rather than reporting an unqualified success.
		if err := d.applyFRRConfig(d.assembleFRRConfig(cfg, commitOverlay)); err != nil {
			slog.Warn("FRR full apply hit a hard reload failure; commit continues, frr manager armed degraded retry debt",
				"err", err)
		}
	}

	// 3b. Apply next-table policy routing rules (ip rule)
	if d.routing != nil {
		// Collect all static routes from main + per-rib. Build the combined
		// list in a fresh slice — appending Inet6StaticRoutes onto
		// cfg.RoutingOptions.StaticRoutes directly would write into that
		// slice's backing array when it has spare capacity (cap > len),
		// mutating the shared active-config object other goroutines read
		// concurrently (same hazard fixed in collectNeighborProbeTargets,
		// fbd159e55 / #1781 r1).
		allRoutes := make([]*config.StaticRoute, 0,
			len(cfg.RoutingOptions.StaticRoutes)+len(cfg.RoutingOptions.Inet6StaticRoutes))
		allRoutes = append(allRoutes, cfg.RoutingOptions.StaticRoutes...)
		allRoutes = append(allRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
		if err := d.routing.ApplyNextTableRules(allRoutes, cfg.RoutingInstances); err != nil {
			slog.Warn("failed to apply next-table rules", "err", err)
			routingErrs = append(routingErrs, fmt.Errorf("apply next-table rules: %w", err))
		}
	}

	// 3c. Apply rib-group route leaking rules (ip rule). #3876: the leak is
	// now per connected prefix (`ip rule to <prefix> lookup <sourceTable>`
	// BEFORE main) so an imported interface route wins over a main-table
	// default route. The connected prefixes are derived from the config
	// addresses on each source instance's member interface units, using the
	// same derivation the userspace FIB uses for connected routes.
	//
	// #5642: the reconcile runs UNCONDITIONALLY (no `len(RibGroups) > 0`
	// gate). ribGroupManager.Apply calls clear() BEFORE its own empty-desired
	// early return, so an EMPTY rib-group set — the transition that removes
	// the FINAL rib-group — still deletes the previously-installed synthetic
	// `ip rule to <prefix> lookup <sourceTable>` leak rules. The old gate
	// skipped the whole block on that zero-transition, so the stale Linux
	// ip-rule (and, because buildRouteSnapshots derives the userspace
	// NextTable leak from the live ip-rule table, the stale userspace FIB
	// entry) kept routing a deleted-VRF prefix into its table indefinitely — a
	// route-leak that kernel-forwarded / local / route-based-IPsec plaintext
	// could follow. A config that never had a rib-group finds no rule in the
	// scanned bands, so clear() issues no RuleDel (no churn); a steady-state
	// non-empty commit reconciles the exact same set as before.
	if d.routing != nil {
		connectedPrefixes := config.RibGroupConnectedPrefixes(cfg)
		if err := d.routing.ApplyRibGroupRules(cfg.RoutingOptions.RibGroups, cfg.RoutingInstances, connectedPrefixes); err != nil {
			slog.Warn("failed to apply rib-group rules", "err", err)
			routingErrs = append(routingErrs, fmt.Errorf("apply rib-group rules: %w", err))
		}
	}

	// 3d. Apply policy-based routing rules (ip rule) for firewall filter
	// routing-instance (filter-based forwarding). Rules are derived only from
	// filters attached as an interface input filter (#3430 H1); a degraded
	// build — an unrepresentable except set, a DSCP-0 match, an
	// ip-rule-unrepresentable L4/per-packet predicate (port-except / tcp-flags /
	// icmp / is-fragment / flex, #3730), or an overflow — is surfaced but does
	// not block the rest of the apply. The degraded term is DROPPED (fail-safe
	// under-steer to the main table), never widened to an address-only over-steer.
	if d.routing != nil {
		pbrRules, buildErr := routing.BuildPBRRules(cfg)
		if buildErr != nil {
			// #5844: buildErr is DELIBERATELY not joined into the commit-error.
			// It is a fail-SAFE representability degradation, not a partial
			// kernel mutation. The kernel ip rule (BuildPBRRules) is only a
			// MIRROR of the userspace FBF steer for SLOW-PATH (XDP_PASS) packets
			// (rules.go: "the kernel also honors PBR for XDP_PASS'd packets, e.g.
			// SNAT'd traffic destined for a VRF/GRE tunnel"). The AUTHORITATIVE
			// fast-path enforcement of a `then routing-instance` term — with the
			// FULL L4 match the kernel ip rule cannot express (port-except /
			// tcp-flags / icmp / is-fragment / flex) — is the userspace filter
			// engine: buildFilterTermSnapshots carries term.RoutingInstance +
			// the full match into the FirewallTermSnapshot
			// (pkg/dataplane/userspace/filters.go), and the Rust evaluator sets
			// acc.routing_instance = term.routing_instance on a full-term match
			// (userspace-dp/src/filter/engine/eval.rs
			// evaluate_interface_filter_routing_instance_*). So a term that
			// cannot be mirrored to an ip rule is DROPPED from the kernel mirror
			// only; on the fast path it is still steered, and a slow-path packet
			// UNDER-steers to the main table (the fail-safe direction — never an
			// address-only OVER-steer / cross-VRF leak, rules.go BuildPBRRules).
			// The degradation is already observable (this WARN + the #4422
			// PBRBuildStats degraded gauge), not silent. ApplyPBRRules(pbrRules)
			// below fully reconciles whatever WAS built (deleting any stale
			// rule), so no stale-or-missing cross-VRF policy survives in the
			// mirror — the #5844 bug class is the netlink RuleAdd/RuleDel failure
			// below, not this representability drop. Fail-closing on buildErr
			// would instead REJECT configs with such terms that commit fine
			// today AND are enforced on the fast path, so it stays a
			// warn-and-continue.
			slog.Warn("PBR rule build degraded; some routing-instance filter terms "+
				"are not mirrored to the kernel FBF path and fall back to the main "+
				"table (userspace filter path still enforces them)", "err", buildErr)
		}
		// ApplyPBRRules IS a kernel reconcile: a failed clear/add leaves a
		// half-installed FBF policy in the kernel ip-rule table, so its error is
		// joined into the commit-error (fail-closed).
		if err := d.routing.ApplyPBRRules(pbrRules); err != nil {
			slog.Warn("failed to apply PBR rules", "err", err)
			routingErrs = append(routingErrs, fmt.Errorf("apply PBR rules: %w", err))
		}
	}

	// Fail-closed but COMPLETE: every rule type above ran regardless of an
	// earlier failure; surface the joined error so a partial ip-rule reconcile
	// fails the commit instead of being silently acknowledged (#5844).
	return errors.Join(routingErrs...)
}

// reconcileRouteLeakSnapshot republishes the userspace route snapshot after
// applyRoutingRules has reconciled the kernel policy-routing (ip rule) table
// (#5642). The full dataplane apply (applyDataplaneAndHACore → d.dp.ApplyConfig)
// runs BEFORE applyRoutingRules and derives its route snapshot from the LIVE
// kernel ip-rules (buildRouteSnapshots → netlink.RuleList). On an inter-VRF
// route-leak transition — most importantly the final-rib-group removal that
// takes RoutingOptions.RibGroups to zero — applyRoutingRules has just deleted
// (or added) the synthetic `ip rule to <prefix> lookup <table>` leak rule, so
// the snapshot ApplyConfig already published still mirrors the PRE-reconcile
// rule table and keeps (or omits) a NextTable leak that no longer matches the
// kernel. Without this reconcile a removed rib-group's deleted-VRF leak would
// survive in the userspace FIB indefinitely (until some later apply happened to
// rebuild it).
//
// This reuses the ip-monitoring routes-only publish surface — no Compile, no
// helper restart — rebuilding buildRouteSnapshots against the now-reconciled
// kernel rules and, only when the content actually changed, publishing the
// leak-free FIB and bumping the FIB generation so established flows re-resolve.
// PublishRouteOverlaySnapshot duplicate-skips an unchanged route set (returns
// published=false), so a steady-state commit and a config that never carried a
// rib-group publish nothing and churn nothing. A nil scheduler-state argument
// keeps the manager's current policy-scheduler view (the one the full apply just
// published) so the unchanged-content hash matches and the skip fires.
//
// #5696 (M19, a #5642 residual): a genuine route-publication or FIB-invalidation
// failure returns a DEFERRED error the caller joins into the tail commit-error
// (fail-closed but complete). This commit-tail reconcile has no dirty-retry
// engine, so swallowing the failure would leave the userspace FIB with a stale
// inter-VRF leak — the exact bug #5642 fixed — while reporting a successful
// commit. Benign no-ops (helperless, duplicate-skip) return nil.
func (d *Daemon) reconcileRouteLeakSnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry) error {
	if cfg == nil {
		return nil
	}
	pub, ok := d.dp.(routeOverlayPublisher)
	if !ok {
		// Helperless (no userspace dataplane publisher): the kernel ip-rule
		// reconcile above is the only route-leak consumer and it already ran.
		return nil
	}
	published, err := pub.PublishRouteOverlaySnapshot(cfg, overlay, nil)
	if err != nil {
		// #5696 (M19): surface the publish failure as a deferred commit error
		// instead of swallowing it. This commit-tail reconcile has no dirty-retry
		// engine (unlike the ip-monitoring actuator), so a swallowed failure would
		// silently reinstate the exact stale inter-VRF leak #5642 removed while the
		// commit reports success. The caller joins this into the tail errors.Join
		// so the commit fails CLOSED — the OLD pre-reconcile snapshot stays live
		// and a re-commit re-runs the reconcile (#5679/#5310 fail-closed pattern).
		slog.Warn("route-leak snapshot reconcile: routes-only republish failed; the "+
			"userspace FIB may retain a stale inter-VRF leak until the next apply",
			"err", err)
		return fmt.Errorf("route-leak snapshot republish: %w", err)
	}
	if !published {
		// Duplicate-skip (route set unchanged) or no published snapshot yet /
		// helper not running: nothing moved, so do not bump the FIB generation
		// (would needlessly churn established-flow route caches). Benign no-op —
		// stays a successful commit.
		return nil
	}
	// Ordering (mirrors the ip-monitoring actuator, #1827 AGY r2-1): bump the
	// FIB generation ONLY after a real publish so established flows re-resolve
	// onto the reconciled routes; bumping before/without a publish would leave
	// flows pinned to the stale leak route.
	if _, err := pub.BumpFIBGeneration(); err != nil {
		// #5696 (M19): the leak-free routes ARE on the wire (publish succeeded),
		// but the FIB generation was not bumped — established flows stay pinned to
		// the stale leak route. With no retry owner for this commit-tail path a
		// swallowed bump leaves that inconsistency unrediscovered; fail the commit
		// closed so a re-commit re-runs the reconcile.
		slog.Warn("route-leak snapshot reconcile: FIB generation bump unconfirmed after "+
			"republish; established flows may re-resolve on a later sweep", "err", err)
		return fmt.Errorf("route-leak snapshot FIB generation bump: %w", err)
	}
	return nil
}

// applyFabricIPVLAN creates the fabric-member IPVLAN overlays (fab0/fab1) for
// cluster heartbeat + VRRP, deferring creation past XSK bind when the userspace
// dataplane is active (an existing IPVLAN breaks zero-copy bind, #128), and
// cleans up stale fabric IPVLAN overlays not in the current config. Extracted
// verbatim from applyConfigLocked (#4407); runs in the same slot, after the
// interface-creation reconcile and before the RETH-MAC pre-check.
func (d *Daemon) applyFabricIPVLAN(cfg *config.Config) {
	// 1.9. Create IPVLAN interfaces for fabric members (fab0, fab1).
	// The physical member (ge-0-0-0) keeps its name; fab0 is IPVLAN L2
	// on top for IP addressing. BPF attaches to the parent.
	// Track which overlays are configured so stale ones can be cleaned up (#128).
	//
	// When the userspace dataplane is active, DEFER IPVLAN creation until
	// after XSK binds complete. The kernel checks for upper devices (like
	// IPVLAN) at XSK bind time — if an IPVLAN exists, zerocopy bind fails
	// and falls back to copy mode (~3 Gbps). Deferring lets the fabric
	// parent bind XSK in zerocopy first, then the IPVLAN is added for
	// sync/heartbeat addressing.
	activeFabricOverlays := make(map[string]bool)
	type deferredIPVLAN struct {
		parent string
		name   string
		addrs  []string
	}
	var deferredOverlays []deferredIPVLAN
	bindingCtrl, isUserspaceDP := d.dp.(userspaceXSKBindingController)
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil || ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
			continue
		}
		parentLinux := config.LinuxIfName(ifCfg.LocalFabricMember)
		fabLinux := config.LinuxIfName(ifName)
		activeFabricOverlays[fabLinux] = true
		var addrs []string
		if unit, ok := ifCfg.Units[0]; ok {
			addrs = unit.Addresses
		}
		// When userspace DP is active, remove any existing IPVLAN and
		// defer recreation until after XSK binds in zerocopy. The kernel
		// checks for upper devices at bind time — IPVLAN blocks zerocopy.
		// On subsequent applyConfig calls (config change), the IPVLAN
		// already exists from the OnXSKBound callback and XSK is already
		// bound, so the xskBoundNotified guard prevents re-deletion.
		if isUserspaceDP {
			if bindingCtrl != nil && !bindingCtrl.XSKBoundNotified() {
				// First applyConfig — remove stale IPVLAN so XSK can zerocopy.
				if link, err := netlink.LinkByName(fabLinux); err == nil {
					netlink.LinkDel(link)
					slog.Info("removed fabric IPVLAN for deferred zerocopy XSK bind",
						"name", fabLinux)
				}
				deferredOverlays = append(deferredOverlays, deferredIPVLAN{
					parent: parentLinux, name: fabLinux, addrs: addrs,
				})
				slog.Info("deferring fabric IPVLAN creation until XSK binds complete",
					"parent", parentLinux, "name", fabLinux)
				// continue // DISABLED: deferred IPVLAN broke forwarding
			}
			// XSK already bound — fall through to reconcile.
		}
		if err := ensureFabricIPVLAN(parentLinux, fabLinux, addrs); err != nil {
			// Fabric overlay is critical for cluster heartbeat and VRRP.
			// Retry up to 5 times with 1s delay — the parent interface
			// might not be ready yet after a power cycle.
			var retryErr error
			for retry := 0; retry < 5; retry++ {
				time.Sleep(time.Second)
				slog.Info("retrying fabric IPVLAN creation",
					"parent", parentLinux, "name", fabLinux, "attempt", retry+2)
				retryErr = ensureFabricIPVLAN(parentLinux, fabLinux, addrs)
				if retryErr == nil {
					break
				}
			}
			if retryErr != nil {
				slog.Error("CRITICAL: fabric IPVLAN creation failed after retries — cluster heartbeat will not work",
					"parent", parentLinux, "name", fabLinux, "err", retryErr)
			}
			continue
		}
	}
	// Register deferred IPVLAN creation callback on the userspace manager.
	if len(deferredOverlays) > 0 && bindingCtrl != nil {
		bindingCtrl.SetOnXSKBound(func() {
			for _, ov := range deferredOverlays {
				slog.Info("XSK bound — creating deferred fabric IPVLAN",
					"parent", ov.parent, "name", ov.name)
				if err := ensureFabricIPVLAN(ov.parent, ov.name, ov.addrs); err != nil {
					slog.Error("deferred fabric IPVLAN creation failed",
						"parent", ov.parent, "name", ov.name, "err", err)
				}
			}
		})
	}
	// Clean up stale fabric IPVLAN overlays not in current config (#128).
	for _, name := range []string{"fab0", "fab1"} {
		if activeFabricOverlays[name] {
			continue
		}
		if link, err := netlink.LinkByName(name); err == nil {
			if _, ok := link.(*netlink.IPVlan); ok {
				netlink.LinkDel(link)
				slog.Info("removed stale fabric IPVLAN", "name", name)
			}
		}
	}
}

// applyVRFReconcile reconciles routing-instance VRFs during a config apply:
// the #2926-C1 context-cancellation boundary check, ReconcileVRFs (create/
// update/orphan-delete vrf-* devices), binding routing-instance member
// interfaces to their VRFs, binding management interfaces (fxp*/fab*/em*) to
// vrf-mgmt when it is managed, and applying the management-VRF routes.
// Extracted verbatim from applyConfigLocked (#4407).
//
// Returns TWO errors (#5700). ctxErr is the #2926-C1 ctx-cancellation check (the
// block's sole early return), which applyConfigLocked propagates unchanged
// through the host-authorization closeout — the C1 abort semantics are
// UNCHANGED. vrfErr is the DEFERRED VRF-device-setup failure: a ReconcileVRFs
// error means the vrf-* device could not be created/reconciled, yet
// reconcileVRFs's partial-failure contract still records the VRF in the
// managed/tracked set (IsManagedVRF returns true below), so the commit used to
// report the VRF configured while it was absent on the kernel — a false
// convergence with no retry owner. vrfErr is threaded into the tail commit-error
// join exactly like the #5310 ifaceErr / #5696 routeLeakErr / #5844
// routingRuleErr deferred errors, so a failed commit fails closed and is the
// retry owner (the next apply re-reconciles). Runs in the same slot, before the
// interface-creation reconcile.
func (d *Daemon) applyVRFReconcile(ctx context.Context, cfg *config.Config) (ctxErr error, vrfErr error) {
	// #2926 boundary C1: before the netlink reconcile phase. Nothing in the
	// kernel / dataplane / FRR has been touched yet (the SNMP swap above is an
	// idempotent in-memory pointer flip), so a cancellation here skips the
	// entire pipeline cleanly. This is the cheapest, safest place to honor a
	// daemon stop.
	if err := ctx.Err(); err != nil {
		return err, nil
	}

	// 0. Reconcile VRF devices (routing-instance VRFs + management VRF).
	// ReconcileVRFs is idempotent: VRFs already present with the correct
	// table ID are preserved (ifindex unchanged). Removed-from-config
	// VRFs are deleted. #847: xpfd claims the entire `vrf-*` kernel
	// namespace — orphan vrf-* devices not in desired and not in
	// m.vrfs (e.g. left over from a routing-instance rename across
	// a daemon restart) are also reaped. Operators MUST NOT
	// pre-create vrf-<name> outside xpfd config.
	//
	// (The original docs/pr/844-vrf-idempotent/plan.md described an
	// earlier design where external VRFs were left alone; the
	// namespace-claim policy in this code supersedes that plan. See
	// the godoc on routing.ReconcileVRFs for the current contract.)
	const mgmtVRFName = "mgmt"
	const mgmtTableID = 999
	mgmtIfaces := make(map[string]bool)
	for name := range cfg.Interfaces.Interfaces {
		if strings.HasPrefix(name, "fxp") || strings.HasPrefix(name, "fab") || strings.HasPrefix(name, "em") {
			mgmtIfaces[config.LinuxIfName(name)] = true
		}
	}

	if d.routing != nil {
		var desired []routing.VRFSpec
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType == "forwarding" {
				slog.Info("forwarding instance, skipping VRF creation",
					"instance", ri.Name)
				continue
			}
			desired = append(desired, routing.VRFSpec{
				Name:    ri.Name,
				TableID: ri.TableID,
			})
		}
		if len(mgmtIfaces) > 0 {
			desired = append(desired, routing.VRFSpec{
				Name:    mgmtVRFName,
				TableID: mgmtTableID,
			})
		}
		if err := d.routing.ReconcileVRFs(desired); err != nil {
			// #5700: the VRF DEVICE setup failed (vrf-* could not be created/
			// reconciled). reconcileVRFs still records the VRF as managed on a
			// partial failure, so surface this into commit truth rather than
			// swallowing it at WARN — otherwise the commit reports the VRF
			// configured while it is not on the kernel (false convergence). This is
			// transient-free: VRF device creation depends on no other interface.
			slog.Warn("failed to reconcile VRFs", "err", err)
			vrfErr = errors.Join(vrfErr, fmt.Errorf("reconcile VRFs: %w", err))
		}
	}

	// 0a. Bind routing-instance interfaces to their VRFs.
	// Name normalization is shared with collectAppliedTunnels'
	// RIListMember scan via riMemberLinuxName (#1884) so the tunnel
	// manager's unbind veto can never diverge from what this loop
	// actually binds. Tunnel list members resolve through
	// cfg.TunnelNameMap() (#1904) so a unit>0 entry like gr-0/0/0.1
	// binds the real per-unit device (gr-0-0-0u1), not the literal
	// ".1" name.
	if d.routing != nil {
		tunMap := cfg.TunnelNameMap()
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType == "forwarding" {
				continue
			}
			for _, ifaceName := range ri.Interfaces {
				linuxName := riMemberLinuxName(tunMap, ifaceName)
				// #5700: deliberately best-effort (WARN, not surfaced). This runs
				// BEFORE applyInterfaceReconcile creates tunnel/xfrmi devices, so a
				// routing-instance member that is a later-created tunnel is legitimately
				// "not found" here — an EXPECTED transient absence that must NOT be
				// promoted into a permanent commit failure. Only the VRF DEVICE setup
				// (ReconcileVRFs, surfaced above as vrfErr) and the authoritative
				// post-networkd management re-bind (rebindManagementVRFIfaces) are
				// load-bearing and transient-free.
				if err := d.routing.BindInterfaceToVRF(linuxName, ri.Name); err != nil {
					slog.Warn("failed to bind interface to VRF",
						"interface", ifaceName, "linux", linuxName,
						"instance", ri.Name, "err", err)
				}
			}
		}
	}

	// 0b. Bind management interfaces (fxp*/fab*/em*) to vrf-mgmt, but
	// only if ReconcileVRFs actually got vrf-mgmt into the managed set.
	// If reconcile errored out before vrf-mgmt could be created,
	// downstream code (applyMgmtVRFRoutes, HA sync) would otherwise
	// run against a non-existent VRF.
	// Compute the final management-VRF interface set, then publish it with a
	// single atomic Store (#5113) so a lock-free DHCP-callback reader never
	// observes the transient nil the old two-step (= nil then = mgmtIfaces)
	// published. mgmtSet stays nil (readers see the safe empty state) unless
	// reconcile actually got vrf-mgmt into the managed set.
	var mgmtSet map[string]bool
	if d.routing != nil && len(mgmtIfaces) > 0 && d.routing.IsManagedVRF(mgmtVRFName) {
		mgmtSet = mgmtIfaces
		for ifName := range mgmtIfaces {
			// #5700: this PRE-networkd bind is best-effort (WARN, not surfaced).
			// applyNetworkdConfig's `networkctl reconfigure` strips the VRF master
			// binding right after this phase, so the AUTHORITATIVE management-VRF
			// bind is the post-networkd rebindManagementVRFIfaces (whose failure IS
			// surfaced into commit truth). Surfacing this pre-strip bind would report
			// a failure for a binding networkd is about to remove and re-establish.
			if err := d.routing.BindInterfaceToVRF(ifName, mgmtVRFName); err != nil {
				slog.Warn("failed to bind interface to management VRF",
					"interface", ifName, "err", err)
			}
		}
	}
	d.publishMgmtVRFIfaces(mgmtSet)

	// #5867: the DHCP management-VRF route program+reconcile (formerly step 0.6
	// here) now runs in applyConfigLocked immediately after this reconcile
	// returns, so its RouteReplace / cleanup error is threaded into the tail
	// commit-error join (fail-closed but complete) instead of being swallowed at
	// this early phase. Moving it out of applyVRFReconcile also keeps a stale-
	// route-pin failure from aborting the whole apply early (it must NOT skip the
	// dataplane apply). Ordering is unchanged: it still runs after this reconcile
	// (which publishes the mgmt-interface set it reads) and before the interface/
	// dataplane reconciles.
	return nil, vrfErr
}

// rebindManagementVRFIfaces re-binds the published management-VRF interface set
// to vrf-mgmt after applyNetworkdConfig's `networkctl reconfigure` strips the
// VRF master binding (it treats the daemon-created vrf-mgmt device as
// unmanaged). This is the AUTHORITATIVE, load-bearing management-VRF bind:
// #5700 aggregates and RETURNS the per-interface bind failures so the caller can
// join them into commit truth (via networkdErr) instead of swallowing at WARN —
// a genuine bind failure otherwise reports the management VRF configured while
// the interface carries no VRF membership (false convergence, no retry owner).
// The management interfaces exist by this phase, so a failure is genuine, not a
// transient absence. Returns nil when there is nothing to bind or every bind
// succeeds. Extracted so the fail-closed bind can be unit-tested directly,
// mirroring applyInterfaceReconcile (#5310).
func (d *Daemon) rebindManagementVRFIfaces() error {
	mgmtSet := d.mgmtVRFIfaceSet()
	if d.routing == nil || len(mgmtSet) == 0 {
		return nil
	}
	var errs []error
	for ifName := range mgmtSet {
		if err := d.routing.BindInterfaceToVRF(ifName, "mgmt"); err != nil {
			slog.Warn("failed to re-bind interface to management VRF",
				"interface", ifName, "err", err)
			errs = append(errs, fmt.Errorf("re-bind %s to management VRF: %w", ifName, err))
		}
	}
	return errors.Join(errs...)
}

// applyInterfaceReconcile creates/reconciles the interface-level network
// devices during a config apply: tunnel interfaces (interface + per-unit),
// xfrmi interfaces for IPsec VPNs (before BPF compilation so compileZones can
// map them to zones), fabric bond/LAG member interfaces, and cleanup of legacy
// RETH bond devices. Extracted verbatim from applyConfigLocked (#4407); all
// steps are idempotent reconciles (unchanged config = no-op). Runs in the same
// slot, after the VRF reconcile and before fabric IPVLAN creation.
//
// Fail-closed (#5310): each sub-stage's GENUINE reconcile failure is
// accumulated with errors.Join and returned so the caller can join it into the
// commit result. Before this the function was void and every sub-stage error
// was swallowed at WARN — a route-based IPsec VPN whose xfrmi failed to be
// created (xfrmManager.Apply used to return nil unconditionally) or a fabric
// bond that could not be realized (#4823) reported a SUCCESSFUL commit while the
// interface carried no traffic. The tolerated idempotent conditions stay
// non-errors inside each manager (an already-exists link is adopted, an
// already-gone delete is a no-op — #4901/#5119/#5261), so a benign re-apply
// still returns nil and keeps succeeding. All steps still run (no early return)
// so a failure in one does not skip the others.
func (d *Daemon) applyInterfaceReconcile(cfg *config.Config) error {
	if d.routing == nil {
		return nil
	}

	var errs []error

	// 1. Create tunnel interfaces (interface-level + per-unit tunnels)
	if err := d.routing.ApplyTunnels(collectAppliedTunnels(cfg)); err != nil {
		slog.Warn("failed to apply tunnels", "err", err)
		errs = append(errs, fmt.Errorf("apply tunnels: %w", err))
	}

	// 1.5. Create xfrmi interfaces for IPsec VPN tunnels.
	// Must happen before BPF compilation so compileZones() can discover
	// the xfrmi interfaces and map them to security zones.
	// Always call ApplyXfrmi so stale xfrmi devices are removed when VPNs
	// are deleted from config.
	if err := d.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
		slog.Warn("failed to apply xfrmi interfaces", "err", err)
		errs = append(errs, fmt.Errorf("apply xfrmi interfaces: %w", err))
	}

	// 1.7. Create bond (LAG) interfaces for fabric-options member-interfaces.
	// Always call ApplyBonds (even with empty list) so stale bonds from
	// previous configs get cleaned up via ClearBonds().
	var bondIfaces []*config.InterfaceConfig
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if len(ifc.FabricMembers) > 0 {
			bondIfaces = append(bondIfaces, ifc)
		}
	}
	if err := d.routing.ApplyBonds(bondIfaces); err != nil {
		slog.Warn("failed to apply bonds", "err", err)
		errs = append(errs, fmt.Errorf("apply bonds: %w", err))
	}

	// 1.8. Clean up legacy RETH bond devices from previous binary versions.
	// VRRP now runs directly on physical member interfaces — no bonds needed.
	// ClearRethInterfaces returns an error on a netlink LinkList failure OR on
	// any per-bond LinkDel failure (aggregated with errors.Join, #5704); surface
	// it so a stale legacy reth bond left in the kernel fails the commit closed.
	if err := d.routing.ClearRethInterfaces(); err != nil {
		slog.Warn("failed to clean up legacy RETH bonds", "err", err)
		errs = append(errs, fmt.Errorf("clean up legacy RETH bonds: %w", err))
	}

	return errors.Join(errs...)
}

// applyTailReconciles runs steps 8–21 of applyConfigLocked — the tail of the
// commit/apply pipeline that dispatches to independent subsystems after the
// ordering-entangled head (VRF/tunnel/IPVLAN/dataplane/RETH-MAC/networkd/FRR,
// steps 0–7). Each step reads only the compiled config (+ nil-guarded
// subsystems); none feeds a later head step, so grouping them here is a
// behavior-preserving mechanical move (#4407 Phase A). The helper runs
// synchronously in the caller's goroutine under d.applySem (the caller holds
// it), so the lock discipline of the inline body is preserved; the few
// intentionally-async callbacks the apply body spawns all live in the head,
// not here.
//
// Error-join contract: the deferred reconcile errors accumulate across the
// whole apply body but are joined only at this tail (fail-closed — every step
// still runs). networkdErr/applyErr/dhcpServerErr/ipsecErr/ifaceErr originate in
// the head and are threaded in as parameters (applyErr is the #5679 ordinary
// non-abort dataplane-apply failure that must fail the commit while the OLD
// policy stays live); routeLeakErr is the #5696 route-leak snapshot
// republish/FIB-bump failure (also head-produced, threaded in like ifaceErr);
// vrrpErr originates in step 8 below when runtime identity validation rejects
// the desired set (#5083); vrfErr is the #5700 VRF-device-setup (ReconcileVRFs)
// failure and routingRuleErr/mgmtRouteErr are threaded from the caller;
// lo0Err/hostInboundErr originate in step 9.5. The returned errors.Join
// preserves the explicit operand order
// (#1778/#2987/#4433/#5083/#5310/#5679/#5696/#5700).
func (d *Daemon) applyTailReconciles(cfg *config.Config, networkdErr, applyErr, dhcpServerErr, ipsecErr, ifaceErr, routeLeakErr, routingRuleErr, mgmtRouteErr, vrfErr error) error {
	// 8. Apply VRRP config — merge user VRRP + RETH VRRP instances
	var vrrpErr error
	vrrpInstances := vrrp.CollectInstances(cfg)
	if d.cluster != nil {
		localPri := d.cluster.LocalPriorities()
		vrrpInstances = append(vrrpInstances, vrrp.CollectRethInstances(cfg, localPri)...)
	}
	if err := d.vrrpMgr.UpdateInstances(vrrpInstances); err != nil {
		slog.Warn("failed to update VRRP instances", "err", err)
		// Identity/family validation is a fail-closed runtime gate. Returning a
		// successful commit while the manager retained the old instance set
		// would claim HA coverage for a family/segment that is not running.
		vrrpErr = fmt.Errorf("update VRRP instances: %w", err)
	}

	// 9. Apply system DNS and NTP configuration.
	//
	// #1715: a single locked reconcileDNS owns /etc/resolv.conf as a
	// managed plain file (resolved disabled+masked), merging static
	// `system name-server` with live DHCP-learned servers. It replaces
	// the prior applySystemDNS (resolved drop-in + restart) and
	// applyDNSService (disable resolved) pair, whose apply order
	// (write-drop-in-then-disable) was a self-inflicted race that left
	// /etc/resolv.conf a dangling symlink. bootEmptyRepairOnly is set
	// before DHCP clients start so the first apply does not blank a good
	// resolv.conf when no static name-server is configured yet.
	d.reconcileDNSLocked(cfg, !d.dnsBootDone)
	d.applySystemNTP(cfg)

	// 9.5. Apply system hostname, timezone, and kernel tuning
	d.applyHostname(cfg)
	d.applyTimezone(cfg)
	d.applyKernelTuning(cfg)
	// #3392: the lo0 input filter is host-protection control-plane enforcement,
	// so an apply/teardown failure must fail the commit closed rather than be
	// swallowed at WARN — the same fail-open #3333 fixed for host-inbound. The
	// error is joined into the commit result at the tail (alongside networkdErr /
	// dhcpServerErr / hostInboundErr); the remaining apply steps still run so
	// management/SSH reconcile is never skipped by an lo0 nft failure.
	lo0Err := d.applyLo0Filter(cfg)
	// #3333: host-inbound is the kernel-nftables PRIMARY enforcement of the
	// host-inbound contract, so an apply/teardown failure must fail the commit
	// closed rather than be swallowed at WARN. The error is joined into the
	// commit result at the tail (alongside networkdErr / dhcpServerErr); the
	// remaining apply steps still run so management/SSH reconcile is never
	// skipped by a host-inbound nft failure.
	hostInboundErr := d.applyHostInboundFilter(cfg)

	// 9.6. Write SSH known hosts file
	d.applySSHKnownHosts(cfg)

	// 10. Apply system syslog forwarding
	d.applySystemSyslog(cfg)

	// Steps 11–13 are the login/credential reconcilers. They return their
	// accumulated failures (#5874) so the cancel closeout can surface them,
	// but on the NORMAL apply path the returns are intentionally DISCARDED:
	// the tail is best-effort here because the next boot re-renders login /
	// sudoers / SSH / root-auth from the active config, so a transient failure
	// converges (the #2926 next-boot contract). Only the daemon-stop cancel
	// closeout — where next-boot convergence does NOT happen while the daemon
	// stays intentionally stopped — collects and fails on these.

	// 11. Apply system login users (create OS accounts, SSH keys)
	_ = d.applySystemLogin(cfg)

	// 11b. Reconcile super-user sudo grants against the CURRENT config so a
	// class downgrade or user removal REVOKES the stale NOPASSWD grant
	// (#3889). Runs unconditionally — applySystemLogin returns early when
	// there are no users, which is exactly the "all users removed" case
	// that must still sweep stale grants.
	_ = d.reconcileSudoers(cfg)

	// 11c. Revoke host credentials for any xpf-provisioned login account that
	// was removed from config (#5128). reconcileSudoers above only revokes the
	// sudo grant; without this a deprovisioned operator keeps their password
	// and authorized_keys and can still SSH in. Like reconcileSudoers it MUST
	// run unconditionally — the "all users removed" case must still revoke.
	_ = d.reconcileAbsentLoginUsers(cfg)

	// 12. Apply SSH service configuration (root-login)
	_ = d.applySSHConfig(cfg)

	// 13. Apply root authentication (encrypted-password + SSH keys)
	_ = d.applyRootAuth(cfg)

	// 14. Apply syslog file destinations (rsyslog configs)
	d.applySyslogFiles(cfg)

	// 14b. Update security log syslog clients + zone name mapping
	if d.eventReader != nil {
		d.applySyslogConfig(d.eventReader, cfg)
	}

	// 15. Archive config to remote sites if transfer-on-commit is enabled
	d.archiveConfig(cfg)

	// 15b. Configure local archival settings for auto-archive on commit
	if cfg.System.Archival != nil {
		dir := cfg.System.Archival.ArchiveDir
		if dir == "" {
			dir = "/var/lib/xpf/archive"
		}
		max := cfg.System.Archival.MaxArchives
		if max <= 0 {
			max = 10
		}
		d.store.SetArchiveConfig(dir, max)
	} else {
		d.store.SetArchiveConfig("", 0)
	}

	// 15c. Reconcile the periodic configuration-archival timer (#4078). Junos
	// `transfer-interval N` archives the running config to the archive-sites
	// every N minutes, independent of transfer-on-commit. Hash-gated so an
	// unrelated commit never bounces a healthy timer; re-armed on daemon
	// restart via this same boot apply; stopped when the leaf is removed.
	d.reconcileArchiveTimer(cfg)

	// 16. Update flow traceoptions (trace file + filters)
	d.updateFlowTrace(cfg)

	// 16b. Reconcile the NetFlow v9 / IPFIX exporters (#2075). Before
	// this, the exporters were only started at boot and stopped at
	// shutdown, so forwarding-options sampling / flow-monitoring config
	// changes were ignored until a daemon restart (and flow export
	// added in a later commit never started). Hash-gated per family so
	// an unrelated commit never bounces a healthy exporter. Placed
	// below the dataplane-apply abort (consistent with reconcileRPM /
	// applySyslogConfig): an aborting commit defers the exporter change
	// to the next clean commit.
	d.reconcileFlowExporters(cfg)

	// 16c. Reconcile the DHCP relay (#2348). Before this the relay was
	// applied only at boot (daemon_run.go), so a day-2 commit that added,
	// removed, or changed a `forwarding-options dhcp-relay` group was
	// ignored until a daemon restart. Manager.Apply diffs desired-vs-running
	// per interface (start added, stop removed, restart changed, leave
	// unchanged) and a nil relay config stops all relays. Bound to
	// d.daemonCtx so the relay goroutines outlive this apply call.
	d.reconcileDHCPRelay(cfg)

	// 16d. Reconcile the LLDP service (#2372). Before this, LLDP was applied
	// only at boot (daemon_run.go), so a day-2 commit that enabled, disabled,
	// or changed `protocols lldp` (interface set, transmit-interval,
	// hold-multiplier) was silently ignored until a daemon restart. reconcileLLDP
	// lazily instantiates the manager on the first enable and Apply()s the new
	// config; a disabled/empty stanza stops the running service. Bound to
	// d.daemonCtx so the TX/RX goroutines outlive this apply call.
	d.reconcileLLDP(cfg)

	// 17. Reconcile event-options policies (RPM-driven failover). Before
	// #3752 this was a bare `if d.eventEngine != nil { Apply }`, and the
	// engine was constructed at boot ONLY when the boot config already had
	// policies — so committing the FIRST event-options policy on a running
	// daemon (day-2) left d.eventEngine nil and the policy inert until a
	// restart. The engine is now constructed unconditionally at boot
	// (daemon_run.go, mirroring LLDP/dhcpRelay); reconcileEventOptions runs
	// here on every day-2 commit so a first-enable takes effect immediately.
	d.reconcileEventOptions(cfg)

	// 17b. Reconcile RPM probes (#1827 PR-1a). Config-hash-gated: the
	// probe set (and the probe next-hop pin rules) is re-applied only
	// when the rendered RPM stanza actually changed, so unrelated
	// commits never wipe probe state.
	d.reconcileRPM(cfg)

	// 17c. Reconcile the ip-monitoring engine (#1827 PR-1b): install
	// the committed policy set (preserving FAIL state across unrelated
	// commits) and seed it with current probe results.
	d.reconcileIPMon(cfg)

	// 18. Update chassis cluster interface monitors
	if d.routing != nil && cfg.Chassis.Cluster != nil &&
		len(cfg.Chassis.Cluster.RedundancyGroups) > 0 {
		d.routing.ApplyInterfaceMonitors(cfg.Chassis.Cluster.RedundancyGroups)
	}

	// 19. Update chassis cluster state machine
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		d.cluster.UpdateConfig(cfg.Chassis.Cluster)
		// Feed interface monitor statuses into cluster weight calculation
		if d.routing != nil {
			monStatuses := d.routing.InterfaceMonitorStatuses()
			for rgID, statuses := range monStatuses {
				for _, st := range statuses {
					d.cluster.SetMonitorWeight(rgID, st.Interface, !st.Up, st.Weight)
				}
			}
		}

		// RETH GARP is handled by native VRRP (VRRP-backed RETH).
		// No manual GARP registration needed.
	}

	// 20. Detect cluster transport config changes and restart comms (#87).
	// Only restart if comms were previously started (activeClusterTransport
	// is non-zero) and the new config differs.
	if d.cluster != nil && d.daemonCtx != nil {
		newTransport := clusterTransportFromConfig(cfg)
		if d.activeClusterTransport != (clusterTransportKey{}) && newTransport != d.activeClusterTransport {
			slog.Info("cluster: transport config changed, restarting comms",
				"old_control", d.activeClusterTransport.ControlInterface,
				"new_control", newTransport.ControlInterface,
				"old_peer", d.activeClusterTransport.PeerAddress,
				"new_peer", newTransport.PeerAddress,
				"old_fabric", d.activeClusterTransport.FabricInterface,
				"new_fabric", newTransport.FabricInterface,
				"old_fabric_peer", d.activeClusterTransport.FabricPeerAddress,
				"new_fabric_peer", newTransport.FabricPeerAddress)
			d.stopClusterComms()
			d.startClusterComms(d.daemonCtx)
		}

		// #4647 BUG-B: reconcile the #2239 DHCP lease-sync push loop against
		// the just-committed `dhcp-lease-synchronization` knob. Without this a
		// runtime knob-ON commit on a running cluster was a silent no-op (the
		// loop was launched only from the connect-time block) — counters stayed
		// 0/0 until an xpfd restart. ensureDHCPLeaseSyncLoop is idempotent, so a
		// knob-unchanged commit is a no-op, a knob-ON commit (re)launches the
		// loop against the live comms context, and a knob-OFF commit stops it.
		d.ensureDHCPLeaseSyncLoop(d.dhcpLeaseSyncEnabled(cfg))
	}

	// 21. Re-apply D3 RSS indirection on config change (#797 HIGH #2).
	// Worker count can change via commit (e.g. `set system dataplane
	// workers 6`), and the D3 disable knob can flip; either requires
	// re-running the reshape (or restore) against the current HW state.
	// Idempotent: matching tables skip the write. Non-mlx5 interfaces
	// are skipped at the per-interface guard. The allowlist is
	// recomputed from the *new* compiled config so interface-set
	// changes (added/removed zoned mlx5 interfaces, fabric interface
	// changes) take effect on the same commit.
	if !d.opts.NoDataplane {
		rssEnabled := true
		workers := 0
		var rssAllowed []string
		// #801: mirror the startup site so a commit that changes any
		// of the Step-0 knobs takes effect without a restart.
		var (
			governor          string
			netdevBudget      int
			coalesceEnable    bool
			coalesceRX        int
			coalesceTX        int
			userspaceDP       bool
			coalesceExplicit  bool
			claimHostTunables bool
		)
		if dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace &&
			cfg.System.UserspaceDataplane != nil {
			userspaceDP = true
			workers = cfg.System.UserspaceDataplane.Workers
			if cfg.System.UserspaceDataplane.RSSIndirectionDisabled {
				rssEnabled = false
			}
			rssAllowed = dpuserspace.UserspaceBoundLinuxInterfaces(cfg)
			claimHostTunables = cfg.System.UserspaceDataplane.ClaimHostTunables
			governor = cfg.System.UserspaceDataplane.CPUGovernor
			netdevBudget = cfg.System.UserspaceDataplane.NetdevBudget
			coalesceExplicit = cfg.System.UserspaceDataplane.CoalescenceAdaptiveExplicit
			if coalesceExplicit &&
				!cfg.System.UserspaceDataplane.CoalescenceAdaptiveDisabled {
				coalesceEnable = true
			}
			coalesceRX = cfg.System.UserspaceDataplane.CoalescenceRXUsecs
			coalesceTX = cfg.System.UserspaceDataplane.CoalescenceTXUsecs
		}
		reapplyRSSIndirection(rssEnabled, workers, rssAllowed)
		// #801 B1 + B2: opt-in gate + restore-on-disable.
		d.applyStep0Tunables(userspaceDP, claimHostTunables, governor, netdevBudget,
			coalesceExplicit, coalesceEnable, coalesceRX, coalesceTX, rssAllowed)
	}
	// #1778 + #2987 + #4433 + #5083 + #5310 + #5679 + #5696: deferred reconcile failures —
	// every reconcile step above has run; surface the networkd write failure, the
	// ordinary (non-abort) dataplane-apply failure (#5679 — the new policy is
	// NOT on the wire, the old one still is), the Kea restart/stop failure, the
	// IPsec render/reload failure, the interface-reconcile failure
	// (xfrmi/bond/tunnel/legacy-reth create/up/delete — #5310), and the route-leak
	// snapshot republish/FIB-bump failure (#5696 — a stale inter-VRF leak would
	// otherwise survive on a "successful" commit) through the commit so a step
	// that left stale or missing kernel/swanctl/dataplane state fails the commit
	// (fail-closed) instead of reporting success. All are joined so none masks the
	// other.
	return errors.Join(networkdErr, applyErr, dhcpServerErr, hostInboundErr, lo0Err, ipsecErr, ifaceErr, routeLeakErr, routingRuleErr, mgmtRouteErr, vrfErr, vrrpErr)
}

// compileErrorMustAbortApply reports whether a dataplane ApplyConfig error
// must abort the commit — i.e. the operator-facing commit must report
// failure rather than success against a fail-closed (disarmed) dataplane.
//
// It delegates to dpuserspace.IsRequiredProtocolGateError so the abort set
// is table-driven and co-located with the protocol-gate sentinels and the
// ensureRequiredSnapshotProtocolLocked gate that emits them. Before #2138
// this matched ONLY ErrPolicySchedulerProtocolIncompatible, so the sibling
// ErrPersistentSourceNATProtocolIncompatible fell through: ApplyConfig
// disarmed the helper but the commit was promoted/persisted anyway — a
// silent forwarding outage on a "successful" commit. The delegation covers
// both gates and any future required protocol gate the moment its sentinel
// joins the list.
//
// "Abort" here means the apply/commit-RPC result returned up to the
// HTTP/gRPC/CLI committer becomes non-nil. Store.Commit/CommitConfirmed/
// SyncApply have ALREADY promoted+persisted the compiled config before
// applyConfigLocked runs, so the abort does not unwind store promotion;
// the operator-visible signal is the failed commit plus the disarmed
// dataplane (the same contract the scheduler gate has always had).
func compileErrorMustAbortApply(err error) bool {
	return dpuserspace.IsRequiredProtocolGateError(err)
}

func (d *Daemon) setDataplaneDeferWorkers(deferWorkers bool) {
	if d.dp == nil {
		return
	}
	type deferSetter interface{ SetDeferWorkers(bool) }
	if setter, ok := d.dp.(deferSetter); ok {
		setter.SetDeferWorkers(deferWorkers)
		return
	}
	d.dp.Link().SetDeferWorkers(deferWorkers)
}

// reapplyAfterDeferredMAC runs the MANDATORY dataplane re-apply that arms the
// deferred AF_XDP workers after a live RETH virtual-MAC change with no link
// cycle (#5134). The first apply of this commit published a workerless
// DeferWorkers=true snapshot (worker startup was deferred so the double-bind
// does not EBUSY on mlx5 zero-copy queues); this re-apply — now with the
// correct MAC and DeferWorkers cleared — is what actually starts the workers.
//
// If the re-apply fails, the error MUST NOT be swallowed into a successful
// commit: the userspace manager only advances its snapshot bookkeeping on a
// successful publish, so a failed re-apply leaves the workerless snapshot as
// the published/last state and status reconciliation replays it forever —
// workers never bind and forwarding is silently down on this node. Record
// generation debt so the status reconcile loop retries the DeferWorkers=false
// publish until the workers bind, self-healing a transient helper /
// control-socket error.
func (d *Daemon) reapplyAfterDeferredMAC(cfg *config.Config) {
	if d.dp == nil {
		return
	}
	if _, err := d.dp.ApplyConfig(context.Background(), cfg); err != nil {
		slog.Warn("failed to re-apply after deferred MAC; recording worker-arm debt for retry",
			"err", err)
		d.recordDataplaneWorkerArmDebt()
	}
}

// recordDataplaneWorkerArmDebt records the #5134 deferred-MAC worker-arm debt on
// the dataplane so status reconciliation retries the DeferWorkers=false publish.
// Mirrors setDataplaneDeferWorkers: assert the recorder directly on d.dp, else
// reach it through the link controller.
func (d *Daemon) recordDataplaneWorkerArmDebt() {
	if d.dp == nil {
		return
	}
	type debtRecorder interface{ RecordDeferredWorkerArmDebt() }
	if r, ok := d.dp.(debtRecorder); ok {
		r.RecordDeferredWorkerArmDebt()
		return
	}
	if r, ok := d.dp.Link().(debtRecorder); ok {
		r.RecordDeferredWorkerArmDebt()
	}
}

// reconcileDHCPRelay re-applies the DHCP relay config on every commit (#2348).
// The relay Manager is created at boot (daemon_run.go) regardless of whether a
// relay was configured then, so a relay added on a day-2 commit starts here and
// a relay removed here stops. Manager.Apply diffs desired-vs-running per
// interface (start added / stop removed / restart changed / leave unchanged),
// and a nil relay config stops all relays. The relay goroutines bind to
// d.daemonCtx (the daemon lifetime) — NOT a request-scoped context — so they
// survive past this apply call and are torn down only at daemon stop. Guarded
// on d.dhcpRelay so a daemon constructed without a relay Manager (e.g. a test
// harness or NoDataplane boot that skipped the boot wiring) is a safe no-op.
func (d *Daemon) reconcileDHCPRelay(cfg *config.Config) {
	if d.dhcpRelay == nil {
		return
	}
	ctx := d.daemonCtx
	if ctx == nil {
		ctx = context.Background()
	}
	d.dhcpRelay.Apply(ctx, cfg.ForwardingOptions.DHCPRelay)
}

// effectiveLLDPConfig translates the typed `protocols lldp` stanza into the
// lldp.LLDPConfig the manager consumes, or returns nil when LLDP is disabled,
// empty, or absent (the "stop the service" signal). It is the single mapping
// used by both boot and the day-2 reconcile, so the diff-guard in reconcileLLDP
// compares like-for-like.
func effectiveLLDPConfig(cfg *config.Config) *lldp.LLDPConfig {
	if cfg == nil || cfg.Protocols.LLDP == nil ||
		cfg.Protocols.LLDP.Disable || len(cfg.Protocols.LLDP.Interfaces) == 0 {
		return nil
	}
	lldpIfaces := make([]lldp.LLDPInterface, 0, len(cfg.Protocols.LLDP.Interfaces))
	for _, iface := range cfg.Protocols.LLDP.Interfaces {
		lldpIfaces = append(lldpIfaces, lldp.LLDPInterface{
			Name:    iface.Name,
			Disable: iface.Disable,
		})
	}
	return &lldp.LLDPConfig{
		Interfaces:     lldpIfaces,
		Interval:       cfg.Protocols.LLDP.Interval,
		HoldMultiplier: cfg.Protocols.LLDP.HoldMultiplier,
		SystemName:     cfg.System.HostName,
	}
}

// reconcileLLDP re-applies the LLDP service config on every commit (#2372). It
// is the single source of truth for LLDP lifecycle — daemon_run.go calls it at
// boot, and applyConfigLocked calls it on every day-2 commit, so a change to
// `protocols lldp` takes effect without a daemon restart.
//
// The manager itself is constructed exactly once at boot (daemon_run.go),
// mirroring d.dhcpRelay. reconcileLLDP NEVER reassigns the d.lldpMgr pointer —
// it only calls Apply()/Stop() on the already-constructed manager. This keeps
// the lock-free d.lldpMgr reads on the `show lldp neighbors` handler goroutines
// race-free against a concurrent commit (finding 3): the pointer is written
// once, before any handler can run.
//
// Change-guarded (finding 6): lldp.Manager.Apply unconditionally Stop()s the
// current generation — closing every per-interface socket, joining goroutines,
// AND wiping the neighbor table — before rebuilding. Calling it on every commit
// would blank `show lldp neighbors` and churn sockets on any unrelated day-2
// commit (e.g. a firewall-policy change) while neighbors re-learn. So Apply (or
// Stop) is invoked only when the effective LLDP config actually changed from the
// last-applied one, matching the diff discipline of the adjacent
// reconcileDHCPRelay (#2348). The first call (boot) always applies.
//
// The manager is bound to d.daemonCtx (the daemon lifetime) — NOT a
// request-scoped context — so the TX/RX/expiry goroutines survive past this
// apply call and are torn down only at daemon stop (or the next reconcile that
// disables LLDP).
func (d *Daemon) reconcileLLDP(cfg *config.Config) {
	if d.lldpMgr == nil {
		// Defensive: a test harness or a boot path that skipped the construct-
		// once wiring leaves the manager nil. Nothing to reconcile.
		return
	}

	want := effectiveLLDPConfig(cfg)

	// Skip when the effective config is unchanged since the last reconcile, so
	// an unrelated commit never bounces a healthy LLDP generation (sockets +
	// neighbor table). The first reconcile (boot) always runs.
	if d.lldpApplyInit && lldpConfigEqual(d.lldpApplied, want) {
		return
	}
	d.lldpApplyInit = true
	d.lldpApplied = want

	if want == nil {
		// Disabled / empty: stop the running service (idempotent if already
		// stopped).
		d.lldpMgr.Stop()
		return
	}

	ctx := d.daemonCtx
	if ctx == nil {
		ctx = context.Background()
	}
	d.lldpMgr.Apply(ctx, want)
}

// initEventEngine constructs the event-options engine and registers the RPM
// event callback (#3752). Like the LLDP manager and the DHCP relay manager, it
// is created UNCONDITIONALLY at boot — not gated on the boot config already
// carrying an event-options policy — so:
//
//   - the d.eventEngine pointer is written exactly ONCE at boot and read-only
//     thereafter, keeping the lock-free reads on the `Stats()` metric/CLI
//     handler goroutines race-free (the same pointer-race discipline #2372
//     established for d.lldpMgr); and
//   - a day-2 commit enabling the FIRST event-options policy takes effect
//     immediately via reconcileEventOptions, instead of being inert until a
//     daemon restart (the #3752 defect).
//
// The engine routes its remediation commit through d.commitAndApply so it
// serializes with HTTP/gRPC commits under d.applySem (#846). Event-options
// changes do not sync to the peer — the engine fires independently on each
// node from that node's local RPM events. Idempotent: a second call is a no-op.
func (d *Daemon) initEventEngine() {
	if d.eventEngine != nil {
		return
	}
	d.eventEngine = eventengine.New(d.store, func(ctx context.Context, comment string) (*config.Config, error) {
		return d.commitAndApply(ctx, comment, false)
	})
	if d.rpm != nil {
		d.rpm.SetEventCallback(d.eventEngine.HandleEvent)
	}
	slog.Info("event-options engine constructed")
}

// reconcileEventOptions applies the committed event-options policy set to the
// engine on every commit (#3752). The engine is constructed once at boot
// (initEventEngine); this only ever calls Apply, which RECONCILES per-policy
// runtime state (carrying cooldown/window memory forward for unchanged
// policies, #2140). It NEVER reassigns the pointer. A nil cfg (or empty policy
// set) applies zero policies — a no-op that also clears a removed set.
func (d *Daemon) reconcileEventOptions(cfg *config.Config) {
	if d.eventEngine == nil {
		// Defensive: boot wiring constructs the engine before any reconcile.
		return
	}
	var policies []*config.EventPolicy
	if cfg != nil {
		policies = cfg.EventOptions
	}
	d.eventEngine.Apply(policies)
}

// lldpConfigEqual reports whether two effective LLDP configs are equivalent for
// reconcile purposes (both nil, or deeply equal). nil means "service stopped".
func lldpConfigEqual(a, b *lldp.LLDPConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.DeepEqual(a, b)
}

func (d *Daemon) publishInitialPolicySchedulerStateLocked(cfg *config.Config, activeState map[string]bool, applyResult *dataplane.ApplyResult) {
	if d.dp == nil || activeState == nil || applyResult == nil {
		return
	}
	if _, isUserspace := d.dp.(userspaceRuntimeModeReporter); isUserspace {
		return
	}
	// #3780: initial (eBPF-path) publish rides the apply transaction; a
	// failure here is surfaced via the same republish-failure metric so
	// it is not silently swallowed. The retired eBPF updater always
	// reports success, so this is a no-op there today.
	d.recordSchedulerRepublishResult(d.updatePolicyScheduleStateLocked(cfg, activeState))
}
