// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/lldp"
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
