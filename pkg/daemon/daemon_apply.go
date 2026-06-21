// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/ipsec"
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

// bootstrapFromFile reads the text Junos config file and imports it as the
// initial active configuration. This is called on first start when the DB
// has no active config yet.
func (d *Daemon) bootstrapFromFile() error {
	data, err := os.ReadFile(d.opts.ConfigFile)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	// Import into the store: enter config mode, load, commit.
	// Commit() handles compilation (including ${node} variable expansion
	// when nodeID is set on the store for cluster mode).
	if err := d.store.EnterConfigure(); err != nil {
		return fmt.Errorf("enter configure: %w", err)
	}
	if err := d.store.LoadOverride(string(data)); err != nil {
		d.store.ExitConfigure()
		return fmt.Errorf("load override: %w", err)
	}
	if _, err := d.store.Commit(); err != nil {
		d.store.ExitConfigure()
		return fmt.Errorf("commit: %w", err)
	}
	d.store.ExitConfigure()
	slog.Info("configuration bootstrapped from file", "file", d.opts.ConfigFile)
	return nil
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
	if err := d.applyConfigLocked(cfg); err != nil {
		slog.Warn("apply config failed", "err", err)
	}
}

// commitAndApply atomically promotes the candidate config and
// applies it. Holds applySem across configstore.Commit and
// applyConfigLocked so two concurrent committers can't interleave
// their commit→apply pairs (which would let kernel state lag store
// state). Optionally syncs to the cluster peer inside the lock.
//
// If ctx is canceled before the semaphore is acquired, returns
// ctx.Err() and NEITHER commit nor apply runs — no divergence. Once
// the semaphore is held, commit and apply run to completion;
// cancellation past that point is ignored (applyConfigLocked is not
// safe to interrupt mid-stream — kernel route writes, FRR reload,
// etc.).
func (d *Daemon) commitAndApply(ctx context.Context, comment string, syncPeer bool) (*config.Config, error) {
	// #1922 Item 2 first-takeover gate (OQ-B, blunt resolution). In
	// bootstrap mode a plain `commit` is refused: the first commit on a
	// foreign/non-appliance host claims interfaces and can cut off
	// management, so it MUST go through `commit confirmed <minutes>` (the
	// system rolls back automatically unless the operator confirms it from
	// a still-reachable session). The gate is blunt (any first commit, not
	// just interface-claiming ones) — the simplest safe rule, matching the
	// #1879 §5 recommendation; the confirmed-commit path is the escape
	// hatch (no separate `commit no-confirm` foot-gun is introduced). Once
	// the first confirmed commit is confirmed (bootstrap exits one-way),
	// plain commits work normally. The day-0 image path never hits this —
	// it resolves NOT-bootstrap before any interactive session.
	if d.inBootstrap() {
		// The daemon is in bootstrap mode (no interface takeover has been
		// confirmed yet). A plain commit is refused regardless of whether
		// this is literally the first commit — bootstrap only exits on a
		// CONFIRMED non-empty (interface-claiming) commit, so until then any
		// takeover must go through commit-confirmed (Copilot: message worded
		// for the mode, not "first commit", since a confirmed-but-empty
		// commit leaves the daemon in bootstrap).
		return nil, fmt.Errorf("system is in bootstrap mode: commit the takeover config with " +
			"'commit confirmed <minutes>' (the interface takeover can cut off management, so the " +
			"system rolls back automatically unless you confirm it from a still-reachable session)")
	}

	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	// #1956 R-8 device-map pre-flight: reject a candidate whose device-map
	// would strand management on next boot, while the operator is still
	// connected and BEFORE the store promotes it. Runs under applySem (after
	// Acquire) but before Commit, so a reject never leaves a promoted store.
	// Plain commit has no auto-rollback target, so pass nil.
	if cand, err := d.store.CompileCandidate(); err == nil {
		if err := d.deviceMapCommitPreflight(cand, nil); err != nil {
			return nil, err
		}
	}

	var compiled *config.Config
	var err error
	if comment != "" {
		compiled, err = d.store.CommitWithDescription(comment)
	} else {
		compiled, err = d.store.Commit()
	}
	if err != nil {
		return nil, err
	}
	if err := d.applyConfigLocked(compiled); err != nil {
		return nil, err
	}
	if syncPeer {
		d.syncConfigToPeer()
	}
	return compiled, nil
}

// syncAndApply is the cluster-sync-recv analogue of commitAndApply.
// Holds applySem across configstore.SyncApply (peer-driven active
// promotion) + applyConfigLocked, so a peer-sync can't interleave
// between a local committer's Commit and applyConfig (which would
// briefly leave store=peer-config but kernel=local-config).
func (d *Daemon) syncAndApply(ctx context.Context, configText string, chassisPreserve func(*config.ConfigTree)) (*config.Config, error) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	compiled, err := d.store.SyncApply(configText, chassisPreserve)
	if err != nil {
		return nil, err
	}
	if compiled != nil {
		if err := d.applyConfigLocked(compiled); err != nil {
			return nil, err
		}
		// #1956 V-1 passive-node device-map admission gate (OQ-15.1 option
		// (a): passive gate + loud health alarm). The active node's strict
		// commit can only validate ITS OWN hardware (R-8), so a synced
		// config whose LOCAL device-map section would strand THIS node's
		// management on next boot must be surfaced loudly here. We do NOT
		// strip/modify the synced delta (that creates the config-divergence
		// overwrite loop AGY flagged); the stores stay identical and the
		// #1922 lifeline keeps mgmt reachable at runtime. The alarm is the
		// operator's signal that the peer-pushed map needs fixing before a
		// reboot. (Option (b), distributed pre-commit validation, is the
		// documented end-state follow-up.)
		d.deviceMapPassiveAdmissionAlarm(compiled)
	}
	return compiled, nil
}

// deviceMapPassiveAdmissionAlarm raises a loud, never-silent HA-health alarm
// when a peer-synced config's LOCAL device-map would strand this node's
// management on next boot. Stores are NOT modified (no divergence loop) — the
// alarm + the #1922 lifeline are the safety net. See syncAndApply.
func (d *Daemon) deviceMapPassiveAdmissionAlarm(synced *config.Config) {
	if synced == nil || !synced.Chassis.DeviceMap.Active() {
		return
	}
	nics, err := enumeratePresentNICs()
	if err != nil {
		// AGY MINOR-5: do not let a transient hardware-lookup failure
		// silently bypass the admission gate — log loudly so the operator
		// knows the peer map was applied unchecked.
		slog.Warn("HA CONFIG-SYNC: could not enumerate NICs to check the peer-pushed device-map "+
			"for a management-lockout; the config is applied UNCHECKED. Re-verify the device-map "+
			"on this node.", "err", err)
		return
	}
	lifelineName, _ := resolveLifelineCurrentName()
	if reason := deviceMapStrandsManagement(synced, nics, protectedForConfig(synced), lifelineName); reason != "" {
		slog.Error("HA CONFIG-SYNC ALARM: the peer-pushed device-map would STRAND this node's "+
			"management on next boot. The config is applied (stores stay consistent) and the "+
			"management lifeline keeps the box reachable now, but a reboot would lock this node "+
			"out. Fix the device-map on the primary and re-sync BEFORE rebooting this node.",
			"reason", reason)
	}
}

// commitConfirmedAndApply is the commit-confirmed analogue of
// commitAndApply. Same atomicity guarantees.
func (d *Daemon) commitConfirmedAndApply(ctx context.Context, minutes int, syncPeer bool) (*config.Config, error) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	// #1956 R-8/V-3 device-map pre-flight: validate BOTH the candidate AND
	// the rollback target (the currently-active config, restored on a
	// confirmed-commit timeout) against present hardware. If EITHER would
	// strand management on next boot, reject while the operator is still
	// connected — so when a timeout fires the target is KNOWN-safe and is
	// applied UNCONDITIONALLY (OQ-15.2, no rollback-time abort). Runs under
	// applySem before Commit, so a reject never leaves a promoted store.
	if cand, err := d.store.CompileCandidate(); err == nil {
		if err := d.deviceMapCommitPreflight(cand, d.store.ActiveConfig()); err != nil {
			return nil, err
		}
	}

	compiled, err := d.store.CommitConfirmed(minutes)
	if err != nil {
		return nil, err
	}
	if err := d.applyConfigLocked(compiled); err != nil {
		return nil, err
	}
	if syncPeer {
		d.syncConfigToPeer()
	}
	return compiled, nil
}

// executeConfirmedRollback is the daemon-owned commit-confirmed timeout
// rollback transaction (#1922 Item 1a). The configstore confirm timer
// fires this (via SetRollbackExecutor) on its own goroutine, NOT under
// the store lock. It acquires d.applySem FIRST, then promotes the store
// state (PromoteRollback) and re-applies the rolled-back config to the
// dataplane inside that single critical section, so a concurrent commit
// (which also holds d.applySem via commitAndApply / commitConfirmedAndApply)
// cannot interleave between store promotion and dataplane re-apply. This
// fixes both bugs the old CLI-registered centralRollbackFn callback had:
// the non-atomic promote-then-apply split-brain window, and service-mode
// (gRPC/REST/remote-cli) timeouts that never re-applied the dataplane
// because no interactive CLI.Run had registered the callback.
//
// Lock order is applySem -> s.mu (matches commitAndApply / syncAndApply):
// every store call made while applySem is held (PromoteRollback, and the
// store calls inside applyConfigLocked such as SetArchiveConfig) takes and
// releases s.mu internally — applySem is always acquired FIRST and s.mu is
// never held across an applySem acquisition, so there is no inversion.
func (d *Daemon) executeConfirmedRollback(gen uint64) {
	_ = d.applySem.Acquire(context.Background(), 1)
	defer d.applySem.Release(1)

	prevCfg, ok := d.store.PromoteRollback(gen)
	if !ok {
		// Superseded (nested CommitConfirmed / ConfirmCommit) or no
		// pending rollback target — nothing happened, nothing to apply.
		return
	}
	if prevCfg == nil {
		// #1922 Item 1b: first commit confirmed on a fresh store timed out.
		// The store already reverted to the empty tree AND persisted the
		// never-committed marker (PromoteRollback). A normal apply of an
		// empty config is WRONG here — it would resurrect the dataplane the
		// failed takeover started and leave a half-configured box. Instead
		// roll the daemon back to bootstrap mode: re-suppress takeover and
		// clean up the takeover artifacts (networkd files, FRR managed
		// section, dataplane attach) the failed first commit created, except
		// the management lifeline. Runs under d.applySem (held above).
		slog.Warn("commit confirmed (first commit) timed out; rolling back to BOOTSTRAP mode " +
			"(removing interface/FRR/dataplane takeover, keeping the management lifeline)")
		d.enterBootstrapMode()
		return
	}
	// #1956 V-3/OQ-15.2: the non-nil rollback target is applied
	// UNCONDITIONALLY here — never aborted for device-map safety. Its
	// device-map safety was validated at commit-confirmed time (the R-8
	// pre-flight checks BOTH candidate and rollback target), so by the time
	// this fires the target is KNOWN-safe. Aborting here would diverge the
	// already-promoted store from the running dataplane (split-brain), which
	// is strictly worse than applying a validated target.
	if err := d.applyConfigLocked(prevCfg); err != nil {
		slog.Error("commit confirmed auto-rollback dataplane apply failed", "err", err)
	}
	slog.Warn("commit confirmed timed out, configuration rolled back")
}

// applyConfigLocked runs the actual reconcile pipeline. MUST be
// called with d.applySem held.
func (d *Daemon) applyConfigLocked(cfg *config.Config) error {
	if d.applyBodyForTest != nil {
		d.applyBodyForTest(cfg)
		return nil
	}

	// Defensive nil guard (AGY r2 Low): no production caller passes a nil
	// compiled config (commitAndApply / syncAndApply / the boot apply all
	// nil-check first), but the bootstrap-exit block below reads cfg, and
	// the historical body dereferences cfg.Warnings — make the contract
	// explicit so a future caller cannot panic the reconcile.
	if cfg == nil {
		return nil
	}

	// Reconcile the SNMP agent's live authorization/identity config FIRST
	// (#2008 H17, Codex r2). The agent is created once at startup
	// (daemon_run.go) and keeps serving on UDP/161; without this step a
	// commit that flips a community read-write -> read-only, deletes a
	// community, or changes the v3 user set would not reach the running agent
	// until a daemon restart, leaving the SET access-control gate reading
	// stale authorization.
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
	// The swap is in-place (UpdateConfig holds the agent's cfgMu) so the UDP
	// listener and in-flight polls are not interrupted, and it is idempotent —
	// an atomic pointer/table swap, safe to call once per apply. Guarded on a
	// non-nil agent: if SNMP was not enabled at startup there is no running
	// listener to reconcile (enabling SNMP for the first time still requires a
	// restart, matching the other start-once subsystems).
	if d.snmpAgent != nil {
		d.snmpAgent.UpdateConfig(cfg.System.SNMP)
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

	// Reset VIP warning suppression so new config gets fresh warnings.
	d.vipWarnedIfaces = nil

	// Log config validation warnings
	for _, w := range cfg.Warnings {
		slog.Warn("config validation", "warning", w)
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
			slog.Warn("failed to reconcile VRFs", "err", err)
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
	d.mgmtVRFInterfaces = nil
	if d.routing != nil && len(mgmtIfaces) > 0 && d.routing.IsManagedVRF(mgmtVRFName) {
		d.mgmtVRFInterfaces = mgmtIfaces
		for ifName := range mgmtIfaces {
			if err := d.routing.BindInterfaceToVRF(ifName, mgmtVRFName); err != nil {
				slog.Warn("failed to bind interface to management VRF",
					"interface", ifName, "err", err)
			}
		}
	}

	// 0.6. Program default routes in the management VRF for DHCP leases.
	d.applyMgmtVRFRoutes()

	// 1. Create tunnel interfaces (interface-level + per-unit tunnels)
	if d.routing != nil {
		if err := d.routing.ApplyTunnels(collectAppliedTunnels(cfg)); err != nil {
			slog.Warn("failed to apply tunnels", "err", err)
		}
	}

	// 1.5. Create xfrmi interfaces for IPsec VPN tunnels.
	// Must happen before BPF compilation so compileZones() can discover
	// the xfrmi interfaces and map them to security zones.
	// Always call ApplyXfrmi so stale xfrmi devices are removed when VPNs
	// are deleted from config.
	if d.routing != nil {
		if err := d.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
			slog.Warn("failed to apply xfrmi interfaces", "err", err)
		}
	}

	// 1.7. Create bond (LAG) interfaces for fabric-options member-interfaces.
	// Always call ApplyBonds (even with empty list) so stale bonds from
	// previous configs get cleaned up via ClearBonds().
	if d.routing != nil {
		var bondIfaces []*config.InterfaceConfig
		for _, ifc := range cfg.Interfaces.Interfaces {
			if len(ifc.FabricMembers) > 0 {
				bondIfaces = append(bondIfaces, ifc)
			}
		}
		if err := d.routing.ApplyBonds(bondIfaces); err != nil {
			slog.Warn("failed to apply bonds", "err", err)
		}
	}

	// 1.8. Clean up legacy RETH bond devices from previous binary versions.
	// VRRP now runs directly on physical member interfaces — no bonds needed.
	if d.routing != nil {
		d.routing.ClearRethInterfaces()
	}

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
		if ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
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
			if !ok || rethCfg.RedundancyGroup <= 0 {
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
	commitOverlay := d.commitOverlayForConfig(cfg)
	if setter, ok := d.dp.(routeOverlaySetter); ok {
		setter.SetRouteOverlay(commitOverlay)
	}

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

	// 2. Apply dataplane config through the runtime config sink.
	var applyResult *dataplane.ApplyResult
	if d.dp != nil {
		var err error
		if applyResult, err = d.dp.ApplyConfig(context.Background(), cfg); err != nil {
			d.recordCompileFailure(err)
			if compileErrorMustAbortApply(err) {
				return err
			}
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
	if d.sessionSync != nil && applyResult != nil {
		d.sessionSync.SetZoneRGMap(buildZoneRGMap(cfg, applyResult.ZoneIDs))
	}

	// 2.45. #1956 V-4: managed->unmapped teardown MUST run BEFORE
	// networkd.Apply so its stale-file sweep has nothing to half-clean.
	// No-op idempotent when nothing transitioned (zero churn on an
	// unrelated commit).
	if cfg.Chassis.DeviceMap.Active() {
		teardownUnmappedManaged(cfg.Chassis.DeviceMap, protectedForConfig(cfg))
	}

	// 2.5. Write systemd-networkd config for managed interfaces
	if d.networkd != nil && applyResult != nil && len(applyResult.ManagedInterfaces) > 0 {
		if err := d.networkd.Apply(applyResult.ManagedInterfaces); err != nil {
			slog.Warn("failed to apply networkd config", "err", err)
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
			if !ok || rethCfg.RedundancyGroup <= 0 {
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
		if _, err := d.dp.ApplyConfig(context.Background(), cfg); err != nil {
			slog.Warn("failed to re-apply after deferred MAC", "err", err)
		}
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
	// the VRF= directive. Re-bind here to restore VRF membership.
	if d.routing != nil && d.mgmtVRFInterfaces != nil {
		for ifName := range d.mgmtVRFInterfaces {
			if err := d.routing.BindInterfaceToVRF(ifName, "mgmt"); err != nil {
				slog.Warn("failed to re-bind interface to management VRF",
					"interface", ifName, "err", err)
			}
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

	// 3. Apply all routes + dynamic protocols via FRR.
	// assembleFRRConfig is the SOLE frr.FullConfig constructor, shared
	// with the ip-monitoring routes-only actuator (#1827) — the full
	// apply consumes the same (config-filtered) overlay computed in
	// step 1.95, so an operator commit while a policy is FAILED
	// preserves a still-valid injected failover route and drops
	// removed/edited entries on the commit itself.
	if d.frr != nil {
		d.applyFRRConfig(d.assembleFRRConfig(cfg, commitOverlay))
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
		}
	}

	// 3c. Apply rib-group route leaking rules (ip rule)
	if d.routing != nil && len(cfg.RoutingOptions.RibGroups) > 0 {
		if err := d.routing.ApplyRibGroupRules(cfg.RoutingOptions.RibGroups, cfg.RoutingInstances); err != nil {
			slog.Warn("failed to apply rib-group rules", "err", err)
		}
	}

	// 3d. Apply policy-based routing rules (ip rule) for firewall filter routing-instance
	if d.routing != nil {
		pbrRules := routing.BuildPBRRules(&cfg.Firewall, cfg.RoutingInstances)
		if err := d.routing.ApplyPBRRules(pbrRules); err != nil {
			slog.Warn("failed to apply PBR rules", "err", err)
		}
	}

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
			// No RA configs — clear any previous RA senders.
			if err := d.ra.Clear(); err != nil {
				slog.Warn("failed to clear RA config", "err", err)
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

	// 6. Apply IPsec config
	// Always call Apply so stale swanctl config is removed when VPNs are
	// deleted from config.
	if d.ipsec != nil {
		if err := d.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
			slog.Warn("failed to apply IPsec config", "err", err)
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

	// 7b. Reconcile DHCP clients (#1793): start clients for units that
	// gained dhcp/dhcpv6 in this commit, stop clients for units that
	// lost it, restart clients whose options changed. The diff keys on
	// config identity only (interface, family, options) — never lease
	// state — so the DHCP lease-change callback re-entering applyConfig
	// (onDHCPAddressChange) cannot restart clients in a loop. Runs after
	// the dataplane compile (step 2) so HOST_INBOUND_DHCP flags are
	// active before a newly started client puts DHCP packets on the wire.
	d.reconcileDHCPClients(cfg)

	// 8. Apply VRRP config — merge user VRRP + RETH VRRP instances
	vrrpInstances := vrrp.CollectInstances(cfg)
	if d.cluster != nil {
		localPri := d.cluster.LocalPriorities()
		vrrpInstances = append(vrrpInstances, vrrp.CollectRethInstances(cfg, localPri)...)
	}
	if err := d.vrrpMgr.UpdateInstances(vrrpInstances); err != nil {
		slog.Warn("failed to update VRRP instances", "err", err)
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
	d.applyLo0Filter(cfg)

	// 9.6. Write SSH known hosts file
	d.applySSHKnownHosts(cfg)

	// 10. Apply system syslog forwarding
	d.applySystemSyslog(cfg)

	// 11. Apply system login users (create OS accounts, SSH keys)
	d.applySystemLogin(cfg)

	// 12. Apply SSH service configuration (root-login)
	d.applySSHConfig(cfg)

	// 13. Apply root authentication (encrypted-password + SSH keys)
	d.applyRootAuth(cfg)

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

	// 17. Update event-options policies (RPM-driven failover)
	if d.eventEngine != nil {
		d.eventEngine.Apply(cfg.EventOptions)
	}

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
	// #1778: deferred DHCP-server failure — every reconcile step above
	// has run; surface the Kea restart/stop failure through the commit.
	return dhcpServerErr
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

func (d *Daemon) publishInitialPolicySchedulerStateLocked(cfg *config.Config, activeState map[string]bool, applyResult *dataplane.ApplyResult) {
	if d.dp == nil || activeState == nil || applyResult == nil {
		return
	}
	if _, isUserspace := d.dp.(userspaceRuntimeModeReporter); isUserspace {
		return
	}
	d.updatePolicyScheduleStateLocked(cfg, activeState)
}
