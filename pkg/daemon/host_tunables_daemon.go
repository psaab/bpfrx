// Daemon-side wiring for #801 Phase-B Step-0 host tunables.
//
// This file owns the state machine for the B1 opt-in gate and the B2
// restore-on-disable path. The pure capture/restore logic lives in
// host_tunables.go — here we route calls through the Daemon struct's
// priorTunables field so the same snapshot survives startup → commit →
// disable → shutdown.
//
// # Scope split (Codex round-2 fix)
//
// Two separate blast radii travel through this file:
//
//  1. Host-scope knobs (cpu-governor, netdev_budget): these touch
//     system-wide kernel state that every other workload on the host
//     shares. They MUST stay behind the `claim-host-tunables` opt-in
//     gate per the B1 finding — flipping the CPU governor or raising
//     netdev_budget silently would violate D3's "only touch what xpfd
//     owns" invariant.
//
//  2. Per-interface coalescence (ethtool -C adaptive / rx-usecs /
//     tx-usecs): this is interface-scoped — same blast radius as D3's
//     RSS indirection rewrite. The #801 Step-0 win (REV CoV
//     7.68%→1.5% on mlx5 adaptive-off) lives entirely in this knob.
//     It runs regardless of `claim-host-tunables` because the mlx5
//     interface is already inside xpfd's zone model, identified via
//     the same `UserspaceBoundLinuxInterfaces` allowlist D3 uses.
//
// Transition matrix for the host-scope knobs (opt_in = claim-host-tunables):
//
//	prior      new        action
//	-------    -------    ----------------------------------------------
//	false      false      no-op (never claimed)
//	false      true       capture + write
//	true       true       capture-if-not-already + write (reconcile)
//	true       false      restore (B2), discard snapshot
//	(shutdown) *          restore (if active) on daemon Stop
//
// Coalescence (interface-scoped) runs on every apply with the same
// allowlist, capturing its own pre-xpfd state for restore on explicit
// adaptive re-enable or daemon shutdown.
package daemon

import (
	"log/slog"
)

// applyStep0Tunables is the single wire point for #801 Step-0 host
// tunables. Called from Run() at startup and from applyConfig() on
// every commit. Handles three responsibilities:
//
//  1. Opt-in gate (B1): host-scope knobs + adaptive flip are only
//     applied when claim_host_tunables is true.
//  2. Snapshot + write (B2): on every apply while claimed, the
//     pre-xpfd value is captured before the first write so restore can
//     revert to the exact pre-xpfd string.
//  3. Restore-on-disable (B2): when claim flips true → false, every
//     captured value is written back and the snapshot is cleared.
//
// Never returns an error — any failure logs and continues. Tunable
// regressions must not block commit or daemon start.
func (d *Daemon) applyStep0Tunables(userspaceDP, claimHostTunables bool,
	governor string, netdevBudget int,
	coalesceExplicit, coalesceEnable bool, coalesceRX, coalesceTX int,
	rssAllowed []string) {
	d.applyStep0TunablesWith(userspaceDP, claimHostTunables, governor, netdevBudget,
		coalesceExplicit, coalesceEnable, coalesceRX, coalesceTX, rssAllowed,
		realHostTunableFS{}, realRSSExecutor{})
}

// applyStep0TunablesWith is the injectable variant used by unit tests.
// Production callers go through applyStep0Tunables (which pins the FS
// + executor to the real implementations).
//
// The function runs two independent pipelines, deliberately NOT a
// shared gate (Codex round-2 BLOCKER fix):
//
//   - Coalescence (interface-scoped): always runs for userspace-dp
//     mlx5 interfaces on the `rssAllowed` allowlist, regardless of
//     `claimHostTunables`. The mlx5 adaptive-off win is the headline
//     #801 result and defaulting it off behind an opt-in gate would
//     disable it for everyone who doesn't also opt into the
//     host-scope knobs. Coalescence captures its own pre-xpfd state
//     into `d.priorTunables.mlx5Adaptive` so shutdown-restore still
//     reverts the interfaces xpfd touched.
//
//   - Host-scope knobs (cpu-governor, netdev_budget): gated by
//     `claimHostTunables` per the B1 finding. Same state machine as
//     before — capture/write on first claim, restore-on-disable when
//     the opt-in flips back off.
func (d *Daemon) applyStep0TunablesWith(userspaceDP, claimHostTunables bool,
	governor string, netdevBudget int,
	coalesceExplicit, coalesceEnable bool, coalesceRX, coalesceTX int,
	rssAllowed []string,
	fs hostTunableFS, execer rssExecutor) {

	d.priorTunablesMu.Lock()
	prior := d.priorTunables
	active := d.priorTunablesActive
	d.priorTunablesMu.Unlock()

	// Ensure a snapshot exists for coalescence capture even when the
	// host-scope opt-in is off. The snapshot is the same struct used
	// by the host-scope path; only the governors/budget sub-fields
	// remain empty until (and unless) the operator opts in. This
	// keeps shutdown-restore honest: interfaces xpfd touched are
	// reverted even when cpu-governor/netdev_budget were never set.
	if prior == nil {
		prior = newPriorHostTunables()
	}

	// Coalescence always runs for userspace-dp deploys. Empty
	// allowlist = no-op inside applyCoalescence. The allowlist is
	// D3-scoped (UserspaceBoundLinuxInterfaces) so we never touch an
	// mlx5 interface outside xpfd's zone model.
	if userspaceDP {
		applyCoalescence(coalesceEnable, coalesceRX, coalesceTX, rssAllowed, execer, prior)
	}

	// Host-scope restore path: previously claimed, now gated off.
	// Restore only the host-scope fields (governors + budget); leave
	// the mlx5Adaptive captures in place because coalescence is still
	// active and those are the snapshots shutdown-restore relies on.
	if active && (!userspaceDP || !claimHostTunables) {
		slog.Info("linksetup: claim-host-tunables disabled, restoring pre-xpfd host-scope values")
		restoreHostScopeTunables(prior, fs)
		d.priorTunablesMu.Lock()
		// Keep the snapshot object alive if coalescence just
		// captured new mlx5 state; only clear host-scope fields.
		prior.governors = map[string]string{}
		prior.budget = ""
		d.priorTunables = prior
		// Claim is now off but coalescence may still have captures;
		// keep priorTunablesActive aligned with claim state so the
		// same restore path doesn't re-fire next reconcile.
		d.priorTunablesActive = false
		d.priorTunablesMu.Unlock()
		return
	}

	// No-op host-scope path: never claimed, nothing to do there.
	// Coalescence writes (if any) already happened above.
	if !userspaceDP || !claimHostTunables {
		slog.Debug("linksetup: step0 host-scope tunables skip (claim-host-tunables not set)",
			"userspace_dp", userspaceDP, "claim", claimHostTunables)
		// Persist the snapshot so coalescence captures survive across
		// reconciles even when the operator never opts in.
		d.priorTunablesMu.Lock()
		d.priorTunables = prior
		d.priorTunablesMu.Unlock()
		return
	}

	// Claim path: snapshot + host-scope write. Host-scope snapshot
	// fields may already be captured from a previous claimed apply;
	// applyHostTunables's capture*() helpers are first-apply-wins so
	// the reconcile case is safe.
	gov, budget := resolvedHostTunables(governor, netdevBudget, true)
	applyHostTunables(gov, budget, fs, prior)

	d.priorTunablesMu.Lock()
	d.priorTunables = prior
	d.priorTunablesActive = true
	d.priorTunablesMu.Unlock()
}

// restoreStep0TunablesOnShutdown is called from the daemon's shutdown
// path. It restores every captured tunable so the host reverts to its
// pre-xpfd state when xpfd exits — matching D3's cleanup contract and
// preventing operators from being left with performance governor +
// netdev_budget=600 after stopping the daemon.
//
// Covers both pipelines from applyStep0TunablesWith:
//   - Host-scope (governor + netdev_budget): captured only when the
//     claim-host-tunables opt-in was active. `active` flag tells us.
//   - Per-interface coalescence (mlx5Adaptive map): captured any time
//     coalescence ran, which is any userspace-dp start regardless of
//     the opt-in gate (Codex round-2 fix).
//
// Best-effort: never returns an error. Safe to call when no tunable
// was ever captured (no-op).
func (d *Daemon) restoreStep0TunablesOnShutdown() {
	d.priorTunablesMu.Lock()
	prior := d.priorTunables
	active := d.priorTunablesActive
	d.priorTunables = nil
	d.priorTunablesActive = false
	d.priorTunablesMu.Unlock()

	if prior == nil {
		slog.Debug("shutdown: host tunables restore skip (no captures)")
		return
	}
	// Scope the log message to what we actually restore so operators
	// can tell a coalescence-only revert from a full host-scope revert.
	hasHostScope := active && (len(prior.governors) > 0 || prior.budget != "")
	hasCoalesce := len(prior.mlx5Adaptive) > 0
	if !hasHostScope && !hasCoalesce {
		slog.Debug("shutdown: host tunables restore skip (empty captures)")
		return
	}
	slog.Info("shutdown: restoring tunables to pre-xpfd values",
		"host_scope", hasHostScope, "coalesce_ifaces", len(prior.mlx5Adaptive))
	// Host-scope restore is gated on `active`: if the opt-in was
	// already flipped off during runtime, we already restored those
	// fields in applyStep0TunablesWith; running the write again would
	// be a no-op but the map may also have been cleared on that path.
	if active {
		restoreHostScopeTunables(prior, realHostTunableFS{})
	}
	// Coalescence restore always runs when captures exist.
	for iface, s := range prior.mlx5Adaptive {
		restoreMlx5Coalesce(iface, s, realRSSExecutor{})
	}
}
