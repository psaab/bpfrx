// Daemon-side wiring for #801 Phase-B Step-0 host tunables.
//
// This file owns the state machine for the B1 opt-in gate and the B2
// restore-on-disable path. The pure capture/restore logic lives in
// host_tunables.go — here we route calls through the Daemon struct's
// priorTunables field so the same snapshot survives startup → commit →
// disable → shutdown.
//
// Transition matrix (opt_in = claim-host-tunables):
//
//	prior      new        action
//	-------    -------    ----------------------------------------------
//	false      false      no-op (never claimed)
//	false      true       capture + write
//	true       true       capture-if-not-already + write (reconcile)
//	true       false      restore (B2), discard snapshot
//	(shutdown) *          restore (if active) on daemon Stop
//
// Per-iface coalescence rx-usecs/tx-usecs is always applied when
// coalescence is configured — those stay bound to the mlx5 interface
// allowlist and do not require opt-in. Only the host-scope flip
// (adaptive on/off) is treated as a "host-scope" claim that requires
// opt-in, because disabling adaptive across all mlx5 ports affects
// latency-sensitive neighbours outside xpfd's zone model.
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
func (d *Daemon) applyStep0TunablesWith(userspaceDP, claimHostTunables bool,
	governor string, netdevBudget int,
	coalesceExplicit, coalesceEnable bool, coalesceRX, coalesceTX int,
	rssAllowed []string,
	fs hostTunableFS, execer rssExecutor) {

	d.priorTunablesMu.Lock()
	prior := d.priorTunables
	active := d.priorTunablesActive
	d.priorTunablesMu.Unlock()

	// Restore path: previously active, now disabled (or non-userspace).
	// Must run BEFORE we possibly create a new priorTunables so two
	// back-to-back apply calls with flipped opt-in don't lose state.
	if active && (!userspaceDP || !claimHostTunables) {
		slog.Info("linksetup: claim-host-tunables disabled, restoring pre-xpfd values")
		restoreHostTunables(prior, fs, execer)
		d.priorTunablesMu.Lock()
		d.priorTunables = nil
		d.priorTunablesActive = false
		d.priorTunablesMu.Unlock()
		// Per-iface rx-usecs/tx-usecs coalescence: this is part of
		// the D3-scoped per-iface allowlist. When claim-host-tunables
		// is OFF, we no longer touch any coalescence state at all
		// (including rx-usecs), because setting rx-usecs without
		// touching adaptive would still surface as an unexpected
		// write to an mlx5 parameter the operator did not authorize.
		// Interface-scoped is still host-visible: restore covered
		// both flip + per-iface above.
		return
	}
	// No-op path: never claimed, nothing to do.
	if !userspaceDP || !claimHostTunables {
		slog.Debug("linksetup: step0 host tunables skip (claim-host-tunables not set)",
			"userspace_dp", userspaceDP, "claim", claimHostTunables)
		return
	}

	// Claim path: snapshot + write. Allocate a snapshot if this is the
	// first claimed apply; existing snapshots are reused so
	// first-apply values survive every reconcile.
	if !active {
		prior = newPriorHostTunables()
	}
	gov, budget := resolvedHostTunables(governor, netdevBudget, true)
	applyHostTunables(gov, budget, fs, prior)
	applyCoalescence(coalesceEnable, coalesceRX, coalesceTX, rssAllowed, execer, prior)

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
// Best-effort: never returns an error. Safe to call when no tunable
// was ever captured (no-op).
func (d *Daemon) restoreStep0TunablesOnShutdown() {
	d.priorTunablesMu.Lock()
	prior := d.priorTunables
	active := d.priorTunablesActive
	d.priorTunables = nil
	d.priorTunablesActive = false
	d.priorTunablesMu.Unlock()

	if !active || prior == nil {
		slog.Debug("shutdown: host tunables restore skip (never claimed)")
		return
	}
	slog.Info("shutdown: restoring host tunables to pre-xpfd values")
	restoreHostTunables(prior, realHostTunableFS{}, realRSSExecutor{})
}
