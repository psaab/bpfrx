package upgrade

import (
	"fmt"
	"time"
)

// RollingCluster is the cluster-control surface the rolling driver needs.
// It is satisfied by a CLI/gRPC-backed implementation in production
// (cluster_cli.go) and a fake in tests. Every method acts on the LOCAL
// node's running daemon unless noted.
type RollingCluster interface {
	// PeerAlive reports whether the cluster peer is alive and reachable.
	PeerAlive() (bool, error)
	// SyncEstablished reports whether session-sync is established/clean.
	SyncEstablished() (bool, error)
	// HAProtocolCompatible reports whether the local and peer HA/session-
	// sync protocol versions are mutually compatible (else the release is
	// not rolling-upgradable; the driver aborts to Path C image-replace).
	HAProtocolCompatible() (bool, error)
	// PeerTakeoverReady reports whether the PEER is ready to take over
	// (peer healthy, interface monitors green, not blocked by a hold) —
	// checked BEFORE demoting the local node so VIPs are never stranded.
	PeerTakeoverReady() (bool, error)
	// ForceSecondary demotes the local node (ISSU drain start).
	ForceSecondary() error
	// DrainComplete reports whether the STRONG drain predicate holds:
	// (a) peer owns the RGs (peer PRIMARY), (b) local VRRP is BACKUP with
	// no VIPs, (c) local rg_active is false, (d) sync clean.
	DrainComplete() (bool, error)
	// ResetFailover clears the manual failover and resumes normal election
	// (failback / let the upgraded node rejoin election).
	ResetFailover() error
	// LocalPrimary reports whether the local node currently owns the RGs
	// (used by the controlled-promotion forward-verify).
	LocalPrimary() (bool, error)
}

// RollingConfig tunes the rolling driver timing.
type RollingConfig struct {
	// DrainDeadline bounds the wait for the strong drain predicate.
	DrainDeadline time.Duration
	// RejoinDeadline bounds the wait for session-sync to re-establish
	// after the cut.
	RejoinDeadline time.Duration
	// PollInterval is the predicate poll cadence.
	PollInterval time.Duration
}

func (c *RollingConfig) withDefaults() {
	if c.DrainDeadline == 0 {
		c.DrainDeadline = 30 * time.Second
	}
	if c.RejoinDeadline == 0 {
		c.RejoinDeadline = 60 * time.Second
	}
	if c.PollInterval == 0 {
		c.PollInterval = 500 * time.Millisecond
	}
}

// RunRolling cuts over the LOCAL clustered node with a controlled drain so
// the cluster keeps forwarding (plan §6.2 B1). Run it on each node in turn
// (the external driver / cluster-setup.sh sequences both); each invocation:
//
//  1. assert peer alive + sync established + HA proto compatible (else
//     ABORT — fall back to image-replace, never drop connections).
//  2. PEER-TAKEOVER-READY precheck BEFORE demoting (else VIP stranding).
//  3. ForceSecondary() to start the drain.
//  4. wait for the STRONG drain predicate (peer PRIMARY, local VRRP
//     BACKUP/no-VIPs, rg_active false, sync clean) — NOT merely weight-0.
//  5. single-node STOP->FLIP->START cut on the now-fully-drained node
//     (auto-rollback DISABLED: HA rollback is operator-driven).
//  6. wait for sync to re-establish.
//  7. ResetFailover() to rejoin normal election (the natural failback is
//     the controlled-promotion forward-verify — the upgraded node forwards
//     only once promoted; the external driver runs the iperf3 forward
//     check post-promotion via make test-failover, never while passive).
//
// If the drain predicate cannot be met within the deadline, ABORT WITHOUT
// cutting — the node is still forwarding, so no harm.
func RunRolling(r *Runner, cfg Config) error {
	cl := NewCLICluster(cfg.Unit)
	return runRollingWith(r, cl, RollingConfig{})
}

// runRollingWith is the testable core (cluster + timing injected).
func runRollingWith(r *Runner, cl RollingCluster, rc RollingConfig) error {
	rc.withDefaults()
	logf := r.logf

	// 1. Preconditions. Any failure aborts WITHOUT touching the dataplane.
	alive, err := cl.PeerAlive()
	if err != nil {
		return fmt.Errorf("rolling: check peer alive: %w", err)
	}
	if !alive {
		return fmt.Errorf("rolling: peer is not alive — refusing to drain the only " +
			"forwarding node; upgrade via image-replace or bring the peer up first")
	}
	synced, err := cl.SyncEstablished()
	if err != nil {
		return fmt.Errorf("rolling: check session sync: %w", err)
	}
	if !synced {
		return fmt.Errorf("rolling: session sync not established — draining now would " +
			"drop connections; aborting (resolve sync or use image-replace)")
	}
	compat, err := cl.HAProtocolCompatible()
	if err != nil {
		return fmt.Errorf("rolling: check HA protocol compatibility: %w", err)
	}
	if !compat {
		return fmt.Errorf("rolling: HA/session-sync protocol is NOT compatible across " +
			"the staged version — this release is not rolling-upgradable; use " +
			"image-replace (Path C) with documented connection loss")
	}

	// 2. Peer-takeover-ready precheck BEFORE demoting (else VIP stranding).
	ready, err := cl.PeerTakeoverReady()
	if err != nil {
		return fmt.Errorf("rolling: check peer takeover readiness: %w", err)
	}
	if !ready {
		return fmt.Errorf("rolling: peer is NOT takeover-ready (health / interface " +
			"monitors / hold) — demoting now would strand VIPs; aborting without " +
			"draining (local node still forwarding)")
	}

	// 3. Start the drain.
	logf("rolling: peer ready; forcing local secondary (drain start)")
	if err := cl.ForceSecondary(); err != nil {
		return fmt.Errorf("rolling: force secondary: %w", err)
	}

	// 4. Wait for the STRONG drain predicate. The local daemon is still up
	//    here, so a predicate error is NOT expected — fail fast (the abort
	//    direction below is safe: we have not cut yet, node still forwards).
	if err := waitPredicate(rc, false, cl.DrainComplete); err != nil {
		// Drain incomplete: the node may still be forwarding. Best-effort
		// failback so we don't leave it half-drained, then abort.
		logf("rolling: drain predicate not met within %s; resetting failover and aborting", rc.DrainDeadline)
		_ = cl.ResetFailover()
		return fmt.Errorf("rolling: strong drain predicate not satisfied within %s "+
			"(peer-primary / local-VRRP-backup / rg_active-false / sync-clean); "+
			"aborted WITHOUT cutting (node still forwarding): %w", rc.DrainDeadline, err)
	}
	logf("rolling: drain complete (peer owns RGs, local backup, rg_active=false, sync clean)")

	// 5. Single-node cut on the fully-drained node. Auto-rollback is
	//    DISABLED: HA rollback is operator-driven (plan §8 inv. 8).
	if err := r.Run(Options{SkipStartHealthRollback: true}); err != nil {
		return fmt.Errorf("rolling: single-node cut failed (HA rollback is "+
			"operator-driven — inspect the node): %w", err)
	}

	// 6. Wait for sync to re-establish on the upgraded node. The cut just
	//    restarted xpfd, so the local gRPC socket is unavailable for the
	//    first few seconds (connection refused) — that is the EXPECTED
	//    transient, not a failure. Tolerate predicate errors and keep
	//    polling until RejoinDeadline; only the deadline (with the last
	//    observed error) aborts. Without this, the first dial failure
	//    short-circuits the wait and the RejoinDeadline tolerance is never
	//    used (false-negative abort while the daemon is healthily starting).
	if err := waitPredicate(RollingConfig{
		DrainDeadline: rc.RejoinDeadline,
		PollInterval:  rc.PollInterval,
	}, true, cl.SyncEstablished); err != nil {
		return fmt.Errorf("rolling: upgraded node did not re-establish session sync "+
			"within %s — leaving it secondary; operator should verify before "+
			"failing back: %w", rc.RejoinDeadline, err)
	}
	logf("rolling: upgraded node re-synced")

	// 7. Rejoin election (failback). The forward-verify is the natural
	//    post-promotion check the external driver runs (controlled
	//    promotion, never while passive).
	if err := cl.ResetFailover(); err != nil {
		return fmt.Errorf("rolling: reset failover (rejoin election): %w", err)
	}
	logf("rolling: local node rejoined election; cut complete for this node")
	return nil
}

// waitPredicate polls pred until it returns true or the deadline elapses.
//
// When tolerateTransientErr is false, the first predicate error aborts
// immediately (fail-fast). When true, a predicate error is treated as
// "not ready yet" — the poll continues until the deadline, and the last
// observed error is surfaced if the deadline elapses without success.
// The tolerant mode is for waits where an error is the EXPECTED transient
// (e.g. polling a gRPC socket that is briefly unavailable while the daemon
// restarts after a cut); the deadline is the backstop that still bounds it.
func waitPredicate(rc RollingConfig, tolerateTransientErr bool, pred func() (bool, error)) error {
	rc.withDefaults()
	end := time.Now().Add(rc.DrainDeadline)
	var lastErr error
	for {
		ok, err := pred()
		switch {
		case err != nil && !tolerateTransientErr:
			return err
		case err != nil:
			lastErr = err // keep polling; treat as not-ready
		case ok:
			return nil
		default:
			// Clean poll, just not ready yet — drop any stale earlier
			// error so a timeout reports the most recent state, not a
			// transient that has since cleared.
			lastErr = nil
		}
		if time.Now().After(end) {
			if lastErr != nil {
				return fmt.Errorf("predicate not satisfied within %s (last error: %w)", rc.DrainDeadline, lastErr)
			}
			return fmt.Errorf("predicate not satisfied within %s", rc.DrainDeadline)
		}
		time.Sleep(rc.PollInterval)
	}
}
