package upgrade

import (
	"fmt"
	"time"
)

// Non-interactive drain/rejoin for the external LANE-1 HA kernel roll
// (#1930 INC-2). These reuse the RollingCluster surface (#1917) so the kernel
// roll drives the SAME proven automation path as the binary rolling cut — and,
// critically, CONFIRM the strong predicates (r1 Codex Critical: the external
// driver must never arm+reboot an undrained primary, nor advance to the peer
// before this node is fully rejoined).

// drainPollInterval is how often the predicates are re-checked while waiting.
const drainPollInterval = 1 * time.Second

// DrainAndConfirm demotes the local node and waits for the STRONG drain
// predicate (peer owns the RGs + sync clean) within deadline. It first refuses
// to drain if the peer is not takeover-ready or the HA protocol is incompatible
// — so a drain can never strand VIPs or split a mixed-protocol cluster.
func DrainAndConfirm(cl RollingCluster, deadline time.Duration) error {
	// Pre-checks: a peer that cannot take over must NOT be drained to.
	alive, err := cl.PeerAlive()
	if err != nil {
		return fmt.Errorf("peer-alive check: %w", err)
	}
	if !alive {
		return fmt.Errorf("peer is not alive — refusing to drain (no node to take over)")
	}
	compat, err := cl.HAProtocolCompatible()
	if err != nil {
		return fmt.Errorf("HA-protocol check: %w", err)
	}
	if !compat {
		return fmt.Errorf("HA/session-sync protocol incompatible with peer — " +
			"this kernel roll is not safe; use image-replace (LANE 2)")
	}
	ready, err := cl.PeerTakeoverReady()
	if err != nil {
		return fmt.Errorf("peer-takeover-ready check: %w", err)
	}
	if !ready {
		return fmt.Errorf("peer is not takeover-ready — refusing to drain (would strand VIPs)")
	}

	if err := cl.ForceSecondary(); err != nil {
		return fmt.Errorf("force secondary: %w", err)
	}

	// Wait for the STRONG drain predicate. If it does not hold within the
	// deadline, the caller must NOT proceed AND we must NOT leave the node
	// force-demoted with the peer not having taken over — that would strand the
	// VIPs (r2 Codex). FAIL BACK (ResetFailover) before returning the error, so
	// this node resumes serving rather than sitting demoted with no primary.
	dl := time.Now().Add(deadline)
	for {
		ok, derr := cl.DrainComplete()
		if derr == nil && ok {
			return nil
		}
		// Bound the next sleep to the remaining time so we do not overshoot the
		// deadline by up to a full poll interval (Copilot): small deadlines (incl.
		// tests) must not silently turn into deadline+interval.
		if time.Now().After(dl) {
			if rbErr := cl.ResetFailover(); rbErr != nil {
				return fmt.Errorf("drain did not complete within %s AND failback "+
					"failed (%v) — node may be stranded demoted; operator attention needed "+
					"(drain error: %v)", deadline, rbErr, derr)
			}
			if derr != nil {
				return fmt.Errorf("drain did not complete within %s (failed back; last error: %w)", deadline, derr)
			}
			return fmt.Errorf("drain did not complete within %s (peer did not take over / sync not clean; failed back)", deadline)
		}
		sleepBounded(dl)
	}
}

// sleepBounded sleeps for drainPollInterval, but never past dl — so a poll loop
// re-checks (and reports timeout) at the deadline rather than overshooting it by
// up to a full interval.
func sleepBounded(dl time.Time) {
	rem := time.Until(dl)
	if rem <= 0 {
		return
	}
	if rem < drainPollInterval {
		time.Sleep(rem)
		return
	}
	time.Sleep(drainPollInterval)
}

// RejoinAndConfirm clears manual failover on the local node and confirms it is
// back as an eligible cluster member with sync re-established within deadline.
// The orchestrator calls this AFTER a node has booted+promoted the candidate,
// and must see it succeed BEFORE it touches the peer (the "never both down"
// gate): a node that cannot rejoin/sync leaves the roll stopped with the peer
// still primary.
func RejoinAndConfirm(cl RollingCluster, deadline time.Duration) error {
	if err := cl.ResetFailover(); err != nil {
		return fmt.Errorf("reset failover: %w", err)
	}
	// Confirm the peer is still a healthy member and sync is re-established —
	// i.e. the cluster is whole again — before declaring the rejoin done.
	dl := time.Now().Add(deadline)
	for {
		alive, aerr := cl.PeerAlive()
		synced, serr := cl.SyncEstablished()
		if aerr == nil && serr == nil && alive && synced {
			return nil
		}
		if time.Now().After(dl) {
			return fmt.Errorf("rejoin not confirmed within %s "+
				"(peer-alive=%v sync-established=%v)", deadline, alive, synced)
		}
		sleepBounded(dl)
	}
}
