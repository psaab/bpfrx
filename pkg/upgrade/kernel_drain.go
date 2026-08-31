package upgrade

import (
	"fmt"
	"strings"
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
// to drain if the peer is not alive or not takeover-ready — so a drain can never
// strand VIPs. Unless allowMixedHA is set, it ALSO refuses an HA-incompatible
// peer (exact-equality), so a single-version LANE-1 roll never splits a
// mixed-protocol cluster. allowMixedHA=true (the LANE-2 image-roll second drain,
// whose mixed-base gate already validated window-compat) intentionally BYPASSES
// only that exact-equality HA check; the peer-alive and takeover-ready prechecks
// still apply (Copilot).
func DrainAndConfirm(cl RollingCluster, deadline time.Duration, allowMixedHA bool) error {
	// Pre-checks: a peer that cannot take over must NOT be drained to.
	alive, err := cl.PeerAlive()
	if err != nil {
		return fmt.Errorf("peer-alive check: %w", err)
	}
	if !alive {
		return fmt.Errorf("peer is not alive — refusing to drain (no node to take over)")
	}
	// HAProtocolCompatible is EXACT-equality (local==peer). For the LANE-1
	// kernel roll the cluster is single-version, so equality is correct. For the
	// LANE-2 image-roll the mixed-base gate has ALREADY validated window-compat
	// (peer in [min-compat, version]), and the SECOND node's drain runs against
	// an already-rolled peer that may legitimately differ within that window —
	// exact-equality would wrongly abort it (r3 Codex HIGH). The orchestrator
	// passes allowMixedHA to relax this one check in that vetted case only.
	if !allowMixedHA {
		compat, err := cl.HAProtocolCompatible()
		if err != nil {
			return fmt.Errorf("HA-protocol check: %w", err)
		}
		if !compat {
			// #7990: this message used to say "HA/session-sync protocol
			// incompatible" while the check looked only at the HA protocol
			// version — a claim the code did not support, and since #7925 the
			// two are separate counters. Name only what was checked.
			return fmt.Errorf("HA protocol incompatible with peer — " +
				"this kernel roll is not safe; use image-replace (LANE 2)")
		}
	}
	// #7990: the session-sync WIRE version is a SEPARATE gate from the HA
	// protocol one, and until now the in-place path had neither the channel nor
	// the check. A drain hands the RGs to the peer; if the peer cannot decode
	// this node's session frames, that handover drops every established flow
	// while heartbeat, election and failover all keep working — so the cluster
	// looks healthy and the loss is only discovered at the failover.
	//
	// NOT gated behind allowMixedHA. That flag exists because the LANE-2
	// mixed-base gate already validated the HA WINDOW and exact-equality would
	// wrongly abort the second node; it says nothing about the session wire,
	// which GateMixedBaseSwap checks for EXACT equality in both cases. Reusing
	// it here would silently disable this gate on exactly the path that most
	// needs it.
	syncOK, syncWhy, err := cl.SessionSyncWireCompatible()
	if err != nil {
		return fmt.Errorf("session-sync wire check: %w", err)
	}
	if !syncOK {
		return fmt.Errorf("session-sync wire incompatible with peer (%s) — draining would "+
			"hand over to a node that cannot receive this node's sessions; use "+
			"image-replace (LANE 2), which gates on this version explicitly", syncWhy)
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
		sleepBounded(dl, drainPollInterval)
	}
}

// sleepBounded sleeps for `interval`, but never past dl — so a poll loop
// re-checks (and reports timeout) at the deadline rather than overshooting it by
// up to a full interval.
//
// #7424: `interval` was `drainPollInterval` until rolling.go's waitPredicate
// became the third caller. That loop polls on the caller-supplied
// RollingConfig.PollInterval, so the interval is a parameter rather than a
// package constant; the two kernel-drain callers pass drainPollInterval and are
// unchanged in behaviour.
func sleepBounded(dl time.Time, interval time.Duration) {
	rem := time.Until(dl)
	if rem <= 0 {
		return
	}
	if rem < interval {
		time.Sleep(rem)
		return
	}
	time.Sleep(interval)
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
	// Confirm the peer is still a healthy member, sync is re-established, AND
	// this node has actually resumed eligibility for EVERY configured RG —
	// i.e. the cluster is whole again — before declaring the rejoin done.
	// PeerAlive + SyncEstablished are GLOBAL predicates: they hold even if some
	// configured RG (e.g. RG>=3 the pre-#5044 {0,1,2} guess dropped) is still
	// held in the ForceSecondary drain. Without the per-RG gate the orchestrator
	// would confirm rejoin and advance to drain the PEER while that RG has no
	// primary on either node — a per-RG blackhole (#5138). LocalRejoinComplete
	// fails closed on an enumeration error or a still-demoted RG, so the roll
	// stops here instead.
	dl := time.Now().Add(deadline)
	// Retain the last non-nil transport/gRPC error from each predicate so a
	// deadline miss reports WHY the rejoin never confirmed, not just the
	// alive/synced booleans (gemini-review-041 Low-2, #4717). Without this an
	// operator sees only "peer-alive=false sync-established=false" and must dig
	// through syslog to learn it was e.g. a refused gRPC dial while xpfd was
	// still restarting. Mirrors DrainAndConfirm's timeout, which already wraps
	// the last DrainComplete error.
	var lastAErr, lastSErr, lastRErr error
	for {
		alive, aerr := cl.PeerAlive()
		synced, serr := cl.SyncEstablished()
		rejoined, rerr := cl.LocalRejoinComplete()
		if aerr == nil && serr == nil && rerr == nil && alive && synced && rejoined {
			return nil
		}
		if aerr != nil {
			lastAErr = aerr
		}
		if serr != nil {
			lastSErr = serr
		}
		if rerr != nil {
			lastRErr = rerr
		}
		if time.Now().After(dl) {
			base := fmt.Errorf("rejoin not confirmed within %s "+
				"(peer-alive=%v sync-established=%v local-rejoined=%v)", deadline, alive, synced, rejoined)
			var details []string
			if lastAErr != nil {
				details = append(details, fmt.Sprintf("last peer-alive error: %v", lastAErr))
			}
			if lastSErr != nil {
				details = append(details, fmt.Sprintf("last sync-established error: %v", lastSErr))
			}
			if lastRErr != nil {
				details = append(details, fmt.Sprintf("last local-rejoin error: %v", lastRErr))
			}
			if len(details) > 0 {
				return fmt.Errorf("%w; %s", base, strings.Join(details, "; "))
			}
			return base
		}
		sleepBounded(dl, drainPollInterval)
	}
}
