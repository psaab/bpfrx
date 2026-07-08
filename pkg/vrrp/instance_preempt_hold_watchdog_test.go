package vrrp

import (
	"testing"
	"time"
)

// Tests for the #4584 preempt hold-time LIVENESS WATCHDOG. When a higher-
// priority node defers preemption of a live lower-priority master
// (`preempt hold-time <N>`), armPreemptHold re-arms masterDownTimer as a
// watchdog so a held (VIP-owning) master that DIES mid-hold is taken over
// within one master-down horizon instead of blackholing until the (possibly
// very long) hold-time elapses. A still-live held master keeps deferring to the
// natural hold expiry — the preempt-hold intent is preserved.
//
// Before #4584 the masterDownTimer sat IDLE for the whole hold (it fired to arm
// the hold and handleBackupRx never reset it for a persisting lower advert), so
// a held master's silence went undetected until the hold-time elapsed.
//
// These drive stepBackup() directly (see instance_preempt_holdtime_test.go for
// why run() is unsafe in a unit test).

// armHoldKeepMasterDown arms the preempt hold by firing masterDownTimer with a
// live lower-priority master present, and RETURNS the masterDownTimer so the
// caller can fire it again as the #4584 watchdog. It asserts the instance
// stayed BACKUP with the hold armed. The masterDownTimer re-arm (the direct
// fail-on-revert signal) is asserted by the individual tests.
func armHoldKeepMasterDown(t *testing.T, vi *vrrpInstance) (masterDown, advert, preemptHold *time.Timer) {
	t.Helper()
	masterDown = time.NewTimer(0)
	t.Cleanup(func() { masterDown.Stop() })
	time.Sleep(2 * time.Millisecond) // let masterDown fire
	advert = time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	preemptHold = time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })

	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP (hold armed)", vi.getState())
	}
	vi.mu.RLock()
	armed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if !armed {
		t.Fatalf("preemptHoldArmed = false, want true after arming the hold")
	}
	return masterDown, advert, preemptHold
}

// TestHoldWatchdog_DeadHeldMaster_ImmediateTakeover is the PRIMARY #4584
// fail-on-revert guard. A priority-200 node arms a 300 s preempt hold against a
// live priority-100 master, then that held (VIP-owning) master DIES mid-hold
// (adverts stop, lastMasterSeen goes stale). The re-armed masterDownTimer
// watchdog must fire and promote NOW — not wait the full 300 s hold. On revert
// the masterDownTimer is left idle after the hold arms, so nothing detects the
// silence until the hold expires.
func TestHoldWatchdog_DeadHeldMaster_ImmediateTakeover(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 300) // 300 s hold
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := armHoldKeepMasterDown(t, vi)

	// #4584 RED-on-revert: armPreemptHold must have re-armed masterDownTimer as
	// the liveness watchdog. On revert it is left idle (fired and never reset)
	// → Stop() returns false.
	if !masterDown.Stop() {
		t.Fatal("masterDownTimer not re-armed as liveness watchdog after preempt hold armed (#4584 reverted?)")
	}

	// The held master DIES: no more adverts, lastMasterSeen goes stale.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now().Add(-time.Hour)
	vi.mu.Unlock()

	// Fire the watchdog (masterDownTimer) while the hold is still armed and the
	// preemptHold timer is far in the future (300 s). Only the watchdog can
	// promote us here — the hold has NOT elapsed.
	masterDown.Reset(0)
	time.Sleep(2 * time.Millisecond)
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateMaster {
		t.Fatalf("state = %s, want MASTER (dead held master → watchdog immediate takeover)", vi.getState())
	}
	vi.mu.RLock()
	stillArmed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if stillArmed {
		t.Error("preemptHoldArmed = true after watchdog takeover; the hold must be disarmed")
	}
}

// TestHoldWatchdog_LiveHeldMaster_DefersToNaturalExpiry proves the preempt-hold
// intent is preserved: while the held master KEEPS sending adverts
// (lastMasterSeen stays fresh), a watchdog fire must NOT preempt it — the
// instance stays BACKUP, the hold stays armed, and the watchdog re-arms itself.
// The hold then runs to its NATURAL expiry, which promotes. On revert the
// masterDown fire re-arms the HOLD (resetting preemptHold) and leaves masterDown
// idle, so the re-arm assertion fails.
func TestHoldWatchdog_LiveHeldMaster_DefersToNaturalExpiry(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 300) // long hold
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := armHoldKeepMasterDown(t, vi)

	// The held master is STILL ALIVE — adverts keep refreshing lastMasterSeen.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	stopAndDrainTimer(masterDown)
	masterDown.Reset(0)
	time.Sleep(2 * time.Millisecond)
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP (live held master must not be preempted by the watchdog)", vi.getState())
	}
	vi.mu.RLock()
	armed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if !armed {
		t.Fatal("preemptHoldArmed = false; the hold must continue while the held master is alive")
	}
	// #4584 RED-on-revert: the watchdog must have re-armed masterDown to keep
	// watching. On revert the masterDown fire re-arms the HOLD instead and
	// leaves masterDown idle → Stop() returns false.
	if !masterDown.Stop() {
		t.Fatal("masterDownTimer not re-armed as watchdog after a live-master fire (#4584 reverted?)")
	}

	// The hold runs to its NATURAL expiry: firing preemptHold now (live lower
	// master still fresh) promotes — proving the live master was deferred to
	// hold-time, not preempted early by the watchdog.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	stopAndDrainTimer(preemptHold)
	preemptHold.Reset(0)
	time.Sleep(2 * time.Millisecond)
	masterDownLong := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDownLong.Stop() })
	vi.stepBackup(masterDownLong, advert, preemptHold)
	if vi.getState() != StateMaster {
		t.Fatalf("state = %s, want MASTER (natural hold expiry → takeover)", vi.getState())
	}
}

// TestHoldWatchdog_NoHoldArmed_NormalFailoverUnchanged confirms the watchdog
// branch is skipped when no hold is armed: a masterDownTimer fire with no
// hold-time configured promotes immediately (normal failover), exactly as
// before #4584. Guards against routing a normal failover through the watchdog.
func TestHoldWatchdog_NoHoldArmed_NormalFailoverUnchanged(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 0) // no hold-time
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	vi.mu.RLock()
	preArmed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if preArmed {
		t.Fatal("preemptHoldArmed = true before any hold armed")
	}

	masterDown := time.NewTimer(0)
	t.Cleanup(func() { masterDown.Stop() })
	time.Sleep(2 * time.Millisecond)
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	preemptHold := time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })

	vi.stepBackup(masterDown, advert, preemptHold)
	if vi.getState() != StateMaster {
		t.Fatalf("state = %s, want MASTER (no hold-time → normal immediate failover)", vi.getState())
	}
}

// TestHeldMasterIsStale exercises the #4584 watchdog predicate directly: a
// fresh advert reads as live (not stale); a zero or beyond-horizon
// lastMasterSeen reads as stale (silent/dead held master).
func TestHeldMasterIsStale(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 300)

	// Fresh advert → live, not stale.
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if vi.heldMasterIsStale() {
		t.Error("heldMasterIsStale() = true for a fresh advert, want false (live master)")
	}

	// Beyond the master-down horizon → stale.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now().Add(-time.Hour)
	vi.mu.Unlock()
	if !vi.heldMasterIsStale() {
		t.Error("heldMasterIsStale() = false for a beyond-horizon advert, want true (silent master)")
	}

	// Never observed → stale.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Time{}
	vi.mu.Unlock()
	if !vi.heldMasterIsStale() {
		t.Error("heldMasterIsStale() = false with no advert ever seen, want true")
	}
}
