package cluster

import (
	"sync"
	"testing"
	"time"
)

// #5084 — the reconnect RESET of the config-generation marks must be atomic with
// respect to every ADVANCE of them.
//
// Both marks are advanced by a non-atomic read-modify-write (load, compare,
// store) and cleared to 0 by resetRecvGen on a peer bulk re-prime, and those run
// on DIFFERENT goroutines: resetRecvGen is driven by the syncMsgBulkStart
// handler on a receive loop, the applied mark is advanced by the single
// configApplyLoop consumer, and the received mark is advanced by a receive loop
// (of which there are TWO — conn0 and conn1). Nothing ordered them, so a clear
// landing between an advance's load and its store was simply LOST.
//
// The harm is not a transient: the marks are monotone-max. A peer that
// OS-rebooted restarts its configGenCounter LOWER, which is the entire reason
// the reset exists. A pre-reboot generation surviving the reset means every one
// of the reconnected peer's CURRENT generations is refused as stale — on the
// applied mark the standby silently keeps running the pre-reboot config, and on
// the received mark the readiness comparison (PeerConfigGen > AppliedConfigGen)
// inverts and the node reports READY while running that wrong policy. Neither
// self-clears short of another accepted re-prime.
//
// What binds what:
//
//	TestConfigGenResetIsNotLostByAConcurrentAppliedAdvance
//	TestConfigGenResetIsNotLostByAConcurrentReceivedAdvance
//	    THE binders. They park an advance inside its own load/store window via
//	    configGenAdvanceBarrierFn, drive resetRecvGen into that window from
//	    another goroutine, and assert the clear survives. Reverting the mutex
//	    leaves the reset free to run inside the window, and the parked store then
//	    re-raises the mark it just cleared.
//	TestConfigGenAdvanceStaysMonotone
//	    Over-reach guard. GREEN with the mutex reverted by design: it pins the
//	    `gen > current` comparison, which the serialization has nothing to do
//	    with, so the two cells are disjoint.

// preRebootGen is a realistic pre-reboot magnitude (configGenCounter is seeded
// from CLOCK_MONOTONIC nanos, so ~30 minutes of uptime stamps ~1.8e12) and
// postRebootGen is what the same node stamps ~12 seconds after a reboot. The
// post value being far LOWER is the whole reason the reset exists.
const (
	resetRaceGenPreReboot  uint64 = 1_800_000_000_123
	resetRaceGenPostReboot uint64 = 12_000_000_456
)

// parkedAdvance drives one advance with its store parked inside the mark's
// load/store window, runs resetRecvGen from a second goroutine while it is
// parked, and returns once both have finished. reachedWindow reports whether the
// advance actually parked (a guard against the test silently becoming a no-op if
// the advance is skipped by its own comparison), and resetFinishedWhileParked
// reports whether the reset completed BEFORE the advance was released — which is
// the observable difference between the serialized and unserialized code.
func parkedAdvance(t *testing.T, s *SessionSync, advance func()) (reachedWindow, resetFinishedWhileParked bool) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s.configGenAdvanceBarrierFn = func() {
		once.Do(func() { close(entered) })
		<-release
	}
	defer func() { s.configGenAdvanceBarrierFn = nil }()

	advanceDone := make(chan struct{})
	go func() {
		defer close(advanceDone)
		advance()
	}()

	select {
	case <-entered:
		reachedWindow = true
	case <-time.After(5 * time.Second):
		close(release)
		<-advanceDone
		return false, false
	}

	// The reconnecting peer's bulk re-prime, driven from another goroutine
	// exactly as the syncMsgBulkStart handler drives it from a receive loop.
	resetDone := make(chan struct{})
	go func() {
		defer close(resetDone)
		s.resetRecvGen()
	}()

	// Give the reset a real chance to run. Serialized, it blocks on configGenMu
	// and this observation is false; unserialized, it completes here.
	select {
	case <-resetDone:
		resetFinishedWhileParked = true
	case <-time.After(250 * time.Millisecond):
	}

	close(release)
	<-advanceDone
	select {
	case <-resetDone:
	case <-time.After(5 * time.Second):
		t.Fatal("resetRecvGen never completed after the parked advance was released")
	}
	return reachedWindow, resetFinishedWhileParked
}

// TestConfigGenResetIsNotLostByAConcurrentAppliedAdvance binds the APPLIED mark.
//
// Harm first: with the clear lost, the standby's high-water stays at the peer's
// PRE-REBOOT generation, so the reconnected peer's current (lower) config is
// refused as stale by shouldApplyConfigGen and the standby silently keeps
// running the pre-reboot configuration.
func TestConfigGenResetIsNotLostByAConcurrentAppliedAdvance(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)

	reached, resetRanInsideWindow := parkedAdvance(t, s, func() {
		s.recordAppliedConfigGen(resetRaceGenPreReboot)
	})
	if !reached {
		t.Fatal("fixture broken: the advance never entered its load/store window, so nothing was parked and this test proves nothing")
	}

	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("the reconnect reset was LOST: the applied config high-water is %d (the peer's PRE-REBOOT generation) instead of 0. "+
			"reset_completed_inside_the_advance_window=%v. The standby now refuses every generation the reconnected peer can produce "+
			"(it restarts its counter LOWER, e.g. %d) and silently keeps running the pre-reboot config",
			got, resetRanInsideWindow, resetRaceGenPostReboot)
	}

	// The whole point of the reset: the reconnected peer's LOWER current
	// generation must now be admitted.
	if !s.shouldApplyConfigGen(resetRaceGenPostReboot) {
		t.Fatalf("the reconnected peer's current generation %d must be admitted after the reset; high-water is %d",
			resetRaceGenPostReboot, s.lastAppliedConfigGen.Load())
	}
}

// TestConfigGenResetIsNotLostByAConcurrentReceivedAdvance binds the RECEIVED
// mark, which has a second receive loop as its racing writer rather than the
// apply loop, and a different harm.
//
// Harm first: TransferReadiness compares PeerConfigGen (this mark) against
// AppliedConfigGen. With the clear lost, PeerConfigGen stays pinned at the
// pre-reboot generation while the applied mark is correctly 0, so the node reads
// as config-stale forever; and once a post-reboot config does apply, the
// comparison is against a generation the peer can never reach again.
func TestConfigGenResetIsNotLostByAConcurrentReceivedAdvance(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)

	reached, resetRanInsideWindow := parkedAdvance(t, s, func() {
		s.recordRecvConfigGen(resetRaceGenPreReboot)
	})
	if !reached {
		t.Fatal("fixture broken: the advance never entered its load/store window, so nothing was parked and this test proves nothing")
	}

	if got := s.lastRecvConfigGen.Load(); got != 0 {
		t.Fatalf("the reconnect reset was LOST: the received config high-water is %d (the peer's PRE-REBOOT generation) instead of 0. "+
			"reset_completed_inside_the_advance_window=%v. The manual-failover readiness gate compares this against the applied mark, "+
			"so it is now pinned above every generation the reconnected peer can produce (e.g. %d)",
			got, resetRanInsideWindow, resetRaceGenPostReboot)
	}
}

// --- over-reach guard: GREEN with the serialization reverted ----------------

// The advance is a monotone MAX, and that is a separate property from being
// serialized against the reset. Pinning it here keeps the mutex from being
// mistaken for the thing that makes the mark monotone: replacing
// `gen > current` with a bare Store reds this and leaves both binders above
// green, so the two cells are disjoint rather than one restating the other.
func TestConfigGenAdvanceStaysMonotone(t *testing.T) {
	t.Run("applied mark", func(t *testing.T) {
		s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		s.recordAppliedConfigGen(resetRaceGenPreReboot)
		if got := s.lastAppliedConfigGen.Load(); got != resetRaceGenPreReboot {
			t.Fatalf("fixture broken: the first advance must take, got %d want %d", got, resetRaceGenPreReboot)
		}
		// A reordered older frame, or a delayed publish from a prior
		// incarnation. It must not pull the mark down.
		s.recordAppliedConfigGen(resetRaceGenPostReboot)
		if got := s.lastAppliedConfigGen.Load(); got != resetRaceGenPreReboot {
			t.Fatalf("the applied high-water must never regress: publishing %d after %d pulled it down to %d",
				resetRaceGenPostReboot, resetRaceGenPreReboot, got)
		}
		// Negative control: a genuinely HIGHER generation must still advance it,
		// so the assertion above pins regression rather than pinning "never
		// moves".
		s.recordAppliedConfigGen(resetRaceGenPreReboot + 1)
		if got := s.lastAppliedConfigGen.Load(); got != resetRaceGenPreReboot+1 {
			t.Fatalf("a strictly higher generation must still advance the applied high-water; got %d want %d",
				got, resetRaceGenPreReboot+1)
		}
	})

	t.Run("received mark", func(t *testing.T) {
		s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		s.recordRecvConfigGen(resetRaceGenPreReboot)
		if got := s.lastRecvConfigGen.Load(); got != resetRaceGenPreReboot {
			t.Fatalf("fixture broken: the first advance must take, got %d want %d", got, resetRaceGenPreReboot)
		}
		s.recordRecvConfigGen(resetRaceGenPostReboot)
		if got := s.lastRecvConfigGen.Load(); got != resetRaceGenPreReboot {
			t.Fatalf("the received high-water must never regress: recording %d after %d pulled it down to %d",
				resetRaceGenPostReboot, resetRaceGenPreReboot, got)
		}
		s.recordRecvConfigGen(resetRaceGenPreReboot + 1)
		if got := s.lastRecvConfigGen.Load(); got != resetRaceGenPreReboot+1 {
			t.Fatalf("a strictly higher generation must still advance the received high-water; got %d want %d",
				got, resetRaceGenPreReboot+1)
		}
	})
}
