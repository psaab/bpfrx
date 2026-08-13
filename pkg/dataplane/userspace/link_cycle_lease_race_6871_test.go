package userspace

import (
	"sync/atomic"
	"testing"
	"time"
)

// #6871 (round 8): linkCycleInFlight must not report "no cycle" on a LOST CAS.
//
// THE RACE. The expiry path reads the lease word, decides it is expired, and
// CASes it to the 0 sentinel. Two other writers touch that same word:
// RenewLinkCycle's CAS (which pushes a live lease further out) and
// acquireLinkCycleLease's Store (which opens a brand-new one). Either can land
// between the reader's Load and the reader's CAS. When it does, the reader's CAS
// FAILS — the word no longer holds the value it read — and the pre-round-8 code
// returned false anyway:
//
//	until := m.linkCycleLeaseUntil.Load()
//	if int64(linkCycleLeaseElapsed()) >= until {
//	    if m.linkCycleLeaseUntil.CompareAndSwap(until, 0) { warn }
//	    return false                      // <- unconditional, CAS result ignored
//	}
//
// A failed CAS means the word moved, and the value it moved TO is the one that
// decides the answer. Ignoring it turns "somebody else just extended or re-took
// this lease" into "there is no lease", which is the guard this whole PR exists
// to provide, defeated by the renewal mechanism round 6 added to strengthen it.
// The reader then reconciles: the 1 Hz tick respawns AF_XDP workers, re-enables
// ctrl, or republishes bindings into a NIC whose queues the live cycle is about
// to destroy (#5103's use-after-unmap).
//
// WHY THE INJECTION POINT IS FAITHFUL, not merely convenient. linkCycleInFlight
// reads the word, then calls linkCycleLeaseElapsed(), then CASes what it read.
// The clock seam therefore sits EXACTLY in the Load->CAS window, so code run
// from inside it interleaves precisely where a competing goroutine does on a
// real box. That makes the repro deterministic instead of a timing lottery: no
// sleeps, no goroutines, no scheduler dependence.

// injectAtLeaseExpiryCheck installs a linkCycleLeaseElapsed seam that runs
// inject EXACTLY ONCE — on the first read — and then reports elapsed forever.
//
// One-shot on purpose: the injected writer computes its own deadline through
// linkCycleLeaseDeadline(), which reads the same seam, and a re-entrant hook
// would recurse. Not sync.Once for the same reason — Once deadlocks when Do is
// re-entered from inside its own function. CompareAndSwap gives the same
// one-shot without that: it commits the flag BEFORE inject runs, so a
// re-entrant read sees it set.
//
// ATOMIC, not a plain bool (#6871 round 11), because this closure is read from
// more than one goroutine. Round 10 made linkCycleLeaseElapsedOverride an
// atomic.Pointer, which makes the SWAP race-free; it does not make the closure
// the pointer points AT goroutine-safe. A test that takes a real lease and does
// not release it leaves a heartbeat beating on a dead Manager, and that
// goroutine's RenewLinkCycle -> linkCycleInFlight -> linkCycleLeaseElapsed path
// CALLS whatever override is installed at that instant — including this one,
// installed by a later test. fakeLinkCycleClock's counter is an atomic.Int64
// for exactly this reason; this flag was the one capture that had not been
// given the same treatment, and `go test -race` reported a genuine
// WARNING: DATA RACE on it (read here, previous write from
// startLinkCycleHeartbeat.func1) once the heartbeat period is shortened enough
// to widen the collision window.
//
// WHAT THE ATOMIC FIXES AND WHAT IT DOES NOT, measured rather than reasoned,
// because the sentence this replaces is the one round 10 overstated. With the
// beat accelerated 15s -> 200us, so that a collision is frequent enough to
// observe at all:
//
//   - the DATA RACE goes away: 1 report before, 0 after, -race -count=5;
//   - the DOUBLE injection goes away by construction — CompareAndSwap admits
//     exactly one injector, where two racing plain-bool readers could both see
//     it unset. Before the fix a 200-run functional loop ended in
//     `panic: Fail in goroutine after ... has completed`, the second injector
//     calling t.Fatal from the heartbeat goroutine and taking the whole test
//     binary down; that was not observed once in 200 runs after;
//   - a leaked beat is NOT thereby made harmless. It can still WIN the one-shot
//     and inject on its own goroutine, and then the discriminator's own read
//     finds the lease word it expected to move unmoved, and reds at "reported
//     NO cycle in flight". That still happens after the fix, ~10 times in 200
//     accelerated runs.
//
// So the direction is what holds: a stolen injection reds a cell, it never
// greens one — the assertions all demand the lease be JUDGED LIVE, and the
// steal can only make the reader see an expiry. A flake, never a false green.
// At the production 15s period the window is microseconds and none of this has
// been observed. Releasing the lease is what keeps a fixture stable; the atomic
// is what keeps it defined.
func injectAtLeaseExpiryCheck(t *testing.T, elapsed time.Duration, inject func()) {
	t.Helper()
	var fired atomic.Bool
	swapLinkCycleLeaseElapsed(t, func() time.Duration {
		if fired.CompareAndSwap(false, true) {
			inject()
		}
		return elapsed
	})
}

// TestLinkCycleInFlightHonoursALostExpiryCAS_6871 is the B1 discriminator.
//
// RED-on-revert: replace the loop in Manager.linkCycleInFlight with the
// straight-line form quoted above — CAS, ignore the result, `return false` —
// and BOTH subtests fail at "reported NO cycle in flight".
func TestLinkCycleInFlightHonoursALostExpiryCAS_6871(t *testing.T) {
	// The lease under test was taken at elapsed=0, so its deadline is exactly
	// one TTL; the reader arrives one second past it and takes the expiry
	// branch. Anything the injected writer stores must therefore be strictly
	// greater than `expired` to count as live.
	const staleDeadline = int64(linkCycleLeaseTTL)
	expired := linkCycleLeaseTTL + time.Second

	t.Run("renewal_wins_the_cas", func(t *testing.T) {
		m := New()
		t.Cleanup(m.releaseLinkCycleLease)
		m.linkCycleLeaseUntil.Store(staleDeadline)

		injectAtLeaseExpiryCheck(t, expired, func() {
			// This is literally the CAS Manager.RenewLinkCycle executes: it
			// passed its own linkCycleInFlight check while the lease was still
			// live, computed a fresh deadline, and its CAS lands here — before
			// the reader's. Its window is arbitrarily small, because a renewal
			// racing the expiry INSTANT is exactly what renewal is for.
			if !m.linkCycleLeaseUntil.CompareAndSwap(staleDeadline,
				int64(expired+linkCycleLeaseTTL)) {
				t.Fatal("fixture: the emulated renewal did not win the CAS")
			}
		})

		if !m.linkCycleInFlight() {
			t.Fatalf("reported NO cycle in flight after losing the expiry CAS to a "+
				"concurrent renewal that had just extended the lease to %d. The reader "+
				"must re-read and judge the NEW value, not report the stale expiry it "+
				"failed to commit: the daemon renews once per RETH member and twice more "+
				"in the tail, so a renewal landing on the expiry instant is the designed "+
				"behaviour — and it currently unlatches the guard for the rest of the "+
				"cycle, letting the 1 Hz tick respawn workers into a NIC that is about to "+
				"unmap their UMEM (#6871 round 8 B1)",
				m.linkCycleLeaseUntil.Load())
		}
	})

	t.Run("fresh_prepare_wins_the_cas", func(t *testing.T) {
		m := New()
		t.Cleanup(m.releaseLinkCycleLease)
		m.linkCycleLeaseUntil.Store(staleDeadline)

		injectAtLeaseExpiryCheck(t, expired, func() {
			// A brand-new PrepareLinkCycle. This variant needs no deschedule at
			// all: the stale lease really has expired (a caller that died
			// mid-cycle — the case the backstop exists for), and the next apply
			// takes a fresh one in the ordinary gap between the reader's Load
			// and its CAS. The new cycle has already joined the workers.
			m.acquireLinkCycleLease()
		})

		if !m.linkCycleInFlight() {
			t.Fatalf("reported NO cycle in flight after losing the expiry CAS to a FRESH "+
				"PrepareLinkCycle (deadline now %d). The workers are joined and ctrl is "+
				"being driven to 0 for that new cycle; a reader that answers with the "+
				"expiry it failed to commit reconciles straight into it",
				m.linkCycleLeaseUntil.Load())
		}
	})

	// The control: a release racing the same window must still read as "no
	// cycle". Without it a fix could satisfy the two cells above by never
	// reporting false from the expiry path at all.
	t.Run("release_wins_the_cas", func(t *testing.T) {
		m := New()
		m.linkCycleLeaseUntil.Store(staleDeadline)

		injectAtLeaseExpiryCheck(t, expired, func() {
			m.releaseLinkCycleLease()
		})

		if m.linkCycleInFlight() {
			t.Error("reported a cycle in flight after a concurrent release retired the " +
				"lease to the 0 sentinel; re-reading must judge the new value, and 0 " +
				"means no cycle")
		}
	})
}

// TestLinkCycleInFlightStillExpiresAStrandedLease_6871 is the second control:
// the round-8 loop must not disable the backstop it re-reads around.
//
// It stays GREEN under the B1 revert (the straight-line form expires a stranded
// lease too), so it is a control rather than a restatement of the discriminator.
func TestLinkCycleInFlightStillExpiresAStrandedLease_6871(t *testing.T) {
	m := New()
	m.linkCycleLeaseUntil.Store(int64(linkCycleLeaseTTL))
	swapLinkCycleLeaseElapsed(t, func() time.Duration { return linkCycleLeaseTTL + time.Second })

	if m.linkCycleInFlight() {
		t.Fatal("a lease past its TTL with nothing renewing it must expire; a lease that " +
			"never expires suppresses the 1 Hz reconcile forever, which is worse than " +
			"the race it closes")
	}
	if got := m.linkCycleLeaseUntil.Load(); got != 0 {
		t.Errorf("expiry must retire the deadline to the 0 sentinel (got %d), or every "+
			"later tick re-walks the same expired lease and re-logs the warning", got)
	}
}
