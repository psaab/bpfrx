package userspace

import (
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
// would recurse. A plain bool rather than sync.Once for the same reason — Once
// deadlocks when Do is re-entered from inside its own function.
func injectAtLeaseExpiryCheck(t *testing.T, elapsed time.Duration, inject func()) {
	t.Helper()
	old := linkCycleLeaseElapsed
	fired := false
	linkCycleLeaseElapsed = func() time.Duration {
		if !fired {
			fired = true
			inject()
		}
		return elapsed
	}
	t.Cleanup(func() { linkCycleLeaseElapsed = old })
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
	old := linkCycleLeaseElapsed
	t.Cleanup(func() { linkCycleLeaseElapsed = old })

	m := New()
	m.linkCycleLeaseUntil.Store(int64(linkCycleLeaseTTL))
	linkCycleLeaseElapsed = func() time.Duration { return linkCycleLeaseTTL + time.Second }

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
