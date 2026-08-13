package userspace

import (
	"runtime"
	"strconv"
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
// inject EXACTLY ONCE — on the first read BY THE GOROUTINE THAT INSTALLED IT —
// and then reports elapsed forever.
//
// One-shot on purpose: the injected writer computes its own deadline through
// linkCycleLeaseDeadline(), which reads the same seam, and a re-entrant hook
// would recurse. Not sync.Once for the same reason — Once deadlocks when Do is
// re-entered from inside its own function. CompareAndSwap gives the same
// one-shot without that: it commits the flag BEFORE inject runs, so a
// re-entrant read sees it set.
//
// OWNED BY THE INSTALLING GOROUTINE (#6871 round 12), and that gate is what
// makes these cells mean anything. linkCycleLeaseElapsedOverride is
// process-global: EVERY goroutine that reaches linkCycleLeaseElapsed calls
// whatever closure is installed at that instant, including a heartbeat left
// beating by an earlier test on a Manager that is not this one. Ungated, such a
// beat can WIN the one-shot, and the injection then runs BEFORE the
// discriminator's own read instead of inside its Load->CAS window:
//
//	inject() advances m.linkCycleLeaseUntil to a LIVE deadline;
//	the reader Loads the already-advanced word;
//	61s < 121s on the FIRST comparison -> true. The expiry branch is never
//	entered, no CAS is attempted, and nothing is tested.
//
// Fixed and B1-reverted implementations return true identically there, so the
// cell PASSES VACUOUSLY. Measured with B1 REVERTED — so both cells are OBLIGED
// to fail — and the beat accelerated 15s -> 200us, -test.count in one binary so
// leaked beats accumulate. Every PASS below is therefore a FALSE GREEN:
//
//	                                          renewal    fresh_prepare
//	whole package, HEAD fixture .............   5 / 20       7 / 20
//	whole package, the four leaks in
//	  link_cycle_lease_6871_test.go closed ..   4 / 20       5 / 20
//	whole package, this gate + those closures   0 / 20       0 / 20
//	this file's tests only, HEAD fixture ....  13 / 54      13 / 54
//	this file's tests only, this gate .......   0 / 100      0 / 100
//
// (The 54 is not a typo: that run died at iteration 54 on a stolen inject
// calling t.Fatal off-goroutine. See the panic note below.)
//
// The SECOND ROW is why the gate is the fix and the releases are only hygiene.
// Closing every unreleased acquire in the file that owns both LIVE leaks barely
// moves the number, because the seam is process-global and any other file's next
// unreleased acquire re-supplies a thief. Enumerating leak sites is a race the
// next acquisition site wins; owning the injection is not.
//
// The steal was also observed DIRECTLY rather than inferred: an instrumented
// build of that second row printed the installing and the firing goroutine ids
// whenever they differed, and over six package runs it reported exactly one
// mismatch — firing from `startLinkCycleHeartbeat.func1` via RenewLinkCycle ->
// linkCycleInFlight -> linkCycleLeaseElapsed, on a goroutine created long before
// the test — against exactly one false green, the same cell in the same run.
//
// THE DIRECTION IS THE OPPOSITE OF WHAT ROUND 11 WROTE HERE, and it is spelled
// out because the 75000x acceleration above is exactly the instrument the next
// lane will reach for. Round 11 said a stolen injection leaves "the lease word
// it expected to move unmoved" and can therefore only RED a cell, never green
// one. Backwards: the steal is precisely what MOVES the word early — it REMOVES
// the expiry the reader was going to observe. A steal greens VACUOUSLY. It reds
// only on the narrow ordering where the reader's own CAS(stale -> 0) commits
// before the thief's store lands, measured at HEAD as 4 of 200 accumulating
// iterations and 1 of 200 separate invocations, all in fresh_prepare_wins_the_cas.
//
// ATOMIC, not a plain bool (#6871 round 11), because this closure is read from
// more than one goroutine — the gate above narrows WHO may inject, not who may
// read. Round 10 made linkCycleLeaseElapsedOverride an atomic.Pointer, which
// makes the SWAP race-free; it does not make the closure the pointer points AT
// goroutine-safe. fakeLinkCycleClock's counter is an atomic.Int64 for exactly
// this reason; this flag was the one capture that had not been given the same
// treatment, and `go test -race` reported a genuine WARNING: DATA RACE on it
// (read here, previous write from startLinkCycleHeartbeat.func1) once the
// heartbeat period is shortened enough to widen the collision window. Measured:
// 1 race report before, 0 after, -race -count=5.
//
// The off-goroutine `panic: Fail in goroutine after ... has completed` has TWO
// producers and each half retires one. The atomic retires the double injection —
// CompareAndSwap admits exactly one injector where two racing plain-bool readers
// could both see the flag unset. The gate retires the single STOLEN injection,
// which panics the same way when the thief's emulated renewal loses its CAS and
// calls t.Fatal from the heartbeat goroutine; that is the panic round 12
// reproduced (1 in a 100-iteration B1-reverted run), and it is not a double
// injection. Neither producer fired at HEAD: 0 panics in 200 accelerated runs.
//
// At the production 15s beat none of this is reachable — the collision window is
// microseconds against a 15s period, and the discriminator is 200/200 RED under
// the B1 revert there.
func injectAtLeaseExpiryCheck(t *testing.T, elapsed time.Duration, inject func()) {
	t.Helper()
	owner := leaseSeamGoID()
	if owner == 0 {
		t.Fatal("fixture: could not read this goroutine's id, so a stolen injection " +
			"could not be told from this test's own; refusing to run a cell that would " +
			"pass vacuously")
	}
	var fired atomic.Bool
	swapLinkCycleLeaseElapsed(t, func() time.Duration {
		if leaseSeamGoID() == owner && fired.CompareAndSwap(false, true) {
			inject()
		}
		return elapsed
	})
}

// leaseSeamGoID returns the calling goroutine's id, parsed out of the header
// runtime.Stack writes ("goroutine <id> [running]:\n...").
//
// Same technique, and for the same reason, as pkg/logging's goID (#2287): the
// property under test belongs to ONE goroutine's Load->CAS window, so the
// fixture has to tell its own read of the shared seam from a concurrent one, and
// no flag can make that distinction — a flag records THAT someone read, never
// WHO. Test-only, and only while an injecting override is installed, which is
// microseconds; runtime.Stack for the current goroutine alone does not stop the
// world.
func leaseSeamGoID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	const prefix = "goroutine "
	s := buf[:n]
	if len(s) < len(prefix) {
		return 0
	}
	s = s[len(prefix):]
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	id, err := strconv.ParseUint(string(s[:i]), 10, 64)
	if err != nil {
		return 0
	}
	return id
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
