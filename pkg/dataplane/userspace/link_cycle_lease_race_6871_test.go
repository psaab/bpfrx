package userspace

import (
	"bytes"
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
// real box. That makes the repro deterministic instead of a timing lottery: the
// interleaving is produced by the seam rather than by the scheduler, so there
// are no sleeps and nothing the assertion depends on is timing-sensitive.
//
// It is not goroutine-FREE, and an earlier revision said it was (#6871 round
// 13). fresh_prepare_wins_the_cas injects a real acquireLinkCycleLease, which
// starts the lease's heartbeat goroutine. Nothing below waits on it: the first
// beat is one linkCycleLeaseHeartbeat (15s) away, the assertion runs
// immediately, and the cell's t.Cleanup releases the lease, which stops and
// JOINS that goroutine before the subtest ends.

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
// cell PASSES VACUOUSLY.
//
// ROUND 12 MEASURED THAT ON A TREE THAT NO LONGER EXISTS, and this comment
// carried its numbers as though they were properties of a scope (#6871 round
// 13). They were properties of a tree state: the round-11 fixture with the four
// acquisitions in link_cycle_lease_6871_test.go left UNRELEASED. Round 12 closed
// all four — each now pairs t.Cleanup(m.releaseLinkCycleLease) with its acquire,
// which STOPS AND JOINS the heartbeat — and with no heartbeat outliving its
// test, no thief exists to win the one-shot.
//
// Re-measured at head with the same instrument (gate OFF, beat accelerated
// 15s -> 200us, B1 REVERTED so both cells are OBLIGED to fail), counting seam
// arrivals by a non-owner goroutine directly rather than inferring them from
// outcomes, and splitting the arrivals that can WIN the one-shot (before `fired`
// is set) from the ones that cannot:
//
//	scope                              false greens   pre-fire   post-fire
//	this file's tests, -count=100 ...   0/100  0/100      0        0 and 4
//	+ link_cycle_lease_6871_test.go .   0/100  0/100      0          10
//	whole package, -count=20 .......    0/12   0/12       0           0
//
// (0 and 4 is two separate runs of the same cell, so a post-fire arrival there
// is at the edge of the noise. The whole-package denominator is 12 because the
// run hit `go test`'s 10-minute default timeout at iteration 12 — a truncation,
// not a signal, and NOT the off-goroutine panic round 12 attributed the earlier
// truncation to.)
//
// WHAT SURVIVES, and it is the direction round 12 and the round-13 hostile
// review both argued: thief ARRIVALS scale with scope, and they come from the
// leak-bearing file rather than from this one — 10 against 0. What does NOT
// survive is any false green attributable to a scope, because at head not one
// arrival landed before the one-shot had already fired. The old row labelled
// "this file's tests only" could not have been measured at that scope, and the
// parenthetical about a run dying at iteration 54 on a stolen inject is not
// reproducible either.
//
// SO THE GATE IS NOT JUSTIFIED BY THAT TABLE ANY MORE, and it does not need to
// be. What justifies it at head needs no thief at all: the installing
// goroutine's OWN earlier read of the seam consumes the one-shot, measured
// 100/100 vacuous with an intervening read and B1 reverted (see the round-13
// note below). A cross-goroutine steal is the case round 12 could still
// reproduce and this tree cannot; self-consumption is the case that reproduces
// exactly, and the two gates close both.
//
// THE DIRECTION IS THE OPPOSITE OF WHAT ROUND 11 WROTE HERE, and it is spelled
// out because the 75000x acceleration above is exactly the instrument the next
// lane will reach for. Round 11 said a stolen injection leaves "the lease word
// it expected to move unmoved" and can therefore only RED a cell, never green
// one. Backwards: the steal is precisely what MOVES the word early — it REMOVES
// the expiry the reader was going to observe. A steal greens VACUOUSLY, and reds
// only on the narrow ordering where the reader's own CAS(stale -> 0) commits
// before the thief's store lands. Round 12 put numbers on that narrow ordering
// (4 of 200 accumulating iterations, 1 of 200 separate invocations, all in
// fresh_prepare_wins_the_cas); those belong to the same pre-closure tree as the
// table above and do not reproduce here either. The DIRECTION is what matters
// and it is a consequence of what inject() does to the word, not of a count.
//
// ATOMIC, and no longer the thing that makes this race-free (#6871 round 13).
// Round 11 made the flag an atomic.Bool because the closure WAS read from more
// than one goroutine: linkCycleLeaseElapsedOverride is an atomic.Pointer, which
// makes the SWAP race-free without making the closure it points AT
// goroutine-safe, and `go test -race` reported a genuine WARNING: DATA RACE on
// this flag (read here, previous write from startLinkCycleHeartbeat.func1) once
// the heartbeat period is shortened enough to widen the collision window —
// 1 race report before, 0 after, -race -count=5.
//
// That measurement was taken against the UNGATED closure. The gate added in
// round 12 and tightened in round 13 is evaluated with `&&`, so it
// short-circuits: a caller that is not the installing goroutine, or is not
// inside linkCycleInFlight, returns before `fired` is touched at all. Only the
// owner ever reaches the flag, so a plain bool would today be sufficient AND
// race-free, and describing the atomic as the protection would be describing
// round 11's code.
//
// It stays because it costs one uncontended CAS on a test-only path and it is
// the half that remains correct if the gate is ever loosened — and because
// CompareAndSwap is the natural spelling of "commit the flag BEFORE inject
// runs", which is what makes the re-entrant read from inside inject a no-op
// rather than infinite recursion. fakeLinkCycleClock's counter is an
// atomic.Int64 for the original reason and is NOT gated, so there the atomic is
// still load-bearing.
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
// That reproduction belongs to the same pre-closure tree as the table above
// (#6871 round 13): with the four acquisitions released, no beat outlives its
// test, so the stolen-injection producer has nothing to fire from and cannot be
// re-demonstrated here. The gate still retires it — a producer that is currently
// unreachable is exactly the kind that returns the moment someone adds an
// unreleased acquire, which is why the fix is the gate and not the releases.
//
// At the production 15s beat the collision is vanishingly unlikely rather than
// impossible — the window is microseconds wide against a 15s period, so a beat
// CAN land in it — and it was not observed there: the discriminator is 200/200
// RED under the B1 revert (#6871 round 13 corrected an earlier "none of this is
// reachable", which is a stronger claim than the measurement supports).
//
// THE GOROUTINE ID IS NOT ENOUGH ON ITS OWN (#6871 round 13). "My goroutine" was
// only ever a proxy for "my call", and the two come apart: linkCycleLeaseElapsed
// is reached from linkCycleLeaseDeadline as well as from linkCycleInFlight, so
// ANY earlier same-goroutine read consumes the one-shot and the injection then
// runs somewhere other than the Load->CAS window it is meant to occupy. That was
// measured, not supposed — an intervening read placed right after installation,
// with the production lost-CAS fix reverted so both cells are OBLIGED to fail,
// passed 100/100.
//
// So the gate states the property directly: the read must be made BY the
// installing goroutine AND FROM INSIDE Manager.linkCycleInFlight. The goroutine
// half rejects a leaked heartbeat's beat (which does reach linkCycleInFlight,
// via RenewLinkCycle); the frame half rejects this goroutine's own reads from
// anywhere else. Neither is redundant.
//
// AND THE CELL FAILS IF THE INJECTION NEVER RAN. A stricter gate can only turn a
// false green into a different false green if "did not fire" stays silent, so
// t.Cleanup asserts it fired. That also covers the gate going stale — rename
// linkCycleInFlight without updating leaseSeamInFlightFrame and every cell here
// fails loudly instead of quietly testing nothing.
func injectAtLeaseExpiryCheck(t *testing.T, elapsed time.Duration, inject func()) {
	t.Helper()
	owner, _ := leaseSeamCaller()
	if owner == 0 {
		t.Fatal("fixture: could not read this goroutine's id from the runtime.Stack " +
			"header, so a stolen injection could not be told from this test's own; " +
			"refusing to run a cell that would pass vacuously")
	}
	var fired atomic.Bool
	// Registered BEFORE swapLinkCycleLeaseElapsed's restore, so cleanup LIFO
	// uninstalls the override first and nothing can flip the flag under the check.
	t.Cleanup(func() {
		if !fired.Load() {
			t.Errorf("fixture: the injection never ran. Every assertion in this cell is " +
				"about what linkCycleInFlight does when a competing writer lands inside its " +
				"Load->CAS window, and no writer landed there — so the cell proved nothing " +
				"and would have passed either way. Either the seam is no longer reached from " +
				"linkCycleInFlight, or leaseSeamInFlightFrame no longer names that frame")
		}
	})
	swapLinkCycleLeaseElapsed(t, func() time.Duration {
		if id, inFlight := leaseSeamCaller(); inFlight && id == owner &&
			fired.CompareAndSwap(false, true) {
			inject()
		}
		return elapsed
	})
}

// leaseSeamInFlightFrame is the traceback spelling of the ONE call site whose
// read is the Load->CAS window. runtime.Stack renders a method frame as
// "<importpath>.(*Manager).linkCycleInFlight(...)", and inlined frames are
// expanded rather than elided, so a compiler decision cannot silently empty this
// match.
const leaseSeamInFlightFrame = ".(*Manager).linkCycleInFlight("

// leaseSeamCaller reports the calling goroutine's id and whether the call is
// being made from inside Manager.linkCycleInFlight, both read out of one
// runtime.Stack dump.
//
// The id uses the same technique, and for the same reason, as pkg/logging's goID
// (#2287): the property under test belongs to ONE goroutine's Load->CAS window,
// so the fixture has to tell its own read of the process-global seam from a
// concurrent one, and no flag can make that distinction — a flag records THAT
// someone read, never WHO.
//
// The header prefix is VERIFIED rather than assumed (#6871 round 13). Skipping
// len("goroutine ") bytes without checking them makes an undocumented runtime
// format an unstated dependency: a changed header would silently yield a parsed
// id from whatever happened to follow, and the gate would then admit or reject
// on a number that means nothing. A mismatch returns 0, which the caller turns
// into a t.Fatal at install time.
//
// Test-only, and only while an injecting override is installed. runtime.Stack
// for the current goroutine alone does not stop the world; the buffer is 8 KiB
// because the frame match needs the frames, and a truncated dump fails CLOSED
// (no match -> no injection -> the vacuity check above fires).
func leaseSeamCaller() (uint64, bool) {
	var buf [8 << 10]byte
	n := runtime.Stack(buf[:], false)
	s := buf[:n]
	const prefix = "goroutine "
	if !bytes.HasPrefix(s, []byte(prefix)) {
		return 0, false
	}
	rest := s[len(prefix):]
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	id, err := strconv.ParseUint(string(rest[:i]), 10, 64)
	if err != nil {
		return 0, false
	}
	return id, bytes.Contains(rest, []byte(leaseSeamInFlightFrame))
}

// TestLeaseSeamCallerDistinguishesGoroutinesAndCallSites_6871 binds the reader
// the gate is built on (#6871 round 13).
//
// NEITHER HALF IS OBSERVABLE FROM THE CELLS BELOW, which is the whole reason
// this exists. Force leaseSeamCaller to return a CONSTANT id and a constant
// true and the gate degenerates to "every goroutine, from every call site, is
// the owner" — restoring exactly the vacuity rounds 12 and 13 closed — and the
// entire suite stays GREEN, because nothing else drives a second goroutine or a
// second call site through it. A guard whose reader can be replaced by a
// constant with no test noticing is a guard bound by nothing.
//
// This is a FUTURE-REGRESSION gap rather than a present inability to fire: the
// realistic failure is a runtime stack-header change, and that fails the prefix
// check, returns 0, and injectAtLeaseExpiryCheck t.Fatals loudly. It is closed
// anyway because it is five assertions.
func TestLeaseSeamCallerDistinguishesGoroutinesAndCallSites_6871(t *testing.T) {
	self, inFlight := leaseSeamCaller()
	if self == 0 {
		t.Fatal("leaseSeamCaller reported id 0 from a plain test goroutine: the " +
			"runtime.Stack header did not start with \"goroutine \", so the gate can no " +
			"longer identify anyone and every cell in this file is about to fail closed")
	}
	if inFlight {
		t.Error("leaseSeamCaller reported IN-FLIGHT from a plain test function. The frame " +
			"half must be false anywhere but inside Manager.linkCycleInFlight, or the gate " +
			"admits this goroutine's reads from linkCycleLeaseDeadline too — which is the " +
			"consumable one-shot round 13 exists to close")
	}

	// Stable across two reads on one goroutine: the gate stores an owner and
	// compares a LATER read against it, so an unstable id would reject the
	// installer's own injection and turn every cell vacuous in the other
	// direction.
	if again, _ := leaseSeamCaller(); again != self {
		t.Errorf("two reads on one goroutine returned different ids (%d then %d)", self, again)
	}

	// Different on a different goroutine. A constant reader satisfies every
	// assertion above and fails this one.
	other := make(chan uint64, 1)
	go func() {
		id, _ := leaseSeamCaller()
		other <- id
	}()
	if got := <-other; got == self {
		t.Errorf("a second goroutine reported the SAME id (%d) as this one. Telling a "+
			"stolen injection from the installer's own is the gate's entire job, and a "+
			"reader that cannot distinguish two goroutines admits every thief", got)
	}

	// And TRUE from inside linkCycleInFlight — the half a rename of that method
	// would silently empty, leaving a gate that admits nobody.
	m := New()
	t.Cleanup(m.releaseLinkCycleLease)
	m.linkCycleLeaseUntil.Store(int64(linkCycleLeaseTTL))
	var sawInFlight atomic.Bool
	var sawID atomic.Uint64
	swapLinkCycleLeaseElapsed(t, func() time.Duration {
		id, inF := leaseSeamCaller()
		if inF {
			sawInFlight.Store(true)
			sawID.Store(id)
		}
		return 0
	})
	if !m.linkCycleInFlight() {
		t.Fatal("fixture: a lease at elapsed=0 with a full-TTL deadline must read as in " +
			"flight; the seam below was not exercised on the intended path")
	}
	if !sawInFlight.Load() {
		t.Errorf("leaseSeamCaller did not report in-flight for a read made from INSIDE "+
			"Manager.linkCycleInFlight, so leaseSeamInFlightFrame (%q) no longer names that "+
			"frame. Every cell in this file then injects nothing — caught by the vacuity "+
			"check as a red, but a red for the wrong reason", leaseSeamInFlightFrame)
	}
	if got := sawID.Load(); got != self {
		t.Errorf("the read from inside linkCycleInFlight reported id %d, but this goroutine "+
			"is %d — the id must not depend on call depth, or the owner comparison fails "+
			"for the installer's own injection", got, self)
	}
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
