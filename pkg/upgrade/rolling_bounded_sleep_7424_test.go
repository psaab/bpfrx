package upgrade

import (
	"testing"
	"time"
)

// #7424 row 5: waitPredicate's deadline check sits BEFORE its sleep, so a raw
// Sleep(PollInterval) overshoots the deadline by up to a full interval. Two
// consequences, and the first is a wrong ANSWER rather than a slow one:
//
//  1. a predicate that first becomes true AFTER the deadline was accepted as
//     satisfied within it;
//  2. a genuine timeout was reported up to one interval late.
//
// WHY THE FIXTURE LOOKS LIKE THIS. Every pre-existing fixture in this package
// uses PollInterval: 1ms, which is why none of them can catch this: the
// overshoot is 1ms and invisible. The shape that makes it observable needs the
// poll interval to be LARGE relative to the deadline, so these cells invert the
// usual ratio — a 50ms deadline against a 5s interval. That is the smallest
// shape where removing the fix changes an outcome.

const (
	sleep7424Deadline = 50 * time.Millisecond
	sleep7424Interval = 5 * time.Second
	// When the predicate flips: after the deadline, but well inside the
	// unbounded sleep that the bug would perform.
	sleep7424Flip = 1 * time.Second
)

// flipAfter returns a predicate that is false until d has elapsed, then true.
func flipAfter(d time.Duration) func() (bool, error) {
	start := time.Now()
	return func() (bool, error) { return time.Since(start) >= d, nil }
}

// The PRIMARY cell: an outcome assertion, not a timing one.
//
// With the bounded sleep, waitPredicate re-checks AT the 50ms deadline, sees a
// still-false predicate, and reports a timeout. With the raw sleep it sleeps a
// full 5s, finds the predicate true at t=5s — a full 100x past its own deadline
// — and returns success.
//
// FAIL-ON-REVERT: restore `time.Sleep(rc.PollInterval)` and this returns nil.
func TestWaitPredicateRejectsAPredicateThatOnlyTurnsTrueAfterTheDeadline_7424(t *testing.T) {
	rc := RollingConfig{
		DrainDeadline: sleep7424Deadline,
		PollInterval:  sleep7424Interval,
	}

	start := time.Now()
	err := waitPredicate(rc, false, flipAfter(sleep7424Flip))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("waitPredicate returned nil for a predicate that first became true at %s, "+
			"%s past its own %s deadline — the sleep overshot the deadline and the "+
			"post-deadline result was accepted as satisfied within it (elapsed %s)",
			sleep7424Flip, sleep7424Flip-sleep7424Deadline, sleep7424Deadline, elapsed)
	}
	// The predicate never became true within the deadline, so it must not have
	// waited for the flip either. Generous by 20x against the 5s interval the
	// bug would sleep, so a loaded box cannot make this flake, while a revert
	// (which cannot finish before 5s) cannot pass it.
	if elapsed > sleep7424Flip {
		t.Errorf("waitPredicate took %s to report a %s timeout; it waited past the deadline "+
			"rather than re-checking at it", elapsed, sleep7424Deadline)
	}
}

// CONTROL. Without this the cell above passes for a predicate that never turns
// true at all, or for a waitPredicate that always errors — neither of which
// would say anything about the deadline. Same predicate, same interval, a
// deadline long enough to contain the flip: it must SUCCEED.
func TestWaitPredicateStillAcceptsAPredicateThatTurnsTrueBeforeTheDeadline_7424(t *testing.T) {
	rc := RollingConfig{
		DrainDeadline: 3 * time.Second,
		PollInterval:  20 * time.Millisecond,
	}
	if err := waitPredicate(rc, false, flipAfter(50*time.Millisecond)); err != nil {
		t.Fatalf("waitPredicate error = %v; the predicate turns true well inside the deadline, "+
			"so the bounded sleep must not have broken the ordinary success path", err)
	}
}

// sleepBounded's own contract, exercised directly at the boundary the callers
// depend on: it must never sleep past the deadline, and must return at once on
// an already-elapsed one.
func TestSleepBoundedNeverOvershootsTheDeadline_7424(t *testing.T) {
	t.Run("clamps to the remaining time", func(t *testing.T) {
		dl := time.Now().Add(40 * time.Millisecond)
		start := time.Now()
		sleepBounded(dl, 5*time.Second)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("sleepBounded slept %s with 40ms remaining and a 5s interval; "+
				"it must clamp to the deadline", elapsed)
		}
	})
	t.Run("returns immediately past the deadline", func(t *testing.T) {
		start := time.Now()
		sleepBounded(time.Now().Add(-time.Second), 5*time.Second)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("sleepBounded slept %s on an already-elapsed deadline; want an "+
				"immediate return", elapsed)
		}
	})
}
