package ipmon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// #8027: TestDebounceCoalescing's `<= 2` bound cannot distinguish coalescing
// from unreachability, so it stays GREEN with the debounce disabled entirely.
//
// The reason is structural, not a fixture accident. Actuation is driven by a
// DIRTY FLAG: one actuation covers every pending transition regardless of how
// many arrived, so a flap storm coalesces BY DESIGN. `<= 2` is therefore
// satisfied by the shape of the code whatever the debounce window does, and a
// bound satisfied by structure rather than by the behaviour under test
// measures nothing about that behaviour.
//
// WHAT ACTUALLY FALSIFIES THE DEBOUNCE. Its job is not to reduce a count — the
// dirty flag already does that — it is to DELAY: after a state change, no
// actuation until the window has elapsed. So the assertion has to be a
// latency LOWER bound, and the acceptance criterion #8027 states is exactly
// that the test must red when `now.Sub(e.dirtySince) >= e.debounce` becomes
// `>= 0`.
//
// WHY THIS IS NOT A NEW TIMING FLAKE, which is the obvious objection given
// #7969 just stabilised the sibling test:
//
//   - It runs on the FAKE CLOCK the package already has (`newTestEngine`).
//     The gate the run loop evaluates reads `e.now()`, so the window is
//     crossed by `clock.Advance`, not by elapsed wall time.
//   - The load-bearing assertion is an ABSENCE — nothing actuated before the
//     window. A loaded machine can only make an actuation LATER, never
//     earlier, so contention cannot produce a false RED here. It could in
//     principle produce a false GREEN (the loop never ran at all), which is
//     what the two liveness waits around it rule out: the engine is shown to
//     actuate both before and after the quiet period, so the quiet is a
//     property of the debounce and not of a wedged goroutine.
//   - The real-time sleep in the middle is a GENEROSITY, not a deadline.
//     Raising it can only make the test more patient; no assertion depends on
//     its value.
//
// THE THROTTLE IS SET SMALL ON PURPOSE. With the default proportions the
// throttle would be the binding constraint, and an actuation held back by the
// throttle looks exactly like one held back by the debounce — the test would
// pass with the debounce disabled, which is the defect being fixed. Making the
// throttle negligible leaves the debounce as the only thing that can delay.
func TestDebounceActuallyDelaysActuation8027(t *testing.T) {
	const (
		debounce = 100 * time.Millisecond
		throttle = time.Millisecond
		// Generous: how long the engine is given to actuate if it is going
		// to. Not a timing assertion — see above.
		quiet = 400 * time.Millisecond
	)

	var actuations atomic.Int32
	e, clock := newTestEngine(func(context.Context) bool {
		actuations.Add(1)
		return true
	})
	e.debounce = debounce
	e.throttle = throttle
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	// --- reach a CLEAN engine, having actuated at least once ------------
	// Applying an all-PASSING config does not dirty anything: the overlay it
	// computes is empty, which is what the engine already believes, so
	// markDirty is a no-op and the loop never actuates. (Worth recording —
	// a first draft assumed config-apply alone produced the baseline
	// actuation, and the fake clock made that assumption fail loudly instead
	// of silently shifting what the measurement was anchored to.)
	//
	// So drive a real state change to get one actuation, then return to
	// clean. Clean matters: markDirtyLocked only sets `dirtySince` on a
	// clean->dirty transition, so if the engine were still dirty when this
	// test's own transition lands, the debounce clock would have started
	// EARLIER and the latency below would be measured against the wrong
	// origin — reading as a debounce failure when it is a setup failure.
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	clock.Advance(debounce + throttle)
	waitForActuation(t, &actuations, 1, 5*time.Second)

	// Prove clean rather than assume it: cross a full window again and
	// require that NOTHING further actuates.
	settled := actuations.Load()
	clock.Advance(debounce + throttle)
	time.Sleep(quiet / 2)
	if got := actuations.Load(); got != settled {
		t.Fatalf("SETUP: engine actuated %d more time(s) after the first actuation "+
			"settled, so it was still dirty when this test's window was supposed "+
			"to start; the latency measurement below would be against the wrong "+
			"origin", got-settled)
	}

	// --- the measurement -----------------------------------------------
	// Mark dirty at fake-time t0 with a genuine state change (fail -> pass).
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))

	// Advance to ONE MILLISECOND SHORT of the window, then wait a generous
	// real interval. The run loop re-evaluates on its own timer throughout,
	// so it has many chances to actuate — and must not take any of them.
	clock.Advance(debounce - time.Millisecond)
	time.Sleep(quiet)

	if got := actuations.Load(); got != settled {
		t.Fatalf("the engine actuated %d time(s) with %v of a %v debounce window "+
			"elapsed. The debounce is not delaying actuation at all: a state change "+
			"is being acted on immediately, which is what the window exists to "+
			"prevent (#8027). Note the dirty flag would still make the COUNT look "+
			"coalesced here, which is why a count bound cannot see this.",
			got-settled, debounce-time.Millisecond, debounce)
	}

	// --- liveness ------------------------------------------------------
	// Cross the window; the actuation must now arrive. Without this the cell
	// above is satisfied by an engine that never actuates for any reason, and
	// "the debounce works" would be indistinguishable from "the loop is
	// wedged" — the exact substitution #8027 is about.
	clock.Advance(2 * time.Millisecond)
	waitForActuation(t, &actuations, settled+1, 5*time.Second)
}

// The THROTTLE has the same falsifiability problem and the same fix, and it is
// worth pinning here rather than leaving the debounce as the only delay under
// test: with the debounce negligible, an actuation must still wait out the
// throttle after the previous one.
//
// This also protects the cell above from a fix that satisfies it by widening
// the throttle instead of honouring the debounce — the two are separately
// bound, so neither can stand in for the other.
func TestThrottlePacesConsecutiveActuations8027(t *testing.T) {
	const (
		debounce = time.Millisecond
		throttle = 100 * time.Millisecond
		quiet    = 400 * time.Millisecond
	)

	var actuations atomic.Int32
	e, clock := newTestEngine(func(context.Context) bool {
		actuations.Add(1)
		return true
	})
	e.debounce = debounce
	e.throttle = throttle
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	clock.Advance(debounce + throttle)
	waitForActuation(t, &actuations, 1, 5*time.Second)
	settled := actuations.Load()

	// A new change immediately after an actuation: the debounce is
	// negligible, so only the throttle can hold it.
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
	clock.Advance(throttle / 2)
	time.Sleep(quiet)

	if got := actuations.Load(); got != settled {
		t.Fatalf("the engine actuated %d more time(s) only %v after the previous "+
			"actuation, against a %v throttle. Sustained flapping is then unbounded "+
			"in rate, which is what the throttle exists to prevent (#8027)",
			got-settled, throttle/2, throttle)
	}

	clock.Advance(throttle)
	waitForActuation(t, &actuations, settled+1, 5*time.Second)
}
