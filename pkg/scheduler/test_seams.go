package scheduler

import "time"

// SetTickIntervalForTesting overrides the evaluation period, which is
// defaultTickInterval (60s) in production.
//
// #8660: it exists so a cell OUTSIDE this package can drive a real tick through
// `Run` rather than calling `evaluate` directly. That distinction is not
// stylistic. The defect #8660 fixed was `Run` failing to hand its ctx down, and
// a cell that calls `evaluate` cannot observe its caller passing the wrong
// argument — measured, not assumed: with `Run` mutated to pass
// `context.Background()`, an evaluate-level cell stayed GREEN.
//
// `pkg/daemon` needs it to park a real tick inside the scheduler goroutine
// behind a wedged apply and then assert shutdown's join completes, which is the
// end-to-end property and cannot be reached in 60-second steps.
//
// Deliberately a seam rather than a constructor option: production has exactly
// one interval and no caller should be choosing it.
func (s *Scheduler) SetTickIntervalForTesting(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickInterval = d
}

// LatchRepublishForTesting sets the #3780 republish latch, so the NEXT
// evaluate tick fires updateFn even though the active-state map did not
// change.
//
// #8660: a cell in pkg/daemon needs a real tick to ENTER the daemon's publish
// so it can be parked on a wedged apply. Between NewPrimed and the first tick
// nothing changes, so without this the tick evaluates and correctly declines to
// notify — and the join cell would then assert against a fixture that never set
// up the condition it is about. It reaches the latch the production error path
// sets rather than inventing a second way to force a notify.
func (s *Scheduler) LatchRepublishForTesting() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.republishPending = true
}
