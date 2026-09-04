package daemon

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

// #8597 (muse-004 K23) — stopPolicySchedulerLoop acquired applySem with
// context.Background(), so a wedged apply stalled the whole orderly shutdown.
//
// daemon_run_shutdown.go states the rule at its own drain: "bound it
// defensively anyway so a wedged apply cannot block the whole shutdown past the
// drain budget." A census of applySem acquires reachable from the shutdown
// sequence finds exactly two — that drain, which was bounded, and this one,
// which was not. (stopPinRetryLoop, the sibling cleanup called on the next
// line, does not touch applySem at all.)
//
// What the stall costs: the scheduler is never cancelled, so shutdown never
// reaches the HA relinquish that follows, and systemd's TimeoutStopSec ends the
// process with SIGKILL — no rg_active clear, no priority-0 advert, no RA
// goodbye. A clean sub-second handover becomes a blackout.

// stopWithin runs stopPolicySchedulerLoop on a goroutine and waits at most
// budget for it.
//
// Every cell in this file that holds applySem MUST go through it. Under the
// mutation this file exists to catch, the call does not return at all — so a
// cell that invoked it inline would HANG rather than fail, and a hanging cell
// is a void: its mutant produces no verdict, only a timed-out package. The one
// cell that ran inline in the first draft did exactly that.
func stopWithin(t *testing.T, d *Daemon, budget time.Duration) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		d.stopPolicySchedulerLoop()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(budget):
		return false
	}
}

// TestStopPolicySchedulerLoopIsBoundedByAWedgedApply_8597 is the RED-on-revert
// core. applySem is held for longer than the shutdown budget, modelling the
// wedged apply; stopPolicySchedulerLoop must still return.
//
// Restoring context.Background() makes this hang rather than fail, so the cell
// runs the call on a goroutine and races it against a timer well beyond the
// budget. A cell that simply called it inline would be a void under its own
// mutant.
func TestStopPolicySchedulerLoopIsBoundedByAWedgedApply_8597(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	// The wedged apply: acquired and never released for the life of the test.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}

	start := time.Now()
	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return while an apply held applySem: " +
			"the shutdown-path acquire is unbounded, so a wedged apply stalls the " +
			"orderly shutdown past TimeoutStopSec and the process is SIGKILLed with " +
			"no rg_active clear, no priority-0 advert and no RA goodbye (#8597/K23)")
	}

	if elapsed := time.Since(start); elapsed < applyCloseoutDrainTimeout {
		t.Errorf("returned after %v, before the %v budget: it cannot have waited for the "+
			"semaphore at all, so this cell is not exercising the wedged-apply path",
			elapsed, applyCloseoutDrainTimeout)
	}
}

// TestStopPolicySchedulerLoopDoesNotReleaseASemaphoreItNeverTook_8597 is the
// correctness half of bounding an acquire, and the bug a careless bound
// introduces.
//
// The original released unconditionally, which was safe only because the
// acquire could not fail. Releasing a weight-1 semaphore that was never
// acquired raises its count above its capacity, so the NEXT acquirer proceeds
// while the wedged apply still holds it — two concurrent applies, from a
// shutdown path whose whole purpose is to serialise against them.
//
// After the timeout above, the semaphore must still be fully held by the wedged
// apply: a fresh non-blocking acquire must FAIL.
func TestStopPolicySchedulerLoopDoesNotReleaseASemaphoreItNeverTook_8597(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}

	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return; the acquire is unbounded (#8597/K23)")
	}

	if d.applySem.TryAcquire(1) {
		t.Fatal("applySem admitted a second holder after a timed-out stop: the stop " +
			"released a permit it never acquired, so the wedged apply now runs " +
			"concurrently with whatever acquires next")
	}
}

// TestStopPolicySchedulerLoopStillTakesTheSemaphoreWhenFree_8597 is the
// OVER-BROAD control. A "fix" that stopped acquiring altogether would pass both
// cells above and lose the mutual exclusion the acquire exists for — the
// schedulerCancel read/clear must happen under the same lock that guards it.
//
// It also pins the release: an acquire that succeeded and was not released
// would leave the semaphore permanently held, which on the Run()-returns path
// (where this is a defer rather than the shutdown sequence) wedges every later
// apply.
func TestStopPolicySchedulerLoopStillTakesTheSemaphoreWhenFree_8597(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	var heldDuringStop bool
	d.schedulerCancel = func() {
		// Runs after the release in the current shape; what matters is that by
		// the time stopPolicySchedulerLoop RETURNS the permit is back.
		heldDuringStop = !d.applySem.TryAcquire(1)
		if !heldDuringStop {
			d.applySem.Release(1)
		}
	}

	start := time.Now()
	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return on a FREE semaphore")
	}

	if elapsed := time.Since(start); elapsed >= applyCloseoutDrainTimeout {
		t.Errorf("took %v on a FREE semaphore: the acquire must succeed immediately when "+
			"no apply is in flight, not wait out the budget", elapsed)
	}
	if !d.applySem.TryAcquire(1) {
		t.Fatal("applySem is still held after stopPolicySchedulerLoop returned on a free " +
			"semaphore: an acquired permit was not released, and every later apply " +
			"blocks on it")
	}
	d.applySem.Release(1)
	if !d.schedulerStopped {
		t.Error("schedulerStopped must latch regardless of the semaphore outcome")
	}
}

// TestStopPolicySchedulerLoopCancelsEvenAfterTheTimeout_8597 pins the point of
// bounding the acquire: it is not that the call returns, it is that the call
// reaches the CANCEL. A bound that gave up and returned early would leave the
// scheduler goroutine running against a runtime the next lines tear down —
// exactly what #5308 ordered this call before the dataplane teardown to prevent.
func TestStopPolicySchedulerLoopCancelsEvenAfterTheTimeout_8597(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}

	cancelled := false
	d.schedulerCancel = func() { cancelled = true }

	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return; the acquire is unbounded (#8597/K23)")
	}

	if !cancelled {
		t.Fatal("the scheduler was never cancelled after the acquire timed out: bounding " +
			"the wait is only worth anything if the call goes on to do its job (#5308 " +
			"orders this before the dataplane teardown so no late tick runs against a " +
			"closed runtime)")
	}
	if d.schedulerCancel != nil {
		t.Error("schedulerCancel must be cleared so a second stop is a no-op")
	}
}
