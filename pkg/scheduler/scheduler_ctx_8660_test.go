package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #8660: the tick must hand updateFn the ctx it was given, because that is the
// only thing that makes a parked publish releasable by cancellation.
//
// The daemon's updateFn acquires the apply semaphore. With the scheduler's ctx
// it is released by schedulerCancel(), so shutdown's schedulerWg.Wait() returns;
// with anything uncancellable the join blocks behind a wedged apply and the
// daemon is SIGKILLed before HA relinquish.
//
// THIS CELL DRIVES Run, NOT evaluate, AND THE DIFFERENCE IS NOT COSMETIC. The
// first version called `s.evaluate(ctx, ...)` directly and claimed to bind the
// chain Run -> evaluate -> updateFn. It did not: a mutation making `Run` pass
// `context.Background()` down — which IS the defect #8660 fixes, one frame up —
// left it GREEN. A cell that calls the function under the defect cannot see the
// caller handing it the wrong argument.
//
// So it goes through `Run`, using the `tickInterval` seam to avoid waiting for
// the 60s production ticker. The other half of the chain — publish acquires with
// the ctx it is handed — is bound in pkg/daemon by
// TestPublishPolicyScheduleStateReleasesOnSuppliedContext8660. They meet at
// updateFn's ctx parameter, which is a type obligation rather than a
// convention.
func TestRunHandsItsContextToUpdateFn8660(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	got := make(chan context.Context, 1)
	s, _ := NewPrimed(map[string]*config.SchedulerConfig{
		"always": {Name: "always"},
	}, func(c context.Context, _ map[string]bool) error {
		got <- c
		return nil
	}, time.Now())

	s.republishPending = true // force a notify without needing a state change
	s.SetTickIntervalForTesting(time.Millisecond)
	go s.Run(ctx)

	select {
	case c := <-got:
		if c == nil {
			t.Fatal("updateFn received a nil context — the tick must hand down " +
				"the scheduler's ctx (#8660)")
		}
		// THE OBSERVABLE, named rather than assumed: a ctx that merely arrives
		// proves nothing. What the fix needs is that cancelling the scheduler
		// cancels the one the publish will block on. Passing context.Background()
		// down would satisfy "non-nil" and reinstate the defect exactly.
		select {
		case <-c.Done():
			t.Fatal("the context handed to updateFn was already cancelled")
		default:
		}
		cancel()
		select {
		case <-c.Done():
		case <-time.After(time.Second):
			t.Fatal("cancelling the ctx passed to evaluate did NOT cancel the one " +
				"handed to updateFn — the tick is supplying a different context, " +
				"so schedulerCancel() cannot release a publish parked on the apply " +
				"semaphore and shutdown's join blocks behind a wedged apply (#8660)")
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("updateFn was never called; the fixture did not force a notify")
	}
}
