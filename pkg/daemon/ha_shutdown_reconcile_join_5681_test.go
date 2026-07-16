package daemon

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestReconcileRGStateLoopJoinedBeforeOwnershipCleanup_5681 pins the #5681 / M23
// shutdown-ordering invariant: the RG-state reconcile safety-net loop is
// registered on the run WaitGroup, so runShutdownSequence's wg.Wait() (the
// barrier that precedes every HA ownership-relinquish step — rg_active clear, RA
// withdraw, direct-mode VIP removal, VRRP Stop) cannot return while a reconcile
// pass is still in flight.
//
// The bug it guards: as a bare `go d.reconcileRGStateLoop(ctx)` the loop was
// never joined. stop() cancelled its ctx, but a tick already inside a reconcile
// pass (re-enabling forwarding / re-adding VIPs) could complete AFTER wg.Wait()
// returned — i.e. during the later ownership-cleanup phase — and re-assert
// mastership, opening a transient dual-master / blackhole window on planned
// shutdown or failover.
//
// Fail-on-revert: reverting startReconcileRGStateLoop to a bare `go` (dropping
// the wg.Add(1)/wg.Done()) leaves the loop unregistered, so wg.Wait() returns
// immediately while the pass is mid-flight and the in-flight-window assertion
// below fires RED.
func TestReconcileRGStateLoopJoinedBeforeOwnershipCleanup_5681(t *testing.T) {
	entered := make(chan struct{}) // closed when the reconcile pass starts
	release := make(chan struct{}) // test releases the in-flight pass

	var mu sync.Mutex
	var passCompleted bool

	d := &Daemon{
		reconcileNowCh: make(chan struct{}, 1),
	}

	// The hook substitutes for the real reconcileRGState and makes exactly ONE
	// pass observably in-flight: it signals `entered`, blocks until the test
	// closes `release`, then records completion. The loop's startup pass
	// (reconcileRGStateLoop calls reconcileRGStatePass immediately) drives it,
	// so the loop is inside a pass when we cancel ctx and wait.
	var once sync.Once
	d.reconcileTickHook = func() {
		first := false
		once.Do(func() { first = true })
		if !first {
			return // later ticks are no-ops
		}
		close(entered)
		<-release
		mu.Lock()
		passCompleted = true
		mu.Unlock()
	}

	var wg sync.WaitGroup
	ctx, stop := context.WithCancel(context.Background())

	// Production spawn seam — Run() launches the loop through exactly this.
	d.startReconcileRGStateLoop(ctx, &wg)

	// Wait until the loop is inside the (blocked) reconcile pass.
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile pass never started")
	}

	// Mirror runShutdownSequence's ordering: cancel the run/signal ctx, then
	// use wg.Wait() as the barrier before HA ownership cleanup.
	stop()
	wgReturned := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgReturned)
	}()

	// The reconcile pass is STILL in flight (blocked on `release`). Because the
	// loop is joined on the run WaitGroup, wg.Wait() MUST NOT have returned —
	// ownership cleanup cannot begin while a pass could still re-enable
	// forwarding / re-add VIPs. A bare-go (unjoined) loop makes wg.Wait()
	// return immediately here → RED.
	select {
	case <-wgReturned:
		t.Fatal("wg.Wait() returned while a reconcile pass was still in flight — " +
			"reconcile loop not joined before HA ownership cleanup (#5681/M23 regression)")
	case <-time.After(300 * time.Millisecond):
		// Good: the barrier is still holding for the in-flight pass.
	}

	// In production, ownership cleanup begins only once wg.Wait() returns.
	// Release the in-flight pass; the joined loop finishes it, sees ctx.Done,
	// and returns, unblocking wg.Wait().
	close(release)

	select {
	case <-wgReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() did not return after the reconcile pass completed — " +
			"join hung the shutdown barrier")
	}

	mu.Lock()
	done := passCompleted
	mu.Unlock()
	if !done {
		t.Fatal("reconcile pass never recorded completion")
	}
}
