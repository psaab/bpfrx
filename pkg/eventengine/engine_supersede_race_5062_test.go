package eventengine

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// #5062 — supersede must not lose an already-accepted action to a racing
// producer.
//
// HandleEvent evaluates under e.mu but RELEASES it before enqueue, so many
// RPM-probe goroutines run enqueue concurrently. When the bounded queue is full,
// enqueue falls into supersede, which DRAINS the accepted actions into a private
// slice (opening slots) then best-effort re-enqueues the survivors. Before the
// fix there was no producer-side lock, so a second concurrent producer could
// take a slot the drain had just freed, forcing supersede's refill `default`
// branch to DROP a survivor — an already-accepted action for a DIFFERENT policy
// — losing it and its FIFO position (miscounted droppedQueueFull).
//
// The fix serializes ALL producer-side queue mutation under e.enqueueMu, so the
// drain->re-enqueue is atomic w.r.t. other producers. This file has two tests:
//
//   (a) TestSupersede_ConcurrentProducersConserveSurvivors — a realistic
//       concurrent-producer barrier: N goroutines each enqueue a DISTINCT
//       new-policy action against a full queue, hammering supersede
//       concurrently. INVARIANT: the already-accepted survivors are conserved
//       exactly once, in FIFO order.
//   (b) TestSupersede_DrainStealWindowIsClosed — a DETERMINISTIC reproduction of
//       the exact drain->steal->drop window using the afterDrainFn seam.
//
// RED-ON-REVERT: remove the e.enqueueMu Lock/Unlock in enqueue (restoring the
// lock-free producer path) and both tests go RED — a survivor is dropped, so the
// drained queue no longer contains every seed exactly once in order.

// fillSeeds pushes actionQueueDepth distinct "seedNN" actions onto the queue in
// FIFO order (worker NOT running, so nothing is consumed) and returns their
// names in order. It writes the channel + queueDepth exactly as enqueue would.
func fillSeeds(t *testing.T, e *Engine) []string {
	t.Helper()
	names := make([]string, 0, actionQueueDepth)
	for i := 0; i < actionQueueDepth; i++ {
		name := fmt.Sprintf("seed%02d", i)
		select {
		case e.actions <- plannedAction{policyName: name}:
			e.counters.queueDepth.Add(1)
		default:
			t.Fatalf("could not seed slot %d: queue unexpectedly full", i)
		}
		names = append(names, name)
	}
	return names
}

// drainNames non-blockingly drains the whole queue and returns the names in
// dequeue (FIFO) order, keeping queueDepth consistent.
func drainNames(e *Engine) []string {
	got := make([]string, 0, actionQueueDepth)
	for {
		select {
		case a := <-e.actions:
			e.counters.queueDepth.Add(-1)
			got = append(got, a.policyName)
		default:
			return got
		}
	}
}

// assertSeedsIntact verifies the queue holds EXACTLY the seeds, each once, in
// the original FIFO order — the conservation + ordering invariant for actions
// that were accepted before a burst of unfittable distinct-policy arrivals.
func assertSeedsIntact(t *testing.T, e *Engine, want []string) {
	t.Helper()
	got := drainNames(e)
	if len(got) != len(want) {
		t.Fatalf("conservation violated: drained %d actions, want %d (a survivor was dropped, #5062)\n got=%v\nwant=%v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("FIFO/conservation violated at index %d: got %q, want %q (#5062)\n got=%v\nwant=%v",
				i, got[i], want[i], got, want)
		}
	}
}

// TestSupersede_ConcurrentProducersConserveSurvivors saturates the bounded queue
// with distinct-policy actions, then fires many concurrent producers (each a
// DISTINCT new policy, so each is genuinely unfittable and must be dropped
// without evicting any survivor) straight at supersede. Every round asserts the
// original survivors are conserved exactly once in FIFO order. Run under -race.
func TestSupersede_ConcurrentProducersConserveSurvivors(t *testing.T) {
	e := New(nil, nil) // nil store/commitFn + enqueue called directly: worker never starts
	defer e.Close()

	const (
		producers = 64
		rounds    = 40
	)

	for round := 0; round < rounds; round++ {
		// Establish a clean full queue of the seeds in order at the top of each
		// round (drain whatever the previous round left, then refill).
		drainNames(e)
		want := fillSeeds(t, e)

		// Barrier: all producers unblock together to maximize the chance of an
		// interleaved drain/refill hitting the race window on buggy code.
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(producers)
		for p := 0; p < producers; p++ {
			go func(id int) {
				defer wg.Done()
				<-start
				// A DISTINCT new policy: no same-policy entry to supersede, so
				// this arrival is unfittable and must be dropped WITHOUT evicting
				// a survivor.
				e.enqueue(plannedAction{policyName: fmt.Sprintf("r%02d_new%03d", round, id)})
			}(p)
		}
		close(start)
		wg.Wait()

		// After a burst of unfittable distinct arrivals, the queue must still be
		// exactly the seeds in FIFO order — no survivor lost, none duplicated.
		if got := int(e.counters.queueDepth.Load()); got != actionQueueDepth {
			t.Fatalf("round %d: queueDepth=%d; want %d (a survivor was dropped or an arrival leaked in, #5062)",
				round, got, actionQueueDepth)
		}
		assertSeedsIntact(t, e, want)
	}
}

// TestSupersede_DrainStealWindowIsClosed deterministically drives the exact
// drain->steal->drop window. Producer A enters supersede and drains the full
// queue; at the drain->re-enqueue boundary (afterDrainFn) a SECOND producer B
// tries to enqueue a distinct "steal" action into the freed slots. Before the
// fix, B's lock-free fast-path send lands "steal" in the emptied channel, so A's
// re-enqueue overflows and drops a seed (survivor). With the fix, B blocks on
// enqueueMu until A finishes re-enqueuing every survivor, so no seed is lost and
// B's own (still unfittable) "steal" is dropped cleanly afterward.
//
// RED-ON-REVERT: drop the enqueueMu Lock/Unlock in enqueue and this test goes
// RED — a seed is missing from the drained queue (B stole its slot).
func TestSupersede_DrainStealWindowIsClosed(t *testing.T) {
	e := New(nil, nil)
	defer e.Close()

	want := fillSeeds(t, e)

	bDone := make(chan struct{})
	var once sync.Once
	e.afterDrainFn = func() {
		// Inject the concurrent producer exactly once, at A's drain->re-enqueue
		// boundary. In production afterDrainFn is nil.
		once.Do(func() {
			go func() {
				// B attempts to take a drain-freed slot. Fixed: blocks on
				// enqueueMu until A releases. Buggy: fast-path send succeeds into
				// the emptied channel and steals a survivor's slot.
				e.enqueue(plannedAction{policyName: "steal"})
				close(bDone)
			}()
			// Give B a chance to land its steal (buggy path completes fast). On
			// the fixed path B is parked on enqueueMu and bDone never fires here,
			// so we time out and let A finish re-enqueuing all survivors first.
			select {
			case <-bDone:
			case <-time.After(300 * time.Millisecond):
			}
		})
	}

	// Producer A: the queue is full, so this drives supersede -> afterDrainFn.
	e.enqueue(plannedAction{policyName: "A_new"})

	// Let B finish (fixed path: it runs after A released the lock).
	select {
	case <-bDone:
	case <-time.After(5 * time.Second):
		t.Fatal("injected producer B never completed")
	}

	// The queue must still hold exactly the seeds in FIFO order. Neither the
	// unfittable "steal" nor "A_new" may have displaced a survivor.
	if got := int(e.counters.queueDepth.Load()); got != actionQueueDepth {
		t.Fatalf("queueDepth=%d; want %d (a survivor was stolen, #5062)", got, actionQueueDepth)
	}
	got := drainNames(e)
	if len(got) != len(want) {
		t.Fatalf("conservation violated: drained %d, want %d (survivor stolen in drain->re-enqueue window, #5062)\n got=%v\nwant=%v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("survivor lost/reordered at index %d: got %q want %q (#5062)\n got=%v\nwant=%v",
				i, got[i], want[i], got, want)
		}
	}
	for _, n := range got {
		if n == "steal" || n == "A_new" {
			t.Fatalf("unfittable arrival %q displaced a survivor (#5062)", n)
		}
	}
}
