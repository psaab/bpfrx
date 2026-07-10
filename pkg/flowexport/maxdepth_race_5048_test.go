package flowexport

import (
	"sync"
	"testing"
	"time"
)

// TestFlowBatchMaxDepthMonotonicUnderConcurrentAdds proves the batch
// high-water mark cannot regress when two adders race in the max-update
// window (#5048).
//
// The high-water update runs OUTSIDE the batch mutex (like the dropped /
// handoffDropped atomics). Before the fix it was a plain load-then-store:
//
//	if depth > b.maxDepth.Load() { b.maxDepth.Store(depth) }
//
// Two adders can interleave there: A observes depth 1 and B observes depth 2,
// both Load 0 and pass the compare, then B stores 2 and A's later store of 1
// clobbers it — the published maximum regresses from 2 to 1 even though a
// depth of 2 was really reached.
//
// FAIL-ON-REVERT: this test uses maxDepthHook to hold BOTH updaters at the
// point right after they Load 0, then releases the higher-depth updater first
// and the lower-depth updater second — forcing exactly the reverse-order store
// that regresses the mark. With the racy load-then-store the final MaxDepth()
// is 1 and the assertion fires; with the CAS-max loop the lower store's
// CompareAndSwap fails, it re-reads 2, and 1 <= 2 stops the loop, so the mark
// stays 2. There is no -race data race either way (both ops are atomic); the
// defect is a lost update, so the proof is a wrong (regressed) maximum.
func TestFlowBatchMaxDepthMonotonicUnderConcurrentAdds(t *testing.T) {
	const (
		loDepth = uint64(1) // first adder to acquire mu -> len 1
		hiDepth = uint64(2) // second adder to acquire mu -> len 2
	)

	b := &flowBatch{}

	loadedLo := make(chan struct{})
	loadedHi := make(chan struct{})
	releaseLo := make(chan struct{})
	releaseHi := make(chan struct{})
	var loOnce, hiOnce sync.Once

	// Gate each updater exactly once, on its FIRST pass through the CAS loop
	// (after Load, before CompareAndSwap). Retries (which only happen on the
	// fixed code, after a losing CAS) must NOT block, so sync.Once is used.
	b.maxDepthHook = func(depth uint64) {
		switch depth {
		case hiDepth:
			hiOnce.Do(func() {
				close(loadedHi)
				<-releaseHi
			})
		case loDepth:
			loOnce.Do(func() {
				close(loadedLo)
				<-releaseLo
			})
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); b.add(FlowRecord{}) }()
	go func() { defer wg.Done(); b.add(FlowRecord{}) }()

	// Both adders have appended under mu (so one observed depth 1 and the other
	// depth 2) and are now parked in the CAS loop having each Loaded maxDepth==0.
	waitClosed(t, loadedLo, "lo updater never reached the max-update barrier")
	waitClosed(t, loadedHi, "hi updater never reached the max-update barrier")

	if got := b.MaxDepth(); got != 0 {
		t.Fatalf("MaxDepth() = %d before any store, want 0 (both updaters should still be parked)", got)
	}

	// Release the HIGHER depth first: it publishes 2.
	close(releaseHi)
	// Wait for the high-water to actually reach 2 so the lower store races in
	// AFTER it — the exact reverse-order interleave the bug needs.
	deadline := time.Now().Add(2 * time.Second)
	for b.MaxDepth() != hiDepth {
		if time.Now().After(deadline) {
			t.Fatalf("hi updater never published depth %d (MaxDepth=%d)", hiDepth, b.MaxDepth())
		}
	}
	// Now release the LOWER depth: a racy store would clobber 2 with 1.
	close(releaseLo)

	wg.Wait()

	if got := b.MaxDepth(); got != hiDepth {
		t.Fatalf("MaxDepth() = %d after reverse-order stores, want %d: "+
			"the high-water mark regressed — the lower late store clobbered the higher one (#5048)",
			got, hiDepth)
	}
}

// TestFlowBatchMaxDepthConcurrentStress hammers the high-water path with many
// concurrent adders (no drain) under -race. Every record is retained, so the
// true peak equals the number of adders; MaxDepth() must equal it. This
// exercises the real CAS-max loop under contention and, together with -race,
// guards the update against both a lost update (wrong max) and any future data
// race on maxDepth. It complements the deterministic barrier test above.
func TestFlowBatchMaxDepthConcurrentStress(t *testing.T) {
	const adders = 256
	b := &flowBatch{capOverride: adders} // large enough that nothing is dropped

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(adders)
	for i := 0; i < adders; i++ {
		go func() {
			defer wg.Done()
			<-start
			b.add(FlowRecord{})
		}()
	}
	close(start)
	wg.Wait()

	if got := b.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d, want 0 (cap %d should hold every record)", got, adders)
	}
	if got := b.depth(); got != adders {
		t.Fatalf("depth() = %d, want %d (all records retained)", got, adders)
	}
	if got := b.MaxDepth(); got != adders {
		t.Fatalf("MaxDepth() = %d, want %d: high-water regressed under concurrent adds (#5048)", got, adders)
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(msg)
	}
}
