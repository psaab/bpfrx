package flowexport

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// TestFlowBatchRetiredAddIsCountedNotStranded is the RED-on-revert proof for
// #4963. A session-close callback can load the pre-reconcile exporter bundle
// just before the reconcile publishes the new one, then call ExportSessionClose
// -> batch.add() AFTER the old exporter's Run did its final flush and returned.
// Without the admission lease that record is silently appended into a batch
// nothing will ever drain again — permanently stranded, with Dropped()/depth
// looking healthy.
//
// After the fix, an add() offered to a retired batch is REJECTED and counted in
// the distinct handoffDropped counter (NOT the cap Dropped counter) and is NOT
// appended. Reverting the retired check in add() re-appends the record: depth
// becomes 2 and HandoffDropped stays 0, failing this test.
func TestFlowBatchRetiredAddIsCountedNotStranded(t *testing.T) {
	var b flowBatch

	// Pre-retire add is accepted normally.
	b.add(FlowRecord{})
	if got := b.depth(); got != 1 {
		t.Fatalf("pre-retire add: depth = %d, want 1", got)
	}

	// The owning exporter's generation is being torn down (bundle swapped, final
	// flush imminent). Everything offered from here is a late, post-final-flush
	// handoff.
	b.retire()

	b.add(FlowRecord{})
	if got := b.HandoffDropped(); got != 1 {
		t.Fatalf("retired add must increment handoffDropped; got %d "+
			"(0 = reverted admission lease: record silently stranded)", got)
	}
	if got := b.depth(); got != 1 {
		t.Fatalf("retired add must NOT append (would strand the record); depth = %d, want 1", got)
	}
	if got := b.Dropped(); got != 0 {
		t.Fatalf("handoff reject must be a DISTINCT counter, not the cap Dropped "+
			"counter; Dropped() = %d, want 0", got)
	}
}

// TestFlowBatchSharedHandoffCounter proves the injected fixed-cardinality
// family counter (SetHandoffCounter) is also incremented on a handoff reject,
// so the daemon can surface drops on an exporter that has already left the live
// bundle (#4963).
func TestFlowBatchSharedHandoffCounter(t *testing.T) {
	var family atomic.Uint64
	var b flowBatch
	b.setSharedHandoff(&family)

	b.retire()
	b.add(FlowRecord{})
	b.add(FlowRecord{IsIPv6: true})

	if got := b.HandoffDropped(); got != 2 {
		t.Fatalf("local handoffDropped = %d, want 2", got)
	}
	if got := family.Load(); got != 2 {
		t.Fatalf("injected family counter = %d, want 2 (drops on a retired "+
			"exporter must survive at fixed cardinality)", got)
	}
}

// TestFlowBatchRetireWaitsForInflightAdmit proves the second half of the fix:
// retirement MUST wait for a callback that already acquired the admission lease
// before the final flush, so that record still lands in the batch the final
// flush drains. The inflightHook holds an add() inside the lease while a
// concurrent retire() runs; retire must not return until the held add()
// completes AND the record must be appended (not rejected).
func TestFlowBatchRetireWaitsForInflightAdmit(t *testing.T) {
	var b flowBatch

	entered := make(chan struct{})
	release := make(chan struct{})
	b.inflightHook = func() {
		close(entered)
		<-release
	}

	addDone := make(chan struct{})
	go func() {
		b.add(FlowRecord{}) // acquires the lease, then blocks in the hook
		close(addDone)
	}()

	<-entered // the add() has passed the retired gate and holds the lease

	retireReturned := make(chan struct{})
	go func() {
		b.retire() // must block until the in-flight add() finishes
		close(retireReturned)
	}()

	// retire() must still be blocked while the admitted add() is in flight.
	select {
	case <-retireReturned:
		t.Fatal("retire() returned while an admitted add() was still in flight — " +
			"the record could be dropped by the final flush (silent strand)")
	case <-time.After(50 * time.Millisecond):
	}

	close(release) // let the admitted add() finish

	select {
	case <-addDone:
	case <-time.After(time.Second):
		t.Fatal("admitted add() never completed")
	}
	select {
	case <-retireReturned:
	case <-time.After(time.Second):
		t.Fatal("retire() never returned after the in-flight add() completed")
	}

	// The admitted record was appended (it will be drained by the final flush),
	// and it was NOT counted as a handoff drop.
	if got := b.depth(); got != 1 {
		t.Fatalf("admitted-before-retire record must be in the batch; depth = %d, want 1", got)
	}
	if got := b.HandoffDropped(); got != 0 {
		t.Fatalf("an add() admitted before retire must not be a handoff drop; got %d", got)
	}
}

// TestExporterHandoffRejectThroughExportSessionClose exercises the full
// ExportSessionClose -> batch.add path on a retired exporter for both the
// NetFlow v9 and IPFIX exporters, and confirms the per-exporter and injected
// family counters both increment while nothing is stranded (#4963).
func TestExporterHandoffRejectThroughExportSessionClose(t *testing.T) {
	rec := logging.EventRecord{Type: "SESSION_CLOSE"}

	t.Run("netflow", func(t *testing.T) {
		var family atomic.Uint64
		e := &Exporter{} // zero exporter: no conns, Run never started
		e.SetHandoffCounter(&family)
		e.Retire()
		e.ExportSessionClose(rec, SessionCloseData{})
		if got := e.HandoffDropped(); got != 1 {
			t.Fatalf("netflow HandoffDropped() = %d, want 1", got)
		}
		if got := family.Load(); got != 1 {
			t.Fatalf("netflow family counter = %d, want 1", got)
		}
		if got := e.BatchDepth(); got != 0 {
			t.Fatalf("netflow retired close must not be batched; BatchDepth() = %d, want 0", got)
		}
	})

	t.Run("ipfix", func(t *testing.T) {
		var family atomic.Uint64
		e := &IPFIXExporter{}
		e.SetHandoffCounter(&family)
		e.Retire()
		e.ExportSessionClose(rec, SessionCloseData{})
		if got := e.HandoffDropped(); got != 1 {
			t.Fatalf("ipfix HandoffDropped() = %d, want 1", got)
		}
		if got := family.Load(); got != 1 {
			t.Fatalf("ipfix family counter = %d, want 1", got)
		}
		if got := e.BatchDepth(); got != 0 {
			t.Fatalf("ipfix retired close must not be batched; BatchDepth() = %d, want 0", got)
		}
	})
}

// TestFlowBatchConcurrentRetireNeverSilentlyLoses is a race-detector stress on
// the invariant that matters: under concurrent add()/retire(), EVERY offered
// record is either in the batch (will be flushed) or counted as a handoff drop
// — never silently lost. Run with -race.
func TestFlowBatchConcurrentRetireNeverSilentlyLoses(t *testing.T) {
	var b flowBatch
	const n = 200

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			b.add(FlowRecord{})
		}()
	}
	// Retire concurrently with the adds.
	go b.retire()
	wg.Wait()
	// retire() may have been called before all adds; call it again to ensure
	// the terminal state is retired and drained, then account.
	b.retire()

	batched := b.depth()
	dropped := b.HandoffDropped()
	if batched+dropped != n {
		t.Fatalf("accounting: batched %d + handoffDropped %d = %d, want %d "+
			"(a record was silently lost)", batched, dropped, batched+dropped, n)
	}
}
