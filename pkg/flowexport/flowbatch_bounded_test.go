package flowexport

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestFlowBatchDropsAboveCap proves the export batch is BOUNDED (#3747):
// once a per-family batch is at capacity, further add()s are dropped
// (drop-newest) and counted rather than growing the slice without bound.
//
// FAIL-ON-REVERT: before #3747 add() appended unconditionally, so the batch
// grew to the full number of records offered (unbounded memory growth) and
// there was no Dropped()/capOverride API at all — the reverted code neither
// compiles this test nor caps the depth.
func TestFlowBatchDropsAboveCap(t *testing.T) {
	const capN = 4
	b := &flowBatch{capOverride: capN}

	// Offer 3x the capN of IPv4 records.
	const offered = capN * 3
	for i := 0; i < offered; i++ {
		b.add(FlowRecord{IsIPv6: false})
	}

	if got := b.depth(); got != capN {
		t.Fatalf("depth after overflow = %d, want capN %d (queue grew past the bound)", got, capN)
	}
	if got := b.Dropped(); got != offered-capN {
		t.Fatalf("Dropped() = %d, want %d (offered %d, capN %d)", got, offered-capN, offered, capN)
	}

	// drain returns exactly the capN-many retained records, then the queue
	// is empty and depth is 0.
	v4, v6 := b.drain()
	if len(v4) != capN || len(v6) != 0 {
		t.Fatalf("drain returned v4=%d v6=%d, want v4=%d v6=0", len(v4), len(v6), capN)
	}
	if got := b.depth(); got != 0 {
		t.Fatalf("depth after drain = %d, want 0", got)
	}
	// Drops are cumulative — draining does not reset the counter.
	if got := b.Dropped(); got != offered-capN {
		t.Fatalf("Dropped() after drain = %d, want %d (must be cumulative)", got, offered-capN)
	}
}

// TestFlowBatchBelowCapNeverDrops proves the happy path (queue below the capN)
// is unchanged: every offered record is retained and nothing is dropped.
func TestFlowBatchBelowCapNeverDrops(t *testing.T) {
	const capN = 8
	b := &flowBatch{capOverride: capN}

	const offered = capN - 1
	for i := 0; i < offered; i++ {
		b.add(FlowRecord{IsIPv6: false})
	}
	if got := b.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d, want 0 for a below-capN workload", got)
	}
	if got := b.depth(); got != offered {
		t.Fatalf("depth = %d, want %d (below-capN workload lost records)", got, offered)
	}
	if got := b.MaxDepth(); got != offered {
		t.Fatalf("MaxDepth() = %d, want %d", got, offered)
	}
	v4, _ := b.drain()
	if len(v4) != offered {
		t.Fatalf("drain returned %d records, want %d", len(v4), offered)
	}
}

// TestFlowBatchCapIsPerFamily proves the v4 and v6 caps are independent: an
// IPv4 overflow does not consume the IPv6 budget (they are split slices).
func TestFlowBatchCapIsPerFamily(t *testing.T) {
	const capN = 3
	b := &flowBatch{capOverride: capN}

	// Overflow v4 while filling v6 to exactly capN (no v6 drop).
	for i := 0; i < capN*2; i++ {
		b.add(FlowRecord{IsIPv6: false})
	}
	for i := 0; i < capN; i++ {
		b.add(FlowRecord{IsIPv6: true})
	}

	if got := b.Dropped(); got != capN {
		t.Fatalf("Dropped() = %d, want %d (only the v4 overflow should drop)", got, capN)
	}
	v4, v6 := b.drain()
	if len(v4) != capN {
		t.Fatalf("v4 retained %d, want %d", len(v4), capN)
	}
	if len(v6) != capN {
		t.Fatalf("v6 retained %d, want %d (v6 must not be starved by the v4 overflow)", len(v6), capN)
	}
}

// TestFlowBatchMaxDepthHighWater proves MaxDepth() captures the peak backlog
// even after a later drain empties the queue — the after-the-fact signal that
// a transient stall built a backlog (#3747).
func TestFlowBatchMaxDepthHighWater(t *testing.T) {
	const capN = 16
	b := &flowBatch{capOverride: capN}

	for i := 0; i < 5; i++ {
		b.add(FlowRecord{IsIPv6: false})
	}
	for i := 0; i < 4; i++ {
		b.add(FlowRecord{IsIPv6: true})
	}
	// Peak combined depth is 9.
	if got := b.MaxDepth(); got != 9 {
		t.Fatalf("MaxDepth() = %d, want 9", got)
	}
	b.drain()
	if got := b.depth(); got != 0 {
		t.Fatalf("depth after drain = %d, want 0", got)
	}
	if got := b.MaxDepth(); got != 9 {
		t.Fatalf("MaxDepth() after drain = %d, want 9 (high-water must survive drain)", got)
	}
}

// TestFlowBatchConcurrentAddDrainBounded exercises the bounded queue under a
// concurrent producer/drain race (run with -race). Every offered record is
// accounted for exactly once — either dropped at capacity or drained — and the
// depth never exceeds 2x capN (per-family capN x two families).
func TestFlowBatchConcurrentAddDrainBounded(t *testing.T) {
	const capPerFamily = 128
	b := &flowBatch{capOverride: capPerFamily}

	const producers = 8
	const perProducer = 4000
	const total = producers * perProducer

	var drained atomic.Uint64
	stop := make(chan struct{})

	var dwg sync.WaitGroup
	dwg.Add(1)
	go func() {
		defer dwg.Done()
		for {
			v4, v6 := b.drain()
			drained.Add(uint64(len(v4) + len(v6)))
			if d := b.depth(); d > 2*capPerFamily {
				t.Errorf("observed depth %d exceeds bound %d", d, 2*capPerFamily)
			}
			select {
			case <-stop:
				// One final drain to sweep whatever landed after the last loop.
				v4, v6 := b.drain()
				drained.Add(uint64(len(v4) + len(v6)))
				return
			default:
			}
		}
	}()

	var pwg sync.WaitGroup
	for p := 0; p < producers; p++ {
		pwg.Add(1)
		go func(p int) {
			defer pwg.Done()
			for i := 0; i < perProducer; i++ {
				b.add(FlowRecord{IsIPv6: (i & 1) == 0})
			}
		}(p)
	}
	pwg.Wait()
	close(stop)
	dwg.Wait()

	// Sweep anything left behind by the drainer's exit race.
	v4, v6 := b.drain()
	drained.Add(uint64(len(v4) + len(v6)))

	if got := drained.Load() + b.Dropped(); got != total {
		t.Fatalf("accounting: drained %d + dropped %d = %d, want total %d",
			drained.Load(), b.Dropped(), got, total)
	}
}

// TestExporterBatchAccessorsSurfaceDrops proves the per-exporter accessors
// (BatchDepth / BatchMaxDepth / BatchDropped) surface the bounded-batch
// counters for BOTH the NetFlow v9 and IPFIX exporters (#3747).
func TestExporterBatchAccessorsSurfaceDrops(t *testing.T) {
	const capN = 2
	const offered = 5

	nf := &Exporter{}
	nf.batch.capOverride = capN
	for i := 0; i < offered; i++ {
		nf.batch.add(FlowRecord{IsIPv6: false})
	}
	if got := nf.BatchDepth(); got != capN {
		t.Fatalf("netflow BatchDepth() = %d, want %d", got, capN)
	}
	if got := nf.BatchMaxDepth(); got != capN {
		t.Fatalf("netflow BatchMaxDepth() = %d, want %d", got, capN)
	}
	if got := nf.BatchDropped(); got != offered-capN {
		t.Fatalf("netflow BatchDropped() = %d, want %d", got, offered-capN)
	}

	ip := &IPFIXExporter{}
	ip.batch.capOverride = capN
	for i := 0; i < offered; i++ {
		ip.batch.add(FlowRecord{IsIPv6: true})
	}
	if got := ip.BatchDepth(); got != capN {
		t.Fatalf("ipfix BatchDepth() = %d, want %d", got, capN)
	}
	if got := ip.BatchDropped(); got != offered-capN {
		t.Fatalf("ipfix BatchDropped() = %d, want %d", got, offered-capN)
	}
}
