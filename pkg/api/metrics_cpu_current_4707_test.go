package api

import "testing"

// TestParseProcStatCPU verifies the aggregate "cpu " line parses into the
// busy/total tick components the delta computation needs.
func TestParseProcStatCPU(t *testing.T) {
	// cpu user nice system idle iowait irq softirq steal
	got, ok := parseProcStatCPU("cpu 100 5 30 800 10 3 2 0 0 0")
	if !ok {
		t.Fatal("parseProcStatCPU returned ok=false for a valid cpu line")
	}
	if got.userNice != 105 { // user 100 + nice 5
		t.Errorf("userNice = %v, want 105", got.userNice)
	}
	if got.system != 30 {
		t.Errorf("system = %v, want 30", got.system)
	}
	// total = user+nice+system+idle+iowait+irq+softirq+steal
	if got.total != 950 {
		t.Errorf("total = %v, want 950", got.total)
	}

	// Older-kernel short line (no iowait/irq/softirq/steal).
	short, ok := parseProcStatCPU("cpu 100 5 30 800")
	if !ok {
		t.Fatal("parseProcStatCPU returned ok=false for a short cpu line")
	}
	if short.total != 935 { // 100+5+30+800
		t.Errorf("short.total = %v, want 935", short.total)
	}

	// A per-core "cpu0 ..." line or non-cpu line must be rejected so the
	// aggregate scan never folds a per-core row into the aggregate.
	if _, ok := parseProcStatCPU("cpu0 1 2 3 4 5 6 7 8"); ok {
		t.Error("parseProcStatCPU accepted a per-core cpu0 line")
	}
	if _, ok := parseProcStatCPU("intr 12345"); ok {
		t.Error("parseProcStatCPU accepted a non-cpu line")
	}
}

// TestCPUUtilizationIsDeltaNotCumulative is the core #4707 regression guard.
//
// Scenario: the box was hammered at boot then went idle. The cumulative
// since-boot ratio (the pre-#4707 formula, cur.busy/cur.total) still reports
// ~89% busy, but the CURRENT utilization between the two scrapes is only 12%.
// The metric must report the delta, not the cumulative average.
//
// RED-on-revert: reverting updateCPUUtilization to the cumulative form
//
//	userPct = cur.userNice / cur.total * 100 * cpus  // 8010/10100 = 79.3...
//
// yields ~79.3, not 10.0, so the equality assertions below FAIL — proving the
// test actually pins the delta behavior and would catch a regression.
func TestCPUUtilizationIsDeltaNotCumulative(t *testing.T) {
	const cpus = 1.0

	// T1: boot burst — mostly busy. busy = 9000 of 10000 total.
	prev := cpuSample{userNice: 8000, system: 1000, total: 10000}
	// T2: 100 more ticks elapsed, almost all idle. Only 12 busy ticks added
	// (10 user+nice, 2 system) out of 100 total ticks in the interval.
	cur := cpuSample{userNice: 8010, system: 1002, total: 10100}

	userPct, systemPct, ok := cpuUtilization(prev, cur, cpus)
	if !ok {
		t.Fatal("cpuUtilization returned ok=false for advancing counters")
	}

	// Delta: dUserNice=10, dSystem=2, dTotal=100 -> 10% and 2%.
	if userPct != 10.0 {
		t.Errorf("delta userPct = %v, want 10.0", userPct)
	}
	if systemPct != 2.0 {
		t.Errorf("delta systemPct = %v, want 2.0", systemPct)
	}

	// Explicitly prove the delta diverges from the (buggy) cumulative form so
	// a silent revert to since-boot averaging cannot pass this test.
	cumulativeUser := cur.userNice / cur.total * 100 * cpus // ~79.3
	if cumulativeUser == userPct {
		t.Fatalf("cumulative (%v) must differ from delta (%v) for this fixture "+
			"to guard against a revert", cumulativeUser, userPct)
	}
	// The stale cumulative average (~79%) must be far above the true current
	// utilization (10%) — that gap is exactly the #4707 bug this test pins.
	if cumulativeUser < 70 {
		t.Errorf("fixture sanity: cumulative user should be ~79%%, got %v", cumulativeUser)
	}
}

// TestUpdateCPUUtilizationFirstSampleSkips verifies first-scrape handling: with
// no predecessor sample the collector emits nothing (emit=false) rather than a
// bogus value, and the SECOND scrape reports the delta against the first.
func TestUpdateCPUUtilizationFirstSampleSkips(t *testing.T) {
	c := &xpfCollector{} // zero value usable; cpuSampleValid starts false

	first := cpuSample{userNice: 8000, system: 1000, total: 10000}
	if _, _, emit := c.updateCPUUtilization(first, 1.0); emit {
		t.Fatal("first scrape must not emit a CPU sample (no predecessor)")
	}
	if !c.cpuSampleValid {
		t.Fatal("first scrape must record the sample as the predecessor")
	}

	second := cpuSample{userNice: 8010, system: 1002, total: 10100}
	userPct, systemPct, emit := c.updateCPUUtilization(second, 1.0)
	if !emit {
		t.Fatal("second scrape must emit the inter-scrape delta")
	}
	if userPct != 10.0 || systemPct != 2.0 {
		t.Errorf("second scrape delta = (%v, %v), want (10, 2)", userPct, systemPct)
	}
}

// TestCPUUtilizationNoAdvanceOrBackwards verifies the guard against emitting
// bogus values when counters don't advance or go backwards (e.g. a counter
// reset after suspend/hotplug), which would otherwise divide by <= 0.
func TestCPUUtilizationNoAdvanceOrBackwards(t *testing.T) {
	s := cpuSample{userNice: 8000, system: 1000, total: 10000}

	// Identical samples: no elapsed ticks -> skip.
	if _, _, ok := cpuUtilization(s, s, 1.0); ok {
		t.Error("cpuUtilization must skip when totals did not advance")
	}

	// Counters went backwards (reset): skip rather than emit a negative %.
	back := cpuSample{userNice: 10, system: 5, total: 100}
	if _, _, ok := cpuUtilization(s, back, 1.0); ok {
		t.Error("cpuUtilization must skip when counters went backwards")
	}

	// Zero CPUs -> skip (avoids nonsense scaling).
	next := cpuSample{userNice: 8010, system: 1002, total: 10100}
	if _, _, ok := cpuUtilization(s, next, 0); ok {
		t.Error("cpuUtilization must skip when cpus <= 0")
	}
}
