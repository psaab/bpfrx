package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// TestApplyAggregatorRegistersExactlyOneCallback is the RED-on-revert proof for
// #4964: applyAggregator must register its session-aggregation EventReader
// callback exactly ONCE regardless of how many report-enabled commits run.
//
// Before the fix applyAggregator called er.AddCallback(agg.HandleEvent) on
// every report-enabled reconcile. The EventReader callback list is append-only
// (ringbuf.go exposes only the all-or-nothing ClearCallbacks), so N commits
// leaked N callbacks, each feeding a stale never-flushed aggregator, and every
// event was then dispatched to all N — an unbounded per-event cost and memory
// leak over the daemon's lifetime.
//
// Reverting to the per-call AddCallback makes CallbackCount grow by one per
// apply, so this test fails at the very first assertion below.
func TestApplyAggregatorRegistersExactlyOneCallback(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}

	cfg := &config.Config{}
	cfg.Security.Log.Report = true

	const cycles = 50
	for i := 0; i < cycles; i++ {
		d.applyAggregator(er, cfg)
		if got := er.CallbackCount(); got != 1 {
			t.Fatalf("after %d report-enabled applies the EventReader must carry "+
				"exactly one aggregation callback; got %d (append-only leak: the "+
				"pre-#4964 per-apply AddCallback)", i+1, got)
		}
		if d.aggregatorPtr.Load() == nil {
			t.Fatalf("apply %d: report enabled must publish a live aggregator", i+1)
		}
	}

	// Stop the last running Run goroutine so the test does not leak it.
	t.Cleanup(func() {
		if d.aggCancel != nil {
			d.aggCancel()
		}
	})
}

// TestApplyAggregatorDisableClearsPointerKeepsCallback verifies the disable
// path: turning reporting off retires the live aggregator (nil pointer, so the
// stable callback becomes a no-op and no further events are accumulated) while
// leaving the single registered callback in place. Re-enabling must NOT add a
// second callback.
func TestApplyAggregatorDisableClearsPointerKeepsCallback(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}

	enabled := &config.Config{}
	enabled.Security.Log.Report = true
	disabled := &config.Config{} // Report defaults false

	// Enable: one callback, live aggregator.
	d.applyAggregator(er, enabled)
	if got := er.CallbackCount(); got != 1 {
		t.Fatalf("enable: expected 1 callback, got %d", got)
	}
	if d.aggregatorPtr.Load() == nil {
		t.Fatal("enable: expected a live aggregator pointer")
	}

	// Disable: pointer nil-ed, callback retained (stable, now a no-op).
	d.applyAggregator(er, disabled)
	if got := er.CallbackCount(); got != 1 {
		t.Fatalf("disable: the stable callback must remain (no per-apply churn); got %d", got)
	}
	if d.aggregatorPtr.Load() != nil {
		t.Fatal("disable: aggregator pointer must be nil so the callback is a no-op")
	}
	if d.aggCancel != nil {
		t.Fatal("disable: the Run cancel func must be cleared")
	}

	// Re-enable: still exactly one callback (aggCBOnce), fresh live aggregator.
	d.applyAggregator(er, enabled)
	if got := er.CallbackCount(); got != 1 {
		t.Fatalf("re-enable: still exactly one callback (aggCBOnce); got %d", got)
	}
	if d.aggregatorPtr.Load() == nil {
		t.Fatal("re-enable: expected a live aggregator pointer")
	}

	t.Cleanup(func() {
		if d.aggCancel != nil {
			d.aggCancel()
		}
	})
}
