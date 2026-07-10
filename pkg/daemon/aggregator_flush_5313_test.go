package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// TestApplyAggregatorEqualityGateKeepsLiveAggregator is the RED-on-revert proof
// for the #5313 equality gate. A report-enabled re-apply whose derived config is
// UNCHANGED must keep the SAME live aggregator running — not cancel+replace it —
// so the pending flush window (up to ~5 min of SESSION_CLOSE counters) survives.
//
// Revert applyAggregator to the pre-#5313 cancel+replace-on-every-call body and
// this goes RED twice: the second apply publishes a fresh aggregator instance
// (pointer identity changes) and the pending window is discarded (empty Flush).
func TestApplyAggregatorEqualityGateKeepsLiveAggregator(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}

	cfg := &config.Config{}
	cfg.Security.Log.Report = true

	// Generation 1.
	d.applyAggregator(er, cfg)
	agg1 := d.aggregatorPtr.Load()
	if agg1 == nil {
		t.Fatal("enable must publish a live aggregator")
	}

	// Accumulate a pending window through the production callback path (the same
	// stable callback the EventReader dispatches to).
	d.aggregationCallback(logging.EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.5:1234",
		DstAddr:      "10.0.2.9:80",
		SessionBytes: 4096,
	}, nil)

	// Re-apply with byte-identical config: the equality gate must keep the live
	// aggregator instance.
	d.applyAggregator(er, cfg)
	agg2 := d.aggregatorPtr.Load()
	if agg2 != agg1 {
		t.Fatal("unchanged report-enabled re-apply must keep the SAME live aggregator " +
			"(equality gate); got a replacement (pre-#5313 cancel+replace-every-call)")
	}

	// And the pending window must still be there.
	topSrc, _ := agg2.Flush()
	if len(topSrc) != 1 || topSrc[0].IP != "10.0.1.5" {
		t.Fatalf("pending window not preserved across unchanged re-apply: %+v "+
			"(a replacement would start from an empty window)", topSrc)
	}

	t.Cleanup(func() {
		if d.aggCancel != nil {
			d.aggCancel()
		}
	})
}

// TestApplyAggregatorConfigChangeFlushesPendingWindow is the RED-on-revert proof
// for the #5313 final flush, driven through the daemon teardown path. Turning
// reporting OFF is a genuine config change: applyAggregator retires the live
// aggregator by cancelling its context, which must trigger aggregator.Run's
// final flush so the pending window is EMITTED before the goroutine returns.
//
// Revert aggregator.Run to `case <-ctx.Done(): return` (no final flush) and this
// goes RED: the disable cancels the context and the pending SESSION_CLOSE
// counters are silently discarded — logFn is never called and the poll times out.
func TestApplyAggregatorConfigChangeFlushesPendingWindow(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}

	enabled := &config.Config{}
	enabled.Security.Log.Report = true
	disabled := &config.Config{} // Report defaults false

	d.applyAggregator(er, enabled)
	agg := d.aggregatorPtr.Load()
	if agg == nil {
		t.Fatal("enable must publish a live aggregator")
	}

	// Redirect the live aggregator's report sink to a capturing sink so the
	// teardown flush is observable (the default sink is er.ForwardLogMsg, which
	// goes nowhere with a client-less EventReader). SetLogFunc is mutex-guarded.
	var mu sync.Mutex
	var msgs []string
	agg.SetLogFunc(func(_ int, msg string) {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
	})

	// Pending window: one SESSION_CLOSE through the production callback path.
	d.aggregationCallback(logging.EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.5:1234",
		DstAddr:      "10.0.2.9:80",
		SessionBytes: 4096,
	}, nil)

	// Disable: config CHANGED -> retire the aggregator. Its ctx is cancelled,
	// which must flush the pending window (#5313) before Run returns.
	d.applyAggregator(er, disabled)
	if d.aggregatorPtr.Load() != nil {
		t.Fatal("disable must nil the published aggregator pointer")
	}

	// The teardown flush runs in the retiring Run goroutine (async). Poll for it.
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		got := len(msgs)
		mu.Unlock()
		if got > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("config change tore down the aggregator without flushing the " +
				"pending window: the #5313 counters were discarded on ctx.Done")
		case <-time.After(5 * time.Millisecond):
		}
	}
}
