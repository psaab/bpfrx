package logging

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestAggregatorRunFinalFlushOnCancel is the RED-on-revert proof for the #5313
// final flush. aggregator.Run must emit the pending window's accumulated
// SESSION_CLOSE counters when its context is cancelled — the path taken on every
// daemon shutdown AND on every config-churn teardown/replace in applyAggregator.
//
// A long flush interval guarantees the ticker never fires inside the test, so
// the ONLY way the counters can be emitted is the ctx.Done final flush. Revert
// Run to `case <-ctx.Done(): return` (no flush) and this goes RED: the pending
// window is discarded and logFn is never called.
func TestAggregatorRunFinalFlushOnCancel(t *testing.T) {
	sa := NewSessionAggregator(time.Hour, 10) // ticker will not fire in-test

	var mu sync.Mutex
	var msgs []string
	sa.SetLogFunc(func(_ int, msg string) {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
	})

	sa.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.5:1234",
		DstAddr:      "10.0.2.9:80",
		SessionBytes: 4096,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		sa.Run(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}

	mu.Lock()
	got := len(msgs)
	mu.Unlock()
	if got == 0 {
		t.Fatal("expected the final flush to emit the pending window on ctx.Done; " +
			"got 0 messages (counters discarded — the #5313 no-flush teardown bug)")
	}
}

// TestAggregatorRunNoEmptyFlushOnCancel guards the other direction: cancelling an
// aggregator with NO pending counters must emit nothing. flushAndLog already
// suppresses an all-empty report, so the ctx.Done final flush of an empty window
// is a no-op — no spurious RT_FLOW_SESSION_AGGREGATE line on a quiet teardown.
func TestAggregatorRunNoEmptyFlushOnCancel(t *testing.T) {
	sa := NewSessionAggregator(time.Hour, 10)

	var mu sync.Mutex
	var msgs []string
	sa.SetLogFunc(func(_ int, msg string) {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
	})

	// No events added — the window is empty.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		sa.Run(ctx)
		close(done)
	}()

	cancel()
	<-done

	mu.Lock()
	got := len(msgs)
	mu.Unlock()
	if got != 0 {
		t.Fatalf("empty-window teardown must emit nothing; got %d messages", got)
	}
}

// TestAggregatorFlushAndLogNoDoubleEmit guards against a double flush: a ticker
// flush that drains the window followed by the ctx.Done final flush must NOT
// re-emit the window. flushAndLog resets the counters via topAndReset, so the
// second call finds an empty window and returns without emitting. This models
// the "ticker fired, then teardown" race directly.
func TestAggregatorFlushAndLogNoDoubleEmit(t *testing.T) {
	sa := NewSessionAggregator(time.Hour, 10)

	var mu sync.Mutex
	var msgs []string
	sa.SetLogFunc(func(_ int, msg string) {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
	})

	sa.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.5:1234",
		DstAddr:      "10.0.2.9:80",
		SessionBytes: 4096,
	})

	sa.flushAndLog() // ticker-equivalent flush: emits and resets the window
	mu.Lock()
	first := len(msgs)
	mu.Unlock()
	if first == 0 {
		t.Fatal("first flush emitted nothing; expected the top-N report")
	}

	sa.flushAndLog() // teardown-equivalent flush of the now-empty window
	mu.Lock()
	second := len(msgs)
	mu.Unlock()
	if second != first {
		t.Fatalf("second flush re-emitted an already-drained window: %d -> %d messages "+
			"(double/empty flush)", first, second)
	}
}
