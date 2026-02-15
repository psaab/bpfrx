package logging

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSessionAggregator_Add(t *testing.T) {
	agg := NewSessionAggregator(time.Hour, 10) // long interval, manual flush

	// SESSION_OPEN should be ignored
	agg.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "10.0.1.1:1234", DstAddr: "10.0.2.1:80"})
	topSrc, topDst := agg.Flush()
	if len(topSrc) != 0 || len(topDst) != 0 {
		t.Error("SESSION_OPEN should not add entries")
	}

	// SESSION_CLOSE should be tracked
	agg.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.5:1234",
		DstAddr:      "10.0.2.1:80",
		SessionBytes: 1000,
	})
	agg.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.5:1235",
		DstAddr:      "10.0.2.1:443",
		SessionBytes: 2000,
	})
	agg.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.10:5000",
		DstAddr:      "10.0.2.1:80",
		SessionBytes: 500,
	})

	topSrc, topDst = agg.Flush()

	// Check sources
	if len(topSrc) != 2 {
		t.Fatalf("expected 2 source entries, got %d", len(topSrc))
	}
	// First entry should be 10.0.1.5 (3000 bytes)
	if topSrc[0].IP != "10.0.1.5" {
		t.Errorf("expected top source 10.0.1.5, got %s", topSrc[0].IP)
	}
	if topSrc[0].Sessions != 2 {
		t.Errorf("expected 2 sessions, got %d", topSrc[0].Sessions)
	}
	if topSrc[0].Bytes != 3000 {
		t.Errorf("expected 3000 bytes, got %d", topSrc[0].Bytes)
	}

	// Check destinations
	if len(topDst) != 1 {
		t.Fatalf("expected 1 destination entry, got %d", len(topDst))
	}
	if topDst[0].IP != "10.0.2.1" {
		t.Errorf("expected top dest 10.0.2.1, got %s", topDst[0].IP)
	}
	if topDst[0].Sessions != 3 {
		t.Errorf("expected 3 sessions, got %d", topDst[0].Sessions)
	}
}

func TestSessionAggregator_FlushResets(t *testing.T) {
	agg := NewSessionAggregator(time.Hour, 10)

	agg.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.1:1234",
		DstAddr:      "10.0.2.1:80",
		SessionBytes: 100,
	})

	topSrc, _ := agg.Flush()
	if len(topSrc) != 1 {
		t.Fatal("expected 1 entry before reset")
	}

	// After flush, counters should be reset
	topSrc, topDst := agg.Flush()
	if len(topSrc) != 0 || len(topDst) != 0 {
		t.Error("expected empty entries after flush")
	}
}

func TestSessionAggregator_TopN(t *testing.T) {
	agg := NewSessionAggregator(time.Hour, 3) // top-3 only

	// Add 5 different sources
	for i := 0; i < 5; i++ {
		agg.Add(EventRecord{
			Type:         "SESSION_CLOSE",
			SrcAddr:      "10.0.1." + string(rune('1'+i)) + ":1234",
			DstAddr:      "10.0.2.1:80",
			SessionBytes: uint64((i + 1) * 1000),
		})
	}

	topSrc, _ := agg.Flush()
	if len(topSrc) != 3 {
		t.Fatalf("expected 3 entries (topN=3), got %d", len(topSrc))
	}
	// Should be sorted by bytes descending
	if topSrc[0].Bytes < topSrc[1].Bytes {
		t.Error("entries should be sorted by bytes descending")
	}
}

func TestSessionAggregator_IPv6(t *testing.T) {
	agg := NewSessionAggregator(time.Hour, 10)

	agg.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "[2001:db8::1]:1234",
		DstAddr:      "[2001:db8::2]:80",
		SessionBytes: 5000,
	})

	topSrc, topDst := agg.Flush()
	if len(topSrc) != 1 {
		t.Fatal("expected 1 IPv6 source")
	}
	if topSrc[0].IP != "2001:db8::1" {
		t.Errorf("expected IPv6 source 2001:db8::1, got %s", topSrc[0].IP)
	}
	if topDst[0].IP != "2001:db8::2" {
		t.Errorf("expected IPv6 dest 2001:db8::2, got %s", topDst[0].IP)
	}
}

func TestSessionAggregator_Run(t *testing.T) {
	agg := NewSessionAggregator(50*time.Millisecond, 10)

	var mu sync.Mutex
	var logged []string
	agg.SetLogFunc(func(severity int, msg string) {
		mu.Lock()
		logged = append(logged, msg)
		mu.Unlock()
	})

	agg.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.1:1234",
		DstAddr:      "10.0.2.1:80",
		SessionBytes: 100,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go agg.Run(ctx)

	// Wait for flush
	time.Sleep(200 * time.Millisecond)
	cancel()

	mu.Lock()
	count := len(logged)
	mu.Unlock()

	if count == 0 {
		t.Error("expected at least one aggregate log line after flush interval")
	}
}

func TestSessionAggregator_HandleEvent(t *testing.T) {
	agg := NewSessionAggregator(time.Hour, 10)

	// Use HandleEvent as a callback
	agg.HandleEvent(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.1:1234",
		DstAddr:      "10.0.2.1:80",
		SessionBytes: 100,
	}, nil)

	topSrc, _ := agg.Flush()
	if len(topSrc) != 1 {
		t.Error("HandleEvent should have added entry")
	}
}

func TestSessionAggregator_Defaults(t *testing.T) {
	agg := NewSessionAggregator(0, 0)
	if agg.flushInterval != 5*time.Minute {
		t.Errorf("expected default 5min interval, got %v", agg.flushInterval)
	}
	if agg.topN != 10 {
		t.Errorf("expected default topN=10, got %d", agg.topN)
	}
}
