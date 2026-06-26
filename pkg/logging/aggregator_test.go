package logging

import (
	"context"
	"fmt"
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
	if agg.maxKeys != defaultMaxAggKeys {
		t.Errorf("expected default maxKeys=%d, got %d", defaultMaxAggKeys, agg.maxKeys)
	}
}

// TestSessionAggregator_CardinalityCap is the #2936 fail-on-revert guard.
// It drives more unique sources AND destinations than the cap through Add()
// and asserts: (1) neither map ever exceeds the cap, (2) the dropped counters
// increment by exactly (offered - cap), and (3) Flush still returns a valid
// top-N over the admitted set. Reverting the cap (unbounded insert) turns this
// RED: the maps grow past the cap and the dropped counters stay 0.
func TestSessionAggregator_CardinalityCap(t *testing.T) {
	const cap = 100
	agg := NewSessionAggregator(time.Hour, 10)
	agg.maxKeys = cap // small cap for the test; production uses defaultMaxAggKeys

	const offered = cap + 250
	for i := 0; i < offered; i++ {
		// Distinct source AND distinct destination per session so both maps
		// are driven past the cap independently.
		agg.Add(EventRecord{
			Type:         "SESSION_CLOSE",
			SrcAddr:      fmt.Sprintf("10.10.%d.%d:1234", i/256, i%256),
			DstAddr:      fmt.Sprintf("10.20.%d.%d:80", i/256, i%256),
			SessionBytes: uint64(i + 1),
		})
	}

	agg.mu.Lock()
	srcLen := len(agg.srcs)
	dstLen := len(agg.dsts)
	droppedSrc := agg.droppedSrc
	droppedDst := agg.droppedDst
	agg.mu.Unlock()

	if srcLen > cap {
		t.Errorf("src map exceeded cap: len=%d cap=%d (cap not enforced)", srcLen, cap)
	}
	if dstLen > cap {
		t.Errorf("dst map exceeded cap: len=%d cap=%d (cap not enforced)", dstLen, cap)
	}
	if srcLen != cap {
		t.Errorf("expected src map at cap=%d, got %d", cap, srcLen)
	}
	if dstLen != cap {
		t.Errorf("expected dst map at cap=%d, got %d", cap, dstLen)
	}
	if want := uint64(offered - cap); droppedSrc != want {
		t.Errorf("droppedSrc=%d, want exactly %d (offered-cap)", droppedSrc, want)
	}
	if want := uint64(offered - cap); droppedDst != want {
		t.Errorf("droppedDst=%d, want exactly %d (offered-cap)", droppedDst, want)
	}

	// Flush must still return a valid, bounded top-N over the admitted set.
	topSrc, topDst, fdSrc, fdDst := agg.flushWithDropped()
	if len(topSrc) != 10 || len(topDst) != 10 {
		t.Errorf("expected top-10 from admitted set, got src=%d dst=%d", len(topSrc), len(topDst))
	}
	if fdSrc != uint64(offered-cap) || fdDst != uint64(offered-cap) {
		t.Errorf("flush dropped counts src=%d dst=%d, want %d", fdSrc, fdDst, offered-cap)
	}
	// top-N must be sorted by bytes descending.
	for i := 1; i < len(topSrc); i++ {
		if topSrc[i-1].Bytes < topSrc[i].Bytes {
			t.Errorf("topSrc not sorted descending at %d", i)
		}
	}

	// Flush resets the dropped counters for the next window.
	agg.mu.Lock()
	resetSrc, resetDst := agg.droppedSrc, agg.droppedDst
	agg.mu.Unlock()
	if resetSrc != 0 || resetDst != 0 {
		t.Errorf("dropped counters not reset after flush: src=%d dst=%d", resetSrc, resetDst)
	}
}

// TestSessionAggregator_BelowCapUnchanged asserts normal-cardinality traffic
// (below the cap) produces identical top-N output with zero dropped keys — the
// common case is behavior-preserving.
func TestSessionAggregator_BelowCapUnchanged(t *testing.T) {
	agg := NewSessionAggregator(time.Hour, 10)
	agg.maxKeys = 100

	// 5 sources, all under the cap, mirroring TestSessionAggregator_TopN-style
	// input. Highest bytes last so ordering is exercised.
	for i := 0; i < 5; i++ {
		agg.Add(EventRecord{
			Type:         "SESSION_CLOSE",
			SrcAddr:      fmt.Sprintf("10.0.1.%d:1234", i+1),
			DstAddr:      "10.0.2.1:80",
			SessionBytes: uint64((i + 1) * 1000),
		})
	}

	topSrc, topDst, droppedSrc, droppedDst := agg.flushWithDropped()
	if droppedSrc != 0 || droppedDst != 0 {
		t.Errorf("below-cap traffic must drop nothing: src=%d dst=%d", droppedSrc, droppedDst)
	}
	if len(topSrc) != 5 {
		t.Fatalf("expected 5 source entries, got %d", len(topSrc))
	}
	if len(topDst) != 1 {
		t.Fatalf("expected 1 destination entry, got %d", len(topDst))
	}
	// Highest-bytes source (10.0.1.5, 5000 bytes) ranks first.
	if topSrc[0].IP != "10.0.1.5" || topSrc[0].Bytes != 5000 {
		t.Errorf("expected top source 10.0.1.5/5000, got %s/%d", topSrc[0].IP, topSrc[0].Bytes)
	}
	if topDst[0].IP != "10.0.2.1" || topDst[0].Sessions != 5 {
		t.Errorf("expected dest 10.0.2.1 with 5 sessions, got %s/%d", topDst[0].IP, topDst[0].Sessions)
	}
}
