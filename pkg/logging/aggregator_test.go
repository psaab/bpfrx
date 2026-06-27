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

// TestSessionAggregator_CardinalityCap is the #2936 bounded-memory guard,
// carried over to the Space-Saving implementation (#3099). It drives more
// unique sources AND destinations than K through Add() and asserts:
// (1) neither counter set ever exceeds K, (2) the overflow (eviction) counters
// increment by exactly (offered - K), and (3) Flush still returns a valid
// top-N. Reverting to an unbounded structure turns this RED: the sets grow past
// K and the overflow counters stay 0.
func TestSessionAggregator_CardinalityCap(t *testing.T) {
	const k = 100
	agg := NewSessionAggregator(time.Hour, 10)
	agg.maxKeys = k // small K for the test; production uses defaultMaxAggKeys

	const offered = k + 250
	for i := 0; i < offered; i++ {
		// Distinct source AND distinct destination per session so both sets
		// are driven past K independently.
		agg.Add(EventRecord{
			Type:         "SESSION_CLOSE",
			SrcAddr:      fmt.Sprintf("10.10.%d.%d:1234", i/256, i%256),
			DstAddr:      fmt.Sprintf("10.20.%d.%d:80", i/256, i%256),
			SessionBytes: uint64(i + 1),
		})
	}

	agg.mu.Lock()
	srcLen := len(agg.srcs.minHeap)
	dstLen := len(agg.dsts.minHeap)
	droppedSrc := agg.srcs.overflow
	droppedDst := agg.dsts.overflow
	agg.mu.Unlock()

	if srcLen > k {
		t.Errorf("src set exceeded K: len=%d K=%d (bound not enforced)", srcLen, k)
	}
	if dstLen > k {
		t.Errorf("dst set exceeded K: len=%d K=%d (bound not enforced)", dstLen, k)
	}
	if srcLen != k {
		t.Errorf("expected src set at K=%d, got %d", k, srcLen)
	}
	if dstLen != k {
		t.Errorf("expected dst set at K=%d, got %d", k, dstLen)
	}
	if want := uint64(offered - k); droppedSrc != want {
		t.Errorf("src overflow=%d, want exactly %d (offered-K)", droppedSrc, want)
	}
	if want := uint64(offered - k); droppedDst != want {
		t.Errorf("dst overflow=%d, want exactly %d (offered-K)", droppedDst, want)
	}

	// Flush must still return a valid, bounded top-N.
	topSrc, topDst, fdSrc, fdDst := agg.flushWithDropped()
	if len(topSrc) != 10 || len(topDst) != 10 {
		t.Errorf("expected top-10, got src=%d dst=%d", len(topSrc), len(topDst))
	}
	if fdSrc != uint64(offered-k) || fdDst != uint64(offered-k) {
		t.Errorf("flush overflow counts src=%d dst=%d, want %d", fdSrc, fdDst, offered-k)
	}
	// top-N must be sorted by bytes descending.
	for i := 1; i < len(topSrc); i++ {
		if topSrc[i-1].Bytes < topSrc[i].Bytes {
			t.Errorf("topSrc not sorted descending at %d", i)
		}
	}

	// Flush resets the overflow counters for the next window.
	agg.mu.Lock()
	resetSrc, resetDst := agg.srcs.overflow, agg.dsts.overflow
	agg.mu.Unlock()
	if resetSrc != 0 || resetDst != 0 {
		t.Errorf("overflow counters not reset after flush: src=%d dst=%d", resetSrc, resetDst)
	}
}

// TestSessionAggregator_LateHeavyHitterArrivalOrder is the #3099 fail-on-revert
// guard for arrival-order independence — the core property Space-Saving buys
// over the old capped-exact-map. It fills the counter set with K light keys
// FIRST (so the set is full), THEN offers a single genuine heavy hitter whose
// first session of the window arrives last. Space-Saving must evict the current
// minimum counter and rank the heavy hitter in the top-K.
//
// Revert to the capped-exact-map aggregator and this goes RED: once the map is
// full, the late heavy hitter is a NEW key, gets dropped, and never ranks — the
// exact arrival-order dependence #3099 fixes.
func TestSessionAggregator_LateHeavyHitterArrivalOrder(t *testing.T) {
	const k = 4
	agg := NewSessionAggregator(time.Hour, k)
	agg.maxKeys = k

	// Fill the set with K light keys (100 bytes each) so it is exactly full.
	for i := 0; i < k; i++ {
		agg.Add(EventRecord{
			Type:         "SESSION_CLOSE",
			SrcAddr:      fmt.Sprintf("10.0.0.%d:1234", i+1),
			DstAddr:      "10.9.9.9:80",
			SessionBytes: 100,
		})
	}

	// The heavy hitter's FIRST session arrives only now — strictly after the
	// set filled. Under the old cap it would be dropped; Space-Saving evicts the
	// minimum (a 100-byte key) and the heavy hitter inherits that floor.
	const heavyIP = "203.0.113.7"
	agg.Add(EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      heavyIP + ":1234",
		DstAddr:      "10.9.9.9:80",
		SessionBytes: 1_000_000,
	})

	topSrc, _ := agg.Flush()

	var found bool
	for _, e := range topSrc {
		if e.IP == heavyIP {
			found = true
			if e.Bytes < 1_000_000 {
				t.Errorf("heavy hitter bytes=%d, want >= 1000000", e.Bytes)
			}
		}
	}
	if !found {
		t.Fatalf("late heavy hitter %s missing from top-K %+v "+
			"(arrival-order dependence — old capped map would drop it)", heavyIP, topSrc)
	}
	// It is the heaviest key in the window, so it must rank first.
	if topSrc[0].IP != heavyIP {
		t.Errorf("expected heavy hitter %s ranked first, got %s", heavyIP, topSrc[0].IP)
	}
}

// TestSessionAggregator_SpaceSavingErrorGuarantee verifies the Space-Saving
// (count, error) bookkeeping invariant on a constructed high-cardinality
// stream: for every monitored key, bytes-bytesErr <= true_bytes <= bytes, and
// the reported byte total never under-estimates the truth. It also checks the
// well-known property that any key with true bytes strictly greater than the
// final minimum counter value MUST be retained (no true heavy hitter is lost).
func TestSessionAggregator_SpaceSavingErrorGuarantee(t *testing.T) {
	const k = 8
	agg := NewSessionAggregator(time.Hour, k)
	agg.maxKeys = k

	// Build a stream with a handful of true heavy hitters interleaved with a
	// long tail of distinct light keys, heavy hitters arriving throughout.
	trueBytes := map[string]uint64{}
	add := func(ip string, b uint64) {
		agg.Add(EventRecord{Type: "SESSION_CLOSE", SrcAddr: ip + ":1", DstAddr: "10.0.0.1:80", SessionBytes: b})
		trueBytes[ip] += b
	}
	heavy := []string{"10.1.1.1", "10.1.1.2", "10.1.1.3"}
	for round := 0; round < 50; round++ {
		// Light tail: a fresh distinct key each round (drives cardinality >> K).
		add(fmt.Sprintf("172.16.%d.%d", round/256, round%256), 10)
		// Heavy hitters keep arriving across the whole window.
		for _, h := range heavy {
			add(h, 1000)
		}
	}

	agg.mu.Lock()
	// Final minimum counter value across the monitored set.
	var minBytes uint64 = ^uint64(0)
	for _, c := range agg.srcs.minHeap {
		if c.bytes < minBytes {
			minBytes = c.bytes
		}
		// Per-key Space-Saving guarantee.
		tb := trueBytes[c.ip]
		if c.bytes < tb {
			t.Errorf("key %s: reported bytes=%d under-estimates true=%d", c.ip, c.bytes, tb)
		}
		if c.bytes-c.bytesErr > tb {
			t.Errorf("key %s: bytes-err=%d exceeds true=%d (error floor violated)",
				c.ip, c.bytes-c.bytesErr, tb)
		}
	}
	monitored := map[string]bool{}
	for _, c := range agg.srcs.minHeap {
		monitored[c.ip] = true
	}
	agg.mu.Unlock()

	// No true heavy hitter (true bytes > final minimum) may be missing.
	for ip, tb := range trueBytes {
		if tb > minBytes && !monitored[ip] {
			t.Errorf("key %s with true bytes=%d > min counter=%d was evicted (Space-Saving violation)",
				ip, tb, minBytes)
		}
	}
	// The three real heavy hitters must all be present and rank at the top.
	for _, h := range heavy {
		if !monitored[h] {
			t.Errorf("true heavy hitter %s not retained", h)
		}
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
