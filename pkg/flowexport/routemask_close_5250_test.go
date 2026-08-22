package flowexport

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// #5250 (A9 F3). routeMaskCache scheduled background netlink FIB lookups from
// the session-close callback and had NO stop signal of any kind — no ctx, no
// Close method, and NewRouteMaskResolver returned only a bare closure, so the
// exporter that owned the cache could not have stopped it even if it wanted to.
// A blocking RTM_GETROUTE could therefore be STARTED after the exporter had
// been torn down.
//
// The absolute guarantee is the one this test pins: after Close returns, no
// FURTHER lookup is ever scheduled.
func TestRouteMaskCacheCloseSchedulesNoFurtherLookups(t *testing.T) {
	var started atomic.Int64
	done := make(chan struct{}, 16)
	c := newRouteMaskCache(time.Hour)
	c.lookup = func(net.IP, int) (uint8, bool) {
		started.Add(1)
		return 24, true
	}
	c.afterPopulate = func() { done <- struct{}{} }

	// One pre-Close miss proves the seam is live before we close it — without
	// this the post-Close assertion would also pass on a cache that never
	// scheduled anything at all.
	c.resolve(net.IPv4(198, 51, 100, 1), 3)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("setup: the pre-Close lookup never ran")
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("setup: want 1 lookup before Close, got %d", got)
	}

	c.Close()

	// Ten distinct keys, so neither the dedup nor the in-flight cap can be
	// what suppresses them.
	for i := 0; i < 10; i++ {
		mask, ok := c.resolve(net.IPv4(198, 51, 100, byte(100+i)), 3)
		if ok || mask != 0 {
			t.Fatalf("a post-Close miss must resolve to the default, got %d,%v", mask, ok)
		}
	}
	// Give any wrongly-scheduled goroutine time to run before we read.
	select {
	case <-done:
		t.Fatal("a background lookup ran AFTER Close — the closed flag is gone")
	case <-time.After(200 * time.Millisecond):
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("%d lookups ran, want 1 (only the pre-Close one) — Close is not "+
			"stopping the scheduler", got)
	}
}

// Close is idempotent and does not hang on a second call.
func TestRouteMaskCacheCloseIsIdempotent(t *testing.T) {
	c := newRouteMaskCache(time.Hour)
	c.lookup = func(net.IP, int) (uint8, bool) { return 0, false }
	c.Close()
	c.Close()
}

// Close waits for an in-flight lookup, but only up to routeMaskCloseGrace — a
// netlink socket wedged in the kernel must not hold daemon shutdown open.
func TestRouteMaskCacheCloseIsBoundedByTheGrace(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	c := newRouteMaskCache(time.Hour)
	c.lookup = func(net.IP, int) (uint8, bool) {
		entered <- struct{}{}
		<-release // never released until after Close has returned
		return 0, false
	}
	c.resolve(net.IPv4(198, 51, 100, 9), 3)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("setup: the blocking lookup never started")
	}

	start := time.Now()
	c.Close()
	elapsed := time.Since(start)
	close(release)

	if elapsed < routeMaskCloseGrace {
		t.Fatalf("Close returned in %v — it did not wait for the in-flight lookup at all", elapsed)
	}
	if elapsed > routeMaskCloseGrace+2*time.Second {
		t.Fatalf("Close blocked for %v on a wedged lookup — the wait is unbounded", elapsed)
	}
}

// The exporters own a cache and must stop it: a NewExporter whose Close does
// not reach the cache leaves the scheduler running for the process lifetime.
func TestExporterCloseStopsTheRouteMaskCache(t *testing.T) {
	e, err := NewExporter(&ExportConfig{InstanceName: "t", TemplateName: "t"})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	if e.maskCache == nil {
		t.Fatal("NewExporter must build a closable route-mask cache")
	}
	e.Close()
	e.maskCache.mu.Lock()
	closed := e.maskCache.closed
	e.maskCache.mu.Unlock()
	if !closed {
		t.Fatal("Exporter.Close did not close the route-mask cache")
	}

	ie, err := NewIPFIXExporter(&ExportConfig{InstanceName: "t", TemplateName: "t"})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	if ie.maskCache == nil {
		t.Fatal("NewIPFIXExporter must build a closable route-mask cache")
	}
	ie.Close()
	ie.maskCache.mu.Lock()
	closed = ie.maskCache.closed
	ie.maskCache.mu.Unlock()
	if !closed {
		t.Fatal("IPFIXExporter.Close did not close the route-mask cache")
	}
}
