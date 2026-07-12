package grpcapi

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestMonitorStatusCacheCoalescesWithinWindow proves the cache issues exactly
// one backing Status() fetch for all callers inside a freshness window and
// refetches once the window elapses — the coalescing behavior that keeps the
// MonitorInterface fan-out O(1) per tick (#5707).
func TestMonitorStatusCacheCoalescesWithinWindow(t *testing.T) {
	var calls atomic.Int64
	base := time.Unix(1_000_000, 0)
	clock := base
	fetch := func() (dpuserspace.ProcessStatus, error) {
		calls.Add(1)
		return dpuserspace.ProcessStatus{Enabled: true}, nil
	}
	c := newMonitorStatusCache(fetch, 900*time.Millisecond, func() time.Time { return clock })

	// First call fetches; the next several within the window are served cached.
	for i := 0; i < 5; i++ {
		if _, err := c.get(); err != nil {
			t.Fatalf("get() error = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("Status() fetch count within window = %d, want 1", got)
	}

	// Advance past the TTL: exactly one more fetch, then cached again.
	clock = base.Add(time.Second)
	for i := 0; i < 5; i++ {
		if _, err := c.get(); err != nil {
			t.Fatalf("get() error = %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("Status() fetch count after TTL advance = %d, want 2", got)
	}
}

// TestMonitorStatusCacheSingleFlightUnderRace exercises many concurrent callers
// against a fixed clock: the mutex must serialize them into a single fetch, and
// -race must stay clean. This guards the shared-state safety the fan-out fix
// introduces across streams.
func TestMonitorStatusCacheSingleFlightUnderRace(t *testing.T) {
	var calls atomic.Int64
	fixed := time.Unix(2_000_000, 0)
	fetch := func() (dpuserspace.ProcessStatus, error) {
		calls.Add(1)
		return dpuserspace.ProcessStatus{}, nil
	}
	c := newMonitorStatusCache(fetch, time.Second, func() time.Time { return fixed })

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.get(); err != nil {
				t.Errorf("get() error = %v", err)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent fetch count = %d, want 1 (single-flight within window)", got)
	}
}

// TestMonitorStatusCachePropagatesError confirms the cached result carries the
// backing error through the window instead of silently masking a failed query.
func TestMonitorStatusCachePropagatesError(t *testing.T) {
	sentinel := errors.New("control socket busy")
	fixed := time.Unix(3_000_000, 0)
	c := newMonitorStatusCache(func() (dpuserspace.ProcessStatus, error) {
		return dpuserspace.ProcessStatus{}, sentinel
	}, time.Second, func() time.Time { return fixed })

	if _, err := c.get(); !errors.Is(err, sentinel) {
		t.Fatalf("get() error = %v, want %v", err, sentinel)
	}
	// Second call within the window returns the cached error too.
	if _, err := c.get(); !errors.Is(err, sentinel) {
		t.Fatalf("cached get() error = %v, want %v", err, sentinel)
	}
}
