package rpm

import (
	"sync"
	"testing"
)

// TestFireEventBufferedUntilCallbackRegistered is the fail-on-revert pin for
// #3755. RPM probes start immediately (runProbeLoop runs the first cycle at
// once), so a probe-failed / test-failed / test-completed event can be emitted
// before the event-options callback is registered. Those first-cycle events
// must NOT be lost: they are buffered and replayed to the callback the moment
// it is installed.
//
// RED-on-revert: without the buffer+replay, fireEvent drops events while
// onEvent is nil and SetEventCallback delivers nothing — got is empty.
func TestFireEventBufferedUntilCallbackRegistered(t *testing.T) {
	m := New()

	// First probe cycle fires before any callback exists.
	m.fireEvent("ping_probe_failed", "WAN", "t")
	m.fireEvent("ping_test_failed", "WAN", "t")

	var mu sync.Mutex
	var got []Event
	m.SetEventCallback(func(ev Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("buffered first-cycle events not replayed on registration: "+
			"got %d, want 2 (#3755 boot-time failover edge dropped)", len(got))
	}
	if got[0].Name != "ping_probe_failed" || got[1].Name != "ping_test_failed" {
		t.Fatalf("replay order wrong (want FIFO): %+v", got)
	}
	// The buffer must be drained after replay so a later event is not
	// re-delivered from the buffer.
	if n := len(m.bufferedEvents); n != 0 {
		t.Fatalf("buffer not drained after replay: %d entries remain", n)
	}
}

// Once a callback is registered, events are delivered live (not buffered).
func TestFireEventDeliveredLiveAfterRegistration(t *testing.T) {
	m := New()
	var mu sync.Mutex
	var got []Event
	m.SetEventCallback(func(ev Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})

	m.fireEvent("ping_test_failed", "WAN", "t")

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("live event not delivered: got %d, want 1", len(got))
	}
	if n := len(m.bufferedEvents); n != 0 {
		t.Fatalf("live event was buffered instead of delivered: %d buffered", n)
	}
}

// The pre-registration buffer is bounded so a callback that never arrives
// (event-options never configured) cannot grow it without limit.
func TestFireEventBufferBounded(t *testing.T) {
	m := New()
	for i := 0; i < maxBufferedEvents*3; i++ {
		m.fireEvent("ping_probe_failed", "WAN", "t")
	}
	m.mu.Lock()
	n := len(m.bufferedEvents)
	m.mu.Unlock()
	if n > maxBufferedEvents {
		t.Fatalf("event buffer unbounded: %d entries > cap %d", n, maxBufferedEvents)
	}
}

// HasEventCallback tracks registration state (used by daemon boot-ordering
// tests).
func TestHasEventCallback(t *testing.T) {
	m := New()
	if m.HasEventCallback() {
		t.Fatal("fresh manager reports a callback registered")
	}
	m.SetEventCallback(func(Event) {})
	if !m.HasEventCallback() {
		t.Fatal("callback not reported after registration")
	}
}
