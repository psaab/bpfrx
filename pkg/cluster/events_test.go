package cluster

import (
	"fmt"
	"sync"
	"testing"
)

func TestEventHistory_BasicRecordRetrieve(t *testing.T) {
	h := NewEventHistory(64)
	h.Record(EventRG, 0, "primary->secondary")
	h.Record(EventRG, 1, "secondary->primary")

	events := h.Events(EventRG)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Message != "primary->secondary" {
		t.Errorf("event[0] message = %q, want %q", events[0].Message, "primary->secondary")
	}
	if events[1].GroupID != 1 {
		t.Errorf("event[1] groupID = %d, want 1", events[1].GroupID)
	}
}

func TestEventHistory_RingBufferWrap(t *testing.T) {
	maxSize := 4
	h := NewEventHistory(maxSize)

	// Insert more than maxSize events.
	for i := 0; i < 10; i++ {
		h.Record(EventHeartbeat, -1, fmt.Sprintf("event-%d", i))
	}

	events := h.Events(EventHeartbeat)
	if len(events) != maxSize {
		t.Fatalf("expected %d events, got %d", maxSize, len(events))
	}
	// Should have the last 4 events (6, 7, 8, 9).
	for i, ev := range events {
		want := fmt.Sprintf("event-%d", i+6)
		if ev.Message != want {
			t.Errorf("event[%d] = %q, want %q", i, ev.Message, want)
		}
	}
}

func TestEventHistory_PerCategoryIsolation(t *testing.T) {
	h := NewEventHistory(64)
	h.Record(EventRG, 0, "rg-event")
	h.Record(EventHeartbeat, -1, "hb-event")
	h.Record(EventMonitor, 1, "mon-event")

	if events := h.Events(EventRG); len(events) != 1 || events[0].Message != "rg-event" {
		t.Errorf("EventRG isolation failed: %v", events)
	}
	if events := h.Events(EventHeartbeat); len(events) != 1 || events[0].Message != "hb-event" {
		t.Errorf("EventHeartbeat isolation failed: %v", events)
	}
	if events := h.Events(EventMonitor); len(events) != 1 || events[0].Message != "mon-event" {
		t.Errorf("EventMonitor isolation failed: %v", events)
	}
	if events := h.Events(EventColdSync); len(events) != 0 {
		t.Errorf("expected empty EventColdSync, got %d events", len(events))
	}
}

func TestEventHistory_ConcurrentAccess(t *testing.T) {
	h := NewEventHistory(64)
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				h.Record(EventRG, n, fmt.Sprintf("w%d-%d", n, j))
			}
		}(i)
	}

	// Concurrent readers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = h.Events(EventRG)
			}
		}()
	}

	wg.Wait()

	events := h.Events(EventRG)
	if len(events) > 64 {
		t.Errorf("ring buffer exceeded maxSize: got %d", len(events))
	}
}

func TestEventHistory_EmptyCategory(t *testing.T) {
	h := NewEventHistory(64)
	events := h.Events(EventFabric)
	if events != nil {
		t.Errorf("expected nil for empty category, got %v", events)
	}
}

func TestEventHistory_GlobalGroupID(t *testing.T) {
	h := NewEventHistory(64)
	h.Record(EventHeartbeat, -1, "global event")
	events := h.Events(EventHeartbeat)
	if len(events) != 1 || events[0].GroupID != -1 {
		t.Errorf("global group ID not preserved: %v", events)
	}
}
