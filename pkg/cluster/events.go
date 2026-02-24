package cluster

import (
	"fmt"
	"sync"
	"time"
)

// EventCategory classifies cluster history events.
type EventCategory int

const (
	EventRG         EventCategory = iota // RG state transitions
	EventHeartbeat                       // heartbeat events
	EventMonitor                         // interface/IP monitor state changes
	EventColdSync                        // bulk session sync progress
	EventConfigSync                      // config sync events
	EventFabric                          // fabric link events
)

func (c EventCategory) String() string {
	switch c {
	case EventRG:
		return "RG"
	case EventHeartbeat:
		return "Heartbeat"
	case EventMonitor:
		return "Monitor"
	case EventColdSync:
		return "Cold Sync"
	case EventConfigSync:
		return "Config Sync"
	case EventFabric:
		return "Fabric"
	default:
		return fmt.Sprintf("unknown(%d)", int(c))
	}
}

// HistoryEvent records a single cluster event with timestamp.
type HistoryEvent struct {
	Time     time.Time
	Category EventCategory
	GroupID  int    // applicable RG (-1 if global)
	Message  string // human-readable
}

// EventHistory is a thread-safe ring buffer storing recent events per category.
type EventHistory struct {
	mu      sync.RWMutex
	events  map[EventCategory][]HistoryEvent
	maxSize int
}

// NewEventHistory creates an EventHistory that stores up to maxSize events per category.
func NewEventHistory(maxSize int) *EventHistory {
	return &EventHistory{
		events:  make(map[EventCategory][]HistoryEvent),
		maxSize: maxSize,
	}
}

// Record adds a new event to the history for the given category.
func (h *EventHistory) Record(cat EventCategory, rgID int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ev := HistoryEvent{
		Time:     time.Now(),
		Category: cat,
		GroupID:  rgID,
		Message:  msg,
	}

	ring := h.events[cat]
	if len(ring) >= h.maxSize {
		// Shift left by 1 (drop oldest).
		copy(ring, ring[1:])
		ring[len(ring)-1] = ev
	} else {
		ring = append(ring, ev)
	}
	h.events[cat] = ring
}

// Events returns a copy of all events for the given category, oldest first.
func (h *EventHistory) Events(cat EventCategory) []HistoryEvent {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ring := h.events[cat]
	if len(ring) == 0 {
		return nil
	}
	cp := make([]HistoryEvent, len(ring))
	copy(cp, ring)
	return cp
}
