package logging

import (
	"sync"
	"time"
)

// EventRecord is a formatted event stored in the event buffer.
type EventRecord struct {
	Time         time.Time
	Type         string // "SESSION_OPEN", "POLICY_DENY", etc.
	SrcAddr      string // "10.0.1.5:443"
	DstAddr      string
	Protocol     string // "TCP", "UDP"
	Action       string // "permit", "deny"
	PolicyID     uint32
	InZone       uint16
	OutZone      uint16
	ScreenCheck  string // for SCREEN_DROP
	SessionPkts  uint64 // for SESSION_CLOSE
	SessionBytes uint64
}

// EventBuffer is a thread-safe circular buffer for recent events.
type EventBuffer struct {
	mu    sync.RWMutex
	buf   []EventRecord
	size  int
	head  int // next write position
	count int // number of events stored
}

// NewEventBuffer creates a new event buffer with the given capacity.
func NewEventBuffer(size int) *EventBuffer {
	return &EventBuffer{
		buf:  make([]EventRecord, size),
		size: size,
	}
}

// Add appends an event to the buffer, overwriting the oldest if full.
func (eb *EventBuffer) Add(rec EventRecord) {
	eb.mu.Lock()
	eb.buf[eb.head] = rec
	eb.head = (eb.head + 1) % eb.size
	if eb.count < eb.size {
		eb.count++
	}
	eb.mu.Unlock()
}

// Latest returns the most recent n events, newest first.
func (eb *EventBuffer) Latest(n int) []EventRecord {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if n > eb.count {
		n = eb.count
	}
	if n == 0 {
		return nil
	}

	result := make([]EventRecord, n)
	for i := 0; i < n; i++ {
		// Walk backwards from the most recent entry
		idx := (eb.head - 1 - i + eb.size) % eb.size
		result[i] = eb.buf[idx]
	}
	return result
}
