package configstore

import (
	"fmt"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

// HistoryEntry is a snapshot of a committed configuration.
type HistoryEntry struct {
	Config    *config.ConfigTree
	Timestamp time.Time
	Comment   string
}

// History is a ring buffer of configuration snapshots for rollback.
type History struct {
	entries []*HistoryEntry
	maxSize int
}

// NewHistory creates a new History with the given maximum size.
func NewHistory(maxSize int) *History {
	return &History{
		maxSize: maxSize,
	}
}

// Push adds a configuration snapshot to the history.
func (h *History) Push(entry *HistoryEntry) {
	h.entries = append(h.entries, entry)
	if len(h.entries) > h.maxSize {
		h.entries = h.entries[1:]
	}
}

// Get returns the nth most recent history entry (0 = most recent).
func (h *History) Get(n int) (*HistoryEntry, error) {
	if n < 0 || n >= len(h.entries) {
		return nil, fmt.Errorf("rollback %d: no such configuration (have %d entries)",
			n+1, len(h.entries))
	}
	// entries are stored oldest-first, so index from the end
	idx := len(h.entries) - 1 - n
	return h.entries[idx], nil
}

// Len returns the number of history entries.
func (h *History) Len() int {
	return len(h.entries)
}

// MaxSize returns the maximum number of history entries.
func (h *History) MaxSize() int {
	return h.maxSize
}

// List returns all history entries, most recent first.
func (h *History) List() []*HistoryEntry {
	result := make([]*HistoryEntry, len(h.entries))
	for i, entry := range h.entries {
		result[len(h.entries)-1-i] = entry
	}
	return result
}
