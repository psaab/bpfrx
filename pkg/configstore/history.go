// Package configstore provides history management for config store.
package configstore

import (
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// HistoryEntry represents a snapshot of a configuration tree.
type HistoryEntry struct {
	Config    *config.ConfigTree
	Timestamp time.Time
	Comment   string
}

// History is a fixed-size ring buffer for configuration history.
type History struct {
	entries []*HistoryEntry
	head    int
	size    int
	maxSize int
}

// NewHistory creates a History with the given maximum size.
func NewHistory(max int) *History {
	return &History{
		entries: make([]*HistoryEntry, max),
		maxSize: max,
	}
}

// MaxSize returns the maximum history size.
func (h *History) MaxSize() int {
	return h.maxSize
}

// Len returns the current number of entries in the history.
func (h *History) Len() int {
	return h.size
}

// Push adds an entry, overwriting the oldest if full.
func (h *History) Push(entry *HistoryEntry) {
	h.entries[h.head] = entry
	h.head = (h.head + 1) % h.maxSize
	if h.size < h.maxSize {
		h.size++
	}
}

// Get returns the entry at position n (0 = most recent, size-1 = oldest).
func (h *History) Get(n int) (*HistoryEntry, error) {
	if n < 0 || n >= h.size {
		return nil, fmt.Errorf("history position %d out of range [0, %d)", n, h.size)
	}
	idx := (h.head - 1 - n + h.maxSize) % h.maxSize
	return h.entries[idx], nil
}

// List returns all entries, most recent first.
func (h *History) List() []*HistoryEntry {
	result := make([]*HistoryEntry, h.size)
	for i := 0; i < h.size; i++ {
		idx := (h.head - 1 - i + h.maxSize) % h.maxSize
		result[i] = h.entries[idx]
	}
	return result
}
