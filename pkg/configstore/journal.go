// Package configstore provides transaction audit logging for configuration changes.
package configstore

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Journal provides a transaction audit log for configuration changes.
// Entries are appended to a JSONL file (one JSON object per line).
type Journal struct {
	filePath string
}

// JournalEntry represents a single audit log entry.
type JournalEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Action    string         `json:"action"`    // "commit", "rollback", "set", "delete", "override", "merge"
	Detail    string         `json:"detail"`    // human-readable description
	Before    *config.Config `json:"before"`    // compiled config before (nil for first commit)
	After     *config.Config `json:"after"`     // compiled config after
}

// NewJournal creates a journal at the given file path.
func NewJournal(filePath string) *Journal {
	return &Journal{filePath: filePath}
}

// Log appends an entry to the journal.
func (j *Journal) Log(entry *JournalEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal journal entry: %w", err)
	}

	f, err := os.OpenFile(j.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open journal: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "%s\n", data); err != nil {
		return fmt.Errorf("write journal entry: %w", err)
	}
	return nil
}

// ListEntries reads all journal entries from disk.
func (j *Journal) ListEntries(limit int) ([]*JournalEntry, error) {
	data, err := os.ReadFile(j.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read journal: %w", err)
	}

	lines := splitNonEmpty(string(data), "\n")
	var entries []*JournalEntry
	for _, line := range lines {
		entry := &JournalEntry{}
		if err := json.Unmarshal([]byte(line), entry); err != nil {
			continue // skip corrupt entries
		}
		entries = append(entries, entry)
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	return entries, nil
}

// splitNonEmpty splits a string and returns non-empty parts.
func splitNonEmpty(s, sep string) []string {
	parts := strings.Split(s, sep)
	var result []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			result = append(result, p)
		}
	}
	return result
}
