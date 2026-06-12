package configstore

// #1896: pre/post equivalence and integration coverage for the compact
// journal. `show system commit` renders Timestamp/Action/Detail from
// ListCommitHistory; the v1 reader (whole-file parse, last-N slice,
// THEN filter to commit actions) is reimplemented here as the oracle
// and compared against the bounded tail reader over a legacy fat
// journal with interleaved non-commit actions.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// v1JournalEntry mirrors the deleted v1 struct shape for writing
// legacy fat lines.
type v1JournalEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Action    string         `json:"action"`
	Detail    string         `json:"detail"`
	Before    *config.Config `json:"before"`
	After     *config.Config `json:"after"`
}

// v1ListCommitHistory is the pre-#1896 implementation, kept verbatim
// as the equivalence oracle: read whole file, parse every line, slice
// to the last `limit`, then filter to commit actions.
func v1ListCommitHistory(path string, limit int) ([]*JournalEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []*JournalEntry
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		entry := &JournalEntry{}
		if err := json.Unmarshal([]byte(line), entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	var commits []*JournalEntry
	for _, e := range entries {
		switch e.Action {
		case "commit", "commit_confirmed", "auto_rollback":
			commits = append(commits, e)
		}
	}
	return commits, nil
}

// writeLegacyJournal writes a v1-format journal: every entry carries a
// full compiled config in After (as the old writer did), with
// interleaved non-commit actions.
func writeLegacyJournal(t *testing.T, path string, n int) {
	t.Helper()
	cfg := &config.Config{System: config.SystemConfig{HostName: strings.Repeat("fat-payload-", 200)}}
	var sb strings.Builder
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		action := "commit"
		switch i % 5 {
		case 1:
			action = "config_sync"
		case 3:
			action = "persist_error"
		}
		e := &v1JournalEntry{
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			Action:    action,
			Detail:    fmt.Sprintf("entry %d", i),
			After:     cfg,
		}
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}
}

// TestListCommitHistoryLegacyEquivalence: over a fat v1 journal the
// bounded reader must return exactly what the v1 whole-file reader
// returned — same entries, same order, same Timestamp/Action/Detail
// (the fields `show system commit` prints).
func TestListCommitHistoryLegacyEquivalence(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, ".config.journal")
	writeLegacyJournal(t, journalPath, 120)

	s := newTestStoreAt(t, filepath.Join(dir, "config"))

	for _, limit := range []int{0, 1, 10, 50, 200} {
		want, err := v1ListCommitHistory(journalPath, limit)
		if err != nil {
			t.Fatalf("oracle limit=%d: %v", limit, err)
		}
		got, err := s.ListCommitHistory(limit)
		if err != nil {
			t.Fatalf("ListCommitHistory(%d): %v", limit, err)
		}
		if len(got) != len(want) {
			t.Fatalf("limit=%d: %d entries, oracle %d", limit, len(got), len(want))
		}
		for i := range got {
			if got[i].Action != want[i].Action || got[i].Detail != want[i].Detail || !got[i].Timestamp.Equal(want[i].Timestamp) {
				t.Errorf("limit=%d entry %d: got {%s %s %s}, oracle {%s %s %s}",
					limit, i, got[i].Timestamp, got[i].Action, got[i].Detail,
					want[i].Timestamp, want[i].Action, want[i].Detail)
			}
		}
	}
}

// TestCommitJournalCompactEntry: a real commit writes a compact v2
// entry — schema marker, config hash present, and the raw line carries
// no config payload.
func TestCommitJournalCompactEntry(t *testing.T) {
	dir := t.TempDir()
	s := newTestStoreAt(t, filepath.Join(dir, "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name compactjournal"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescription("compact entry test"); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListCommitHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 commit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Detail != "compact entry test" || e.Action != "commit" {
		t.Fatalf("wrong entry: %+v", e)
	}
	if e.ConfigHash == "" || len(e.ConfigHash) != 64 {
		t.Fatalf("missing/short config hash: %q", e.ConfigHash)
	}
	if e.ConfigHash != journalConfigHash(s.ActiveTree()) {
		t.Fatal("config hash does not match post-commit active tree")
	}

	raw, err := os.ReadFile(filepath.Join(dir, ".config.journal"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"after"`) || strings.Contains(string(raw), `"before"`) {
		t.Fatal("v2 journal line still carries config payloads")
	}
	if strings.Contains(string(raw), "compactjournal") {
		t.Fatal("v2 journal line leaks config content")
	}
	if len(raw) > 4096 {
		t.Fatalf("compact entry unexpectedly large: %d bytes", len(raw))
	}
}

// TestJournalConfigHashMatchesRollbackFile: the hash stored in the
// journal entry for commit K must equal the sha256 of the rollback
// file written when commit K+1 displaces that config — the operator
// correlation contract documented on journal.Entry.ConfigHash.
func TestJournalConfigHashMatchesRollbackFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	s := newTestStoreAt(t, cfgPath)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name gen-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescription("first"); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListCommitHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	firstHash := entries[len(entries)-1].ConfigHash

	if err := s.SetFromInput("system host-name gen-two"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescription("second"); err != nil {
		t.Fatal(err)
	}

	// rollback slot 1 now holds the post-first-commit tree.
	data, err := os.ReadFile(cfgPath + ".1")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != firstHash {
		t.Fatalf("rollback.1 hash %s != journal entry hash %s", got, firstHash)
	}
}
