package configstore

import (
	"os"
	"strings"
	"testing"
)

// TestLoadRollbackHistory_TombstonesOversizeSlot_5557 pins that
// loadRollbackHistory bounds a rollback slot by MaxConfigSize before handing it
// to the parser — the same ceiling every other parse entry point enforces
// (checkConfigSize on LoadOverride/LoadMerge/LoadSet/SyncApply). A slot larger
// than the cap is tombstoned (nil Config) instead of parsed, so a
// local-root-planted or corrupt oversized slot cannot drive an unbounded parse
// at boot.
//
// The slot content is a VALID config padded with trailing whitespace past the
// cap: with the guard it is tombstoned; WITHOUT the guard it parses to a real
// history entry. Asserting the loaded entry has a nil Config therefore goes RED
// exactly when the size guard is reverted (a bare "aaaa" payload could not
// distinguish the guard, since it would tombstone via the corrupt-parse branch
// either way).
func TestLoadRollbackHistory_TombstonesOversizeSlot_5557(t *testing.T) {
	s := newTestStore(t)

	body := "system {\n    host-name padded-rollback;\n}\n"
	oversize := body + strings.Repeat(" ", MaxConfigSize+1)
	if len(oversize) <= MaxConfigSize {
		t.Fatalf("test payload not over the cap: %d <= %d", len(oversize), MaxConfigSize)
	}
	if err := os.WriteFile(s.rollbackPath(1), []byte(oversize), 0o600); err != nil {
		t.Fatalf("write oversized rollback slot: %v", err)
	}

	s.loadRollbackHistory()

	if s.history.Len() == 0 {
		t.Fatal("loadRollbackHistory loaded no entries")
	}
	entry, err := s.history.Get(0)
	if err != nil {
		t.Fatalf("history.Get(0): %v", err)
	}
	if entry.Config != nil {
		t.Fatal("oversized rollback slot was parsed into a live history entry; " +
			"the MaxConfigSize guard is missing (slot must tombstone as nil Config)")
	}
}
