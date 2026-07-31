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

// TestLoadRollbackHistory_ContinuesPastOversizeIntermediateSlot_5557 pins that
// an oversized INTERMEDIATE slot is tombstoned in place (nil Config) WITHOUT
// dropping or shifting the later valid slots — the #4810 positional invariant
// applied to the #5557 size guard. Slots 1 and 3 hold valid, distinct configs;
// slot 2 is oversized. After load:
//   - rollback 1 (Get(0)) loads slot 1's config,
//   - rollback 2 (Get(1)) is the tombstone (nil Config),
//   - rollback 3 (Get(2)) STILL loads slot 3's config at its correct position —
//     proving the loader continued past the oversized intermediate slot instead
//     of terminating or collapsing slot 3 down into the rollback-2 index.
func TestLoadRollbackHistory_ContinuesPastOversizeIntermediateSlot_5557(t *testing.T) {
	s := newTestStore(t)

	slot1 := "system {\n    host-name rollback-slot-one;\n}\n"
	slot3 := "system {\n    host-name rollback-slot-three;\n}\n"
	oversize := "system {\n    host-name rollback-slot-two;\n}\n" + strings.Repeat(" ", MaxConfigSize+1)
	if len(oversize) <= MaxConfigSize {
		t.Fatalf("intermediate payload not over the cap: %d <= %d", len(oversize), MaxConfigSize)
	}

	for n, body := range map[int]string{1: slot1, 2: oversize, 3: slot3} {
		if err := os.WriteFile(s.rollbackPath(n), []byte(body), 0o600); err != nil {
			t.Fatalf("write rollback slot %d: %v", n, err)
		}
	}

	s.loadRollbackHistory()

	if s.history.Len() != 3 {
		t.Fatalf("history.Len() = %d, want 3 (oversized intermediate slot must tombstone in place, not drop later slots)", s.history.Len())
	}

	// rollback 1 -> slot 1 (valid).
	one, err := s.history.Get(0)
	if err != nil {
		t.Fatalf("history.Get(0): %v", err)
	}
	if one.Config == nil || !strings.Contains(one.Config.FormatSet(), "rollback-slot-one") {
		t.Fatalf("rollback 1 did not load slot 1's config; got %+v", one.Config)
	}

	// rollback 2 -> slot 2 (oversized: tombstoned, nil Config).
	two, err := s.history.Get(1)
	if err != nil {
		t.Fatalf("history.Get(1): %v", err)
	}
	if two.Config != nil {
		t.Fatal("rollback 2 (oversized intermediate slot) was parsed into a live entry; expected a nil-Config tombstone")
	}

	// rollback 3 -> slot 3 (valid) — the continuation-past-oversize assertion.
	three, err := s.history.Get(2)
	if err != nil {
		t.Fatalf("history.Get(2): %v", err)
	}
	if three.Config == nil || !strings.Contains(three.Config.FormatSet(), "rollback-slot-three") {
		t.Fatalf("rollback 3 did not load slot 3's config at its correct position; "+
			"the loader dropped or shifted the later valid slot past the oversized intermediate. got %+v", three.Config)
	}
}
