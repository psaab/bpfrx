package configstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7176 (C179-056). A tombstoned history position left its on-disk slot
// untouched, so the file kept the PREVIOUS generation's config text. History is
// most-recent-first and shifts on every commit, so those bytes then sat under a
// different index — and on the next boot loadRollbackHistory parsed them as a
// healthy slot, losing the tombstone entirely. `rollback N` returned another
// generation's config with nothing in the load path able to notice.
//
// At runtime #4810 works exactly as designed: rollbackEntry() refuses the
// tombstone. The defect only materialises ACROSS A BOOT, which is precisely why
// nothing tested it — the suite had no reload cell at all.

// setupShiftedTombstone commits four configs, corrupts slot 2 so it tombstones
// at load, then commits once more so the tombstone SHIFTS onto slot 3. Returns
// the store path.
func setupShiftedTombstone(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hostA", "hostB", "hostC", "hostD"} {
		s.SetFromInput("system host-name " + name)
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}
	// A directory where a slot file belongs: unreadable, so it tombstones.
	slot2 := s.rollbackPath(2)
	if err := os.Remove(slot2); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(slot2, 0o755); err != nil {
		t.Fatal(err)
	}

	s2 := newTestStoreAt(t, path)
	s2.loadRollbackHistory()
	if got := s2.history.List(); len(got) < 2 || got[1].Config != nil {
		t.Fatal("fixture broken: slot 2 did not tombstone at load, so the shift below " +
			"would not exercise the tombstone path at all")
	}
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s2.SetFromInput("system host-name hostE")
	if _, err := s2.Commit(); err != nil {
		t.Fatalf("commit hostE with a tombstone present: %v", err)
	}
	return path
}

// THE CELL THAT WOULD HAVE CAUGHT THIS. Fires when a position that is a
// tombstone in memory comes back HEALTHY after a reload from disk.
func TestRollbackTombstoneSurvivesReload_7176(t *testing.T) {
	path := setupShiftedTombstone(t)

	reloaded := newTestStoreAt(t, path)
	reloaded.loadRollbackHistory()
	entries := reloaded.history.List()
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 history entries after reload, got %d", len(entries))
	}
	if entries[2].Config != nil {
		t.Fatalf("history position 2 came back HEALTHY after a reload — the tombstone "+
			"was resurrected as a slot holding another generation's config, and "+
			"`rollback 3` now returns it:\n%s", entries[2].Config.Format())
	}
}

// The slot must hold the marker, not stale config. Fires when saveRollbackFiles
// leaves the previous generation's bytes in place.
func TestRollbackTombstoneSlotHoldsMarker_7176(t *testing.T) {
	path := setupShiftedTombstone(t)
	s := newTestStoreAt(t, path)
	got, err := os.ReadFile(s.rollbackPath(3))
	if err != nil {
		t.Fatalf("read slot 3: %v", err)
	}
	if string(got) != rollbackTombstoneMarker {
		t.Errorf("slot 3 = %q, want the tombstone marker %q", got, rollbackTombstoneMarker)
	}
}

// THE CELL THAT MAKES THE MARKER SAFE, and the reason it is shaped the way it
// is. Fires when the marker PARSES CLEANLY.
//
// The obvious marker — a bare "# xpf-rollback-tombstone" comment — parses with
// ZERO errors into an EMPTY config. A reader predating the prefix check would
// then offer that slot as a healthy empty configuration, so `rollback N` would
// WIPE the configuration instead of returning the wrong generation: the fix
// making the bug strictly worse. The trailing "}" is what guarantees a parse
// error, so such a reader tombstones it through the existing corrupt-file
// branch — which is the correct outcome there, and is why this change needs no
// format negotiation.
func TestTombstoneMarkerFailsToParse_7176(t *testing.T) {
	tree, errs := config.NewParser(rollbackTombstoneMarker).Parse()
	if len(errs) == 0 {
		n := 0
		if tree != nil {
			n = len(tree.Children)
		}
		t.Fatalf("the tombstone marker PARSES CLEANLY (%d top-level children) — a reader "+
			"without the prefix check would load it as a valid config and `rollback N` "+
			"would restore it. Keep a construct that is a guaranteed parse error.", n)
	}
}
