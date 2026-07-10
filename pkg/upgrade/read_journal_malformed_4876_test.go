package upgrade

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadJournalSourceGenerationMalformedErrors_4876 pins the fail-closed
// contract for a PRESENT-but-malformed upgrade journal. A corrupted/truncated
// journal cannot name the generation a crashed cut pins, so it MUST surface an
// error (not degrade to ("",nil)) — otherwise the destructive publish GC would
// run with an empty protection set and could reap the pinned source (#4876).
func TestReadJournalSourceGenerationMalformedErrors_4876(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.json")

	// Absent journal is NOT an error (nothing to protect).
	if g, err := ReadJournalSourceGeneration(path); err != nil || g != "" {
		t.Fatalf("absent journal: got (%q,%v), want (\"\",nil)", g, err)
	}

	// Present but unparseable: must error so the caller fails closed.
	if err := os.WriteFile(path, []byte(`{"source_generation": "g0-abc"`), 0600); err != nil {
		t.Fatal(err)
	}
	if g, err := ReadJournalSourceGeneration(path); err == nil {
		t.Fatalf("malformed journal: got (%q,nil), want a non-nil error (fail closed)", g)
	}

	// Well-formed journal still returns its pin with no error.
	if err := os.WriteFile(path, []byte(`{"source_generation":"g0-abc"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if g, err := ReadJournalSourceGeneration(path); err != nil || g != "g0-abc" {
		t.Fatalf("well-formed journal: got (%q,%v), want (g0-abc,nil)", g, err)
	}
}
