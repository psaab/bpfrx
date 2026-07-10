package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGCProtectionForPublish_4876 pins the fail-closed GC-protection gate the
// publish-generation verb uses. A crashed/resumable cut leaves a durable
// journal pinning its source generation; if publish-generation cannot read
// that pin, running destructive GC with an empty protection set can reap the
// pinned source and brick the resume. The gate must therefore SKIP GC whenever
// the protection set is unknown (present-but-unreadable / malformed journal)
// and only run it when the journal is absent or successfully read.
func TestGCProtectionForPublish_4876(t *testing.T) {
	dir := t.TempDir()

	// Absent journal: genuinely unprotected -> GC proceeds, empty protection.
	absent := filepath.Join(dir, "absent-journal.json")
	protected, runGC, warn := gcProtectionForPublish(absent)
	if !runGC {
		t.Fatalf("absent journal: runGC=false, want true (no crashed cut to protect)")
	}
	if len(protected) != 0 {
		t.Fatalf("absent journal: protected=%v, want empty", protected)
	}
	if warn != "" {
		t.Fatalf("absent journal: warn=%q, want empty", warn)
	}

	// Well-formed journal pinning a generation: GC proceeds AND protects it.
	pinned := filepath.Join(dir, "pinned-journal.json")
	if err := os.WriteFile(pinned, []byte(`{"target_version":"2.0.0","state":"copied","source_generation":"g0-deadbeef"}`), 0600); err != nil {
		t.Fatal(err)
	}
	protected, runGC, warn = gcProtectionForPublish(pinned)
	if !runGC {
		t.Fatalf("pinned journal: runGC=false, want true")
	}
	if !protected["g0-deadbeef"] {
		t.Fatalf("pinned journal: protected=%v, want g0-deadbeef protected", protected)
	}
	if warn != "" {
		t.Fatalf("pinned journal: warn=%q, want empty", warn)
	}

	// Legacy well-formed journal with no pin: GC proceeds, nothing to protect.
	legacy := filepath.Join(dir, "legacy-journal.json")
	if err := os.WriteFile(legacy, []byte(`{"target_version":"2.0.0","state":"copied"}`), 0600); err != nil {
		t.Fatal(err)
	}
	protected, runGC, _ = gcProtectionForPublish(legacy)
	if !runGC || len(protected) != 0 {
		t.Fatalf("legacy journal: (runGC=%v, protected=%v), want (true, empty)", runGC, protected)
	}

	// Present-but-malformed journal: protection UNKNOWN -> GC MUST be skipped.
	// This is the #4876 fail-closed guard. Before the fix, a malformed journal
	// degraded to ("",nil) and GC ran with an empty protection set.
	malformed := filepath.Join(dir, "malformed-journal.json")
	if err := os.WriteFile(malformed, []byte(`{not valid json`), 0600); err != nil {
		t.Fatal(err)
	}
	_, runGC, warn = gcProtectionForPublish(malformed)
	if runGC {
		t.Fatalf("malformed journal: runGC=true, want false — destructive GC must be skipped when protection is unknown")
	}
	if warn == "" {
		t.Fatalf("malformed journal: warn empty, want a non-empty operator message on the GC-skip path")
	}
}
