package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewFailsClosedWhenDBDirUnusable is the #1893 regression test: when
// the .configdb directory cannot be created, New must return a precise
// error instead of constructing a Store around a nil *DB (which used to
// log a fictional "falling back to file-only" warning and then panic on
// the first Load/Save/commit).
//
// A regular file is planted at the .configdb path so os.MkdirAll fails
// with ENOTDIR — unlike a 0555 parent directory, this also fails under
// root/CAP_DAC_OVERRIDE, keeping the test meaningful in privileged CI.
func TestNewFailsClosedWhenDBDirUnusable(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, ".configdb")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0644); err != nil {
		t.Fatalf("plant blocker file: %v", err)
	}

	s, err := New(filepath.Join(dir, "xpf.conf"))
	if err == nil {
		t.Fatal("New succeeded with an unusable .configdb path; want fail-closed error")
	}
	if s != nil {
		t.Fatalf("New returned a non-nil store alongside an error: %+v", s)
	}
	if !strings.Contains(err.Error(), ".configdb") {
		t.Errorf("error should name the db dir, got: %v", err)
	}
	if strings.Contains(err.Error(), "file-only") && !strings.Contains(err.Error(), "no file-only fallback") {
		t.Errorf("error must not imply a file-only fallback exists, got: %v", err)
	}
}

// TestNewSucceedsAndLoadWorks pins the happy path of the two-value
// constructor: a writable directory yields a working store whose Load
// and Save round-trip without panicking.
func TestNewSucceedsAndLoadWorks(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
}
