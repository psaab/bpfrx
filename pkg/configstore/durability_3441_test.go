package configstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// restoreRollbackSeams restores the package-level rollback/archive
// persistence seams (#3441) after a test overrides them. Tests in this
// package run serially, so a single deferred restore is sufficient.
func restoreRollbackSeams(t *testing.T) {
	t.Helper()
	dur, atom, sync, rm := rbWriteFileDurable, rbWriteFileAtomic, rbSyncDir, rbRemove
	t.Cleanup(func() {
		rbWriteFileDurable, rbWriteFileAtomic, rbSyncDir, rbRemove = dur, atom, sync, rm
	})
}

// TestAutoArchiveCapturesCommittedTreeNoOverwrite pins #3441 H4: each commit
// must archive ITS OWN just-committed text, and two rapid commits must not
// overwrite each other's archive.
//
// RED on revert: the pre-#3441 code passed nothing to the async goroutine and
// let it read s.active.Format() whenever it ran (so both goroutines could
// archive the second commit's tree) AND named the file at second resolution
// (so two same-second commits resolved to one path, overwriting). Either
// failure mode trips the assertions below.
func TestAutoArchiveCapturesCommittedTreeNoOverwrite(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	s.SetArchiveConfig(archiveDir, 10)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"archive-aaa", "archive-bbb"} {
		s.SetFromInput("system host-name " + name)
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}

	// Let the async archive goroutines finish.
	deadline := time.Now().Add(2 * time.Second)
	var ents []os.DirEntry
	for time.Now().Before(deadline) {
		e, err := os.ReadDir(archiveDir)
		if err == nil && len(e) >= 2 {
			ents = e
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(ents) != 2 {
		t.Fatalf("expected 2 distinct archive files (no overwrite), got %d", len(ents))
	}

	contents := map[string]bool{}
	for _, e := range ents {
		data, err := os.ReadFile(filepath.Join(archiveDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents[string(data)] = true
	}

	for _, name := range []string{"archive-aaa", "archive-bbb"} {
		found := false
		for c := range contents {
			if strings.Contains(c, "host-name "+name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no archive captured commit %q — async writer archived the wrong (later) tree", name)
		}
	}
}

// TestWriteArchiveSameTimestampNoOverwrite pins the #3441 H4 Codex MAJOR
// fix: two archives sharing the SAME wall-clock timestamp (the coarse-clock
// / NTP-step-back collision the nanosecond format alone could not rule out)
// must still produce TWO distinct files, because the monotonic seq is part
// of the filename.
//
// RED on revert: with a ts-only filename both writes resolve to the same
// path, so the second overwrites the first — len == 1 and the first config
// is lost.
func TestWriteArchiveSameTimestampNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 6, 28, 12, 0, 0, 123456789, time.UTC)

	if err := writeArchive(dir, 10, "config-A\n", ts, 1); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(dir, 10, "config-B\n", ts, 2); err != nil {
		t.Fatal(err)
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("same-timestamp archives must not overwrite: got %d files, want 2", len(ents))
	}
	contents := map[string]bool{}
	for _, e := range ents {
		d, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents[string(d)] = true
	}
	if !contents["config-A\n"] || !contents["config-B\n"] {
		t.Errorf("an archive was overwritten despite the seq: contents=%v", contents)
	}
}

// TestWriteArchivePrunesOldestByTimestampSeq verifies retention still prunes
// the OLDEST archives with the new config-<ts>.<seq>.conf filename: the
// lexical sort rotateArchives uses stays chronological because the timestamp
// dominates and the zero-padded seq only breaks same-ts ties in commit order.
func TestWriteArchivePrunesOldestByTimestampSeq(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		if err := writeArchive(dir, 3, fmt.Sprintf("cfg-%d\n", i), ts, uint64(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("want 3 archives after prune (max=3), got %d", len(ents))
	}
	remain := map[string]bool{}
	for _, e := range ents {
		d, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		remain[strings.TrimSpace(string(d))] = true
	}
	for _, w := range []string{"cfg-2", "cfg-3", "cfg-4"} {
		if !remain[w] {
			t.Errorf("newest archive %q should be retained; remain=%v", w, remain)
		}
	}
	for _, w := range []string{"cfg-0", "cfg-1"} {
		if remain[w] {
			t.Errorf("oldest archive %q should have been pruned; remain=%v", w, remain)
		}
	}
}

// TestRollbackSlotOneDurableAndDirSync pins the rollback-file durability
// contract via the seam recorders: slot 1 (the immediate `rollback 1` target)
// must be written with WriteFileDurable, and the directory must be fsync'd.
// The recorders prove the call ROUTING (durable-vs-atomic + dir-sync); the
// actual fsync syscalls are covered by pkg/fsatomic's own tests
// (TestDurableFsyncsFileAndDir, TestSyncDir), so this need not re-assert them.
//
// RED on revert: downgrading slot 1 to WriteFileAtomic drops it from the
// durable-write recorder; removing the trailing SyncDir clears syncedDir.
func TestRollbackSlotOneDurableAndDirSync(t *testing.T) {
	restoreRollbackSeams(t)

	var durableWrites, atomicWrites []string
	var syncedDir bool
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		durableWrites = append(durableWrites, path)
		return fsatomic.WriteFileDurable(path, data, perm, opts...)
	}
	rbWriteFileAtomic = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		atomicWrites = append(atomicWrites, path)
		return fsatomic.WriteFileAtomic(path, data, perm, opts...)
	}
	rbSyncDir = func(dir string) error {
		syncedDir = true
		return fsatomic.SyncDir(dir)
	}

	s := newTestStore(t)
	// Two commits => slot1 (durable) + slot2 (atomic).
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"durable-a", "durable-b"} {
		s.SetFromInput("system host-name " + name)
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}

	slot1 := s.rollbackPath(1)
	if !containsPath(durableWrites, slot1) {
		t.Errorf("slot 1 %q was not written durably (WriteFileDurable); durable=%v", slot1, durableWrites)
	}
	if containsPath(atomicWrites, slot1) {
		t.Errorf("slot 1 %q was written via the atomic (non-fsync) writer", slot1)
	}
	if !syncedDir {
		t.Error("rollback directory was never fsync'd (SyncDir not called)")
	}
}

// TestRollbackHistoryDegradedOnWriteFailure pins #3441 L1: a rollback-slot
// write failure must flip the degraded bit and emit a journal entry instead
// of being warning-only.
//
// RED on revert: removing the degraded tracking leaves
// RollbackHistoryDegraded()==false and no journal entry after an injected
// slot-write failure.
func TestRollbackHistoryDegradedOnWriteFailure(t *testing.T) {
	restoreRollbackSeams(t)
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		return errors.New("injected slot write failure")
	}

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("system host-name degraded-host")
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit should still succeed despite rollback-file failure: %v", err)
	}

	if !s.RollbackHistoryDegraded() {
		t.Error("RollbackHistoryDegraded() = false after a slot-write failure, want true")
	}

	entries, err := s.journal.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "rollback_persist_error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("no rollback_persist_error journal entry after a slot-write failure")
	}
}

// TestLoadRollbackHistoryContinuesPastReadError pins #3441 L2:
// loadRollbackHistory must break only on a genuinely-missing slot, not on a
// transient/permission read error — otherwise a bad intermediate slot drops
// every later readable slot.
//
// RED on revert: breaking on any read error loads only slot 1, dropping the
// readable slot 3 below.
func TestLoadRollbackHistoryContinuesPastReadError(t *testing.T) {
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
	// Slots after the 4 commits (most-recent-first): .1=hostC, .2=hostB,
	// .3=hostA, .4=<empty initial>. Make slot 2 unreadable as a regular file
	// by replacing it with a directory — os.ReadFile then returns an error
	// that is NOT os.IsNotExist, independent of euid (works as root too).
	slot2 := s.rollbackPath(2)
	if err := os.Remove(slot2); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(slot2, 0755); err != nil {
		t.Fatal(err)
	}

	// Fresh store over the same files; load only the rollback history.
	s2 := newTestStoreAt(t, path)
	s2.loadRollbackHistory()

	if s2.history.Len() < 3 {
		t.Fatalf("loaded %d rollback entries, want >=3 (slots after the corrupt slot 2 must still load)", s2.history.Len())
	}
	gotA := false
	for _, e := range s2.history.List() {
		if strings.Contains(e.Config.Format(), "host-name hostA") {
			gotA = true
			break
		}
	}
	if !gotA {
		t.Error("slot 3 (hostA) was dropped — loader broke on the slot-2 read error instead of continuing")
	}
}

// TestCleanupRollbackFilesContinuesPastRemoveError pins #3441 L3:
// cleanupRollbackFiles must break only on a genuinely-absent slot, not on an
// arbitrary remove error — otherwise stale higher slots survive and violate
// the loader's contiguous-sequence invariant.
//
// RED on revert: breaking on any remove error leaves config.4 / config.5
// behind once config.3's remove is injected to fail.
func TestCleanupRollbackFilesContinuesPastRemoveError(t *testing.T) {
	restoreRollbackSeams(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	s := newTestStoreAt(t, path)

	// Create stale slots 3, 4, 5 directly on disk.
	for _, n := range []int{3, 4, 5} {
		if err := os.WriteFile(s.rollbackPath(n), []byte("stale"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	slot3 := s.rollbackPath(3)
	rbRemove = func(p string) error {
		if p == slot3 {
			return errors.New("injected remove failure") // not os.IsNotExist
		}
		return os.Remove(p)
	}

	s.cleanupRollbackFiles(3)

	if _, err := os.Stat(slot3); err != nil {
		t.Errorf("slot 3 should remain (its remove was injected to fail): %v", err)
	}
	for _, n := range []int{4, 5} {
		if _, err := os.Stat(s.rollbackPath(n)); !os.IsNotExist(err) {
			t.Errorf("slot %d should have been removed despite the slot-3 failure (stat err=%v)", n, err)
		}
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
