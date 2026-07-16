package configstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// TestDeleteConfirmDirSynced pins #4864: removing confirm.json must be a
// DURABLE transition. A successful os.Remove is not durable until the parent
// directory is fsynced — a crash/power-loss in the window before the directory
// entry removal flushes can replay the stale confirm.json on reboot, and
// recoverPendingConfirmLocked would then revert an already-confirmed config (in
// HA, re-diverge a confirmed standby). WriteConfirm persists confirm.json
// through fsatomic.WriteFileDurable (dir-synced), so the delete must match that
// dir-sync discipline.
//
// RED on revert: dropping the fsatomic.SyncDir call after the unlink leaves
// syncedDir empty, tripping the assertion below.
func TestDeleteConfirmDirSynced(t *testing.T) {
	restoreRollbackSeams(t)

	var removedPaths []string
	var syncedDir string
	rbRemove = func(path string) error {
		removedPaths = append(removedPaths, path)
		return os.Remove(path)
	}
	rbSyncDir = func(dir string) error {
		syncedDir = dir
		return fsatomic.SyncDir(dir)
	}

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	// Arm a persisted confirm record so there is a real file to delete.
	if err := s.db.WriteConfirm(&confirmRecord{Deadline: time.Now().Add(10 * time.Minute)}); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}
	confirmPath := s.db.confirmPath()
	if _, err := os.Stat(confirmPath); err != nil {
		t.Fatalf("confirm.json must exist after WriteConfirm: %v", err)
	}

	if err := s.db.DeleteConfirm(); err != nil {
		t.Fatalf("DeleteConfirm: %v", err)
	}

	// The file must be gone.
	if _, err := os.Stat(confirmPath); !os.IsNotExist(err) {
		t.Fatalf("confirm.json still present after DeleteConfirm: err=%v", err)
	}
	// The unlink must have gone through the seam.
	if !containsPath(removedPaths, confirmPath) {
		t.Errorf("confirm.json unlink not recorded; removed=%v", removedPaths)
	}
	// The parent directory MUST have been fsynced so the unlink is durable.
	wantDir := filepath.Dir(confirmPath)
	if syncedDir != wantDir {
		t.Errorf("confirm-state directory %q was not fsync'd after delete (SyncDir called on %q)",
			wantDir, syncedDir)
	}
}

// TestDeleteConfirmAbsentReachesDirSync pins the #5835 correction to the #4864
// durability contract: deleting an ABSENT confirm.json still fsyncs the parent
// directory. The DB layer cannot tell "never existed" from "a prior call
// unlinked it but its dir fsync failed" (the removal is then not yet durable),
// so the absent path MUST fall through to the dir fsync — otherwise an
// absent-file retry after an unlink-succeeded/dir-sync-failed report would
// launder a non-durable removal into a false success, and a crash would replay
// the stale dirent on reboot. Reaching the sync unconditionally is harmless
// (idempotent) and makes the retry converge.
//
// RED on revert: restoring the old `os.IsNotExist -> return nil` short-circuit
// (before the dir fsync) leaves syncedDir empty, tripping the assertion.
func TestDeleteConfirmAbsentReachesDirSync(t *testing.T) {
	restoreRollbackSeams(t)

	var syncedDir string
	rbSyncDir = func(dir string) error {
		syncedDir = dir
		return fsatomic.SyncDir(dir)
	}

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	// No confirm.json written — the absent path.
	if err := s.db.DeleteConfirm(); err != nil {
		t.Fatalf("DeleteConfirm on absent file must be nil: %v", err)
	}
	if syncedDir != filepath.Dir(s.db.confirmPath()) {
		t.Errorf("absent-file delete must still fsync the confirm-state directory %q so an "+
			"absent-file retry reaches the #4864 durability sync; synced %q",
			filepath.Dir(s.db.confirmPath()), syncedDir)
	}
}
