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

// TestDeleteConfirmAbsentNoDirSync confirms the no-op path: deleting an absent
// confirm.json is not an error and does NOT fsync the directory (nothing was
// unlinked, so there is nothing to make durable).
func TestDeleteConfirmAbsentNoDirSync(t *testing.T) {
	restoreRollbackSeams(t)

	var syncedDir string
	rbSyncDir = func(dir string) error {
		syncedDir = dir
		return fsatomic.SyncDir(dir)
	}

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	// No confirm.json written.
	if err := s.db.DeleteConfirm(); err != nil {
		t.Fatalf("DeleteConfirm on absent file must be nil: %v", err)
	}
	if syncedDir != "" {
		t.Errorf("absent-file delete must not fsync the directory, synced %q", syncedDir)
	}
}
