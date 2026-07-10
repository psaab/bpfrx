package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// TestFactoryResetDurableKeyFirstOrdering pins #5197 A4-b1-F5: the factory
// reset must fsync .configdb AFTER the master.key unlink and BEFORE the
// ciphertext body is removed, then fsync configDir at the very end so every
// unlink is durable. Without the mid barrier the key-first
// cryptographic-erasure guarantee ("a crash can never leave ciphertext
// together with its key") is not durably enforced — both unlinks sit in the
// page cache and the filesystem may persist the ciphertext removal while
// losing the key removal.
//
// RED on revert: dropping the fsatomic.SyncDir(.configdb) barrier or the final
// fsatomic.SyncDir(configDir) (e.g. reverting to the old discarded
// os.Open+d.Sync) changes the recorded seam-call order and trips the exact
// match below.
func TestFactoryResetDurableKeyFirstOrdering(t *testing.T) {
	restoreRollbackSeams(t)

	var events []string
	rbRemove = func(path string) error {
		events = append(events, "remove:"+path)
		return os.Remove(path)
	}
	rbSyncDir = func(dir string) error {
		events = append(events, "sync:"+dir)
		return fsatomic.SyncDir(dir)
	}

	dir := t.TempDir()
	configBase := "xpf.conf"
	dbDir := filepath.Join(dir, ".configdb")
	masterKey := filepath.Join(dbDir, "master.key")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatalf("mkdir .configdb: %v", err)
	}
	if err := os.WriteFile(masterKey, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("seed master.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "active.json"), []byte("cipher"), 0o600); err != nil {
		t.Fatalf("seed active.json: %v", err)
	}

	if err := FactoryResetConfigDir(dir, configBase); err != nil {
		t.Fatalf("FactoryResetConfigDir: %v", err)
	}

	// Exactly: unlink the key, fsync the key's dir (durability barrier before
	// the ciphertext RemoveAll), then fsync the parent at the end. The
	// enumerated top-level removals go through os.Remove directly and are not
	// recorded here.
	want := []string{
		"remove:" + masterKey,
		"sync:" + dbDir,
		"sync:" + dir,
	}
	if !reflect.DeepEqual(events, want) {
		t.Errorf("durable-erase seam order mismatch:\n got  %v\n want %v", events, want)
	}
	if _, err := os.Stat(dbDir); !os.IsNotExist(err) {
		t.Errorf(".configdb should be gone after factory reset, stat err=%v", err)
	}
}

// TestFactoryResetPropagatesDirSyncError pins the second half of #5197
// A4-b1-F5: a final directory-fsync FAILURE must be surfaced, not swallowed.
// The pre-fix code discarded the end-of-function d.Sync()/d.Close() errors
// (`_ =`) and returned firstErr, so a wipe whose namespace changes never
// reached stable storage was reported as a clean factory reset.
//
// RED on revert: restoring the discarded `_ = d.Sync()` makes
// FactoryResetConfigDir return nil here.
func TestFactoryResetPropagatesDirSyncError(t *testing.T) {
	restoreRollbackSeams(t)

	dir := t.TempDir()
	dbDir := filepath.Join(dir, ".configdb")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatalf("mkdir .configdb: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "master.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatalf("seed master.key: %v", err)
	}

	sentinel := errors.New("injected final dir fsync failure")
	rbSyncDir = func(d string) error {
		if filepath.Clean(d) == filepath.Clean(dir) {
			return sentinel // fail ONLY the final configDir barrier
		}
		return fsatomic.SyncDir(d)
	}

	err := FactoryResetConfigDir(dir, "xpf.conf")
	if err == nil {
		t.Fatalf("FactoryResetConfigDir must surface a final dir-fsync failure, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("returned error = %v, want it to wrap the injected fsync failure", err)
	}
}
