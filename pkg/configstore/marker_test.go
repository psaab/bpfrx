package configstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCommittedMarkerRoundTrip proves WriteActive stamps committed=1 and
// WriteActiveMarker(false) stamps the never-committed marker, both readable
// via ReadActiveMeta.
func TestCommittedMarkerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.SetWriterVersion("test-1.0")

	tree := &config.ConfigTree{Children: []*config.Node{{Keys: []string{"system"}}}}

	// Real commit => committed=true.
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	if _, committed, err := db.ReadActiveMeta(); err != nil || !committed {
		t.Fatalf("ReadActiveMeta after WriteActive: committed=%v err=%v; want committed=true", committed, err)
	}

	// Never-committed marker => committed=false.
	if err := db.WriteActiveMarker(tree, false); err != nil {
		t.Fatalf("WriteActiveMarker(false): %v", err)
	}
	if _, committed, err := db.ReadActiveMeta(); err != nil || committed {
		t.Fatalf("ReadActiveMeta after marker: committed=%v err=%v; want committed=false", committed, err)
	}
}

// TestMarkerMigrationLegacyDB proves the C3 migration rule: a DB with no
// committed= envelope field (an older build, or a no-envelope legacy DB)
// reads committed=true so an upgrade never misclassifies into bootstrap.
func TestMarkerMigrationLegacyDB(t *testing.T) {
	dir := t.TempDir()

	// (1) Enveloped DB with NO committed= field (older floor build): build
	// the header by hand omitting committed=.
	body := []byte(`{"Children":null}`)
	hdr := []byte(envelopeMagic + " v=1 writer=old ast=1 min-reader=1 rollback-fmt=1\n")
	legacyEnvelope := append(append([]byte{}, hdr...), body...)
	if err := os.WriteFile(filepath.Join(dir, "active.json"), legacyEnvelope, 0644); err != nil {
		t.Fatal(err)
	}
	db, err := NewDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, committed, err := db.ReadActiveMeta(); err != nil || !committed {
		t.Fatalf("enveloped-no-committed DB: committed=%v err=%v; want committed=true", committed, err)
	}

	// (2) No-envelope (pre-floor) DB also reads committed.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "active.json"), body, 0644); err != nil {
		t.Fatal(err)
	}
	db2, err := NewDB(dir2)
	if err != nil {
		t.Fatal(err)
	}
	if _, committed, err := db2.ReadActiveMeta(); err != nil || !committed {
		t.Fatalf("no-envelope DB: committed=%v err=%v; want committed=true", committed, err)
	}
}

// TestStoreEverCommittedLifecycle proves the in-memory marker tracks the
// successful-commit lifecycle and the first-commit rollback clears it.
func TestStoreEverCommittedLifecycle(t *testing.T) {
	dir := t.TempDir()
	st, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}

	if st.EverCommitted() {
		t.Fatal("fresh store: EverCommitted=true; want false")
	}

	// A real commit sets the marker.
	if err := st.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := st.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	st.ExitConfigure()
	if !st.EverCommitted() {
		t.Fatal("after Commit: EverCommitted=false; want true")
	}
}

// TestFirstCommitRollbackWritesNeverCommittedMarker proves Item 1b: a
// first commit confirmed on a fresh store, rolled back on timeout, persists
// the never-committed marker (committed=0) and NOT an operator-committed-empty
// tree, and clears the in-memory everCommitted flag.
func TestFirstCommitRollbackWritesNeverCommittedMarker(t *testing.T) {
	dir := t.TempDir()
	st, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}

	var lastCommitted bool
	var sawMarkerWrite bool
	st.SetWriteActiveMarkerForTesting(func(_ *config.ConfigTree, committed bool) error {
		sawMarkerWrite = true
		lastCommitted = committed
		return nil
	})

	// First commit confirmed on a fresh store.
	if err := st.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := st.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := st.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	st.ExitConfigure()
	if !st.EverCommitted() {
		t.Fatal("after CommitConfirmed: EverCommitted=false; want true (committed-to-disk)")
	}

	// Drive the rollback timer dispatch deterministically.
	gen := st.ConfirmGenForTesting()
	prevCfg, ok := st.PromoteRollback(gen)
	if !ok {
		t.Fatal("PromoteRollback: ok=false; want true (first-commit revert)")
	}
	if prevCfg != nil {
		t.Fatal("PromoteRollback: prevCfg != nil on first-commit rollback; want nil")
	}
	if !sawMarkerWrite {
		t.Fatal("first-commit rollback did not write the never-committed marker")
	}
	if lastCommitted {
		t.Fatal("first-commit rollback wrote committed=true; want committed=false (never-committed)")
	}
	if st.EverCommitted() {
		t.Fatal("after first-commit rollback: EverCommitted=true; want false")
	}
}
