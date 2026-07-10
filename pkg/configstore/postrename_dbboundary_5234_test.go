package configstore

// #5234 — prove the #5185 post-rename durability classification survives
// the DB layer's error-wrap boundary.
//
// db.go writeTreeMarked wraps every fsatomic failure as
// fmt.Errorf("persist %s: %w", path, err). The commit paths classify a
// post-rename durability failure with errors.As via
// isPostRenameDurabilityFailure and CONVERGE-to-C instead of rejecting. If
// that %w were ever downgraded to %v, errors.As would stop matching through
// the wrap → the classification silently regresses to the original
// plain-rejection-while-C-is-durable bug (#5185), with NO red test to catch
// it, because the existing converge tests inject via the Store's
// writeActiveFn seam, which BYPASSES the db.go wrap entirely.
//
// These tests close that gap by driving a REAL post-rename directory-fsync
// failure through the production db.WriteActive path (fsatomic's
// afterRenameSyncDir seam, exported for cross-package tests as
// SetAfterRenameSyncDirForTesting). They FAIL RED if db.go's `persist %w`
// is downgraded to %v — at that point isPostRenameDurabilityFailure returns
// false, so db.WriteActive's error stops classifying and Commit rejects
// instead of converging.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

var errDBBoundaryDirFsync = errors.New("injected: post-rename directory fsync failed")

// TestDB_WriteActive_PostRenameClassifiedThroughWrap is the focused
// boundary assertion: a real post-rename dir-fsync failure inside
// fsatomic.WriteFileDurable, surfaced through db.WriteActive's
// `persist %s: %w` wrap, must STILL classify as a post-rename durability
// failure. RED if the db.go wrap is downgraded from %w to %v.
func TestDB_WriteActive_PostRenameClassifiedThroughWrap(t *testing.T) {
	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}

	restore := fsatomic.SetAfterRenameSyncDirForTesting(func(string) error {
		return errDBBoundaryDirFsync
	})
	defer restore()

	err = db.WriteActive(&config.ConfigTree{})
	if err == nil {
		t.Fatal("db.WriteActive must surface the post-rename dir-fsync failure")
	}
	// The classification MUST survive the db.go `persist %w` wrap. This is
	// the exact regression (%w -> %v) the coverage gap left unguarded.
	if !isPostRenameDurabilityFailure(err) {
		t.Fatalf("post-rename classification must survive the db.go `persist %%w` wrap; "+
			"got %T: %v", err, err)
	}
	// Confirm the error actually traversed the db.go wrap (not a bare seam).
	if !strings.Contains(err.Error(), "persist ") {
		t.Errorf("error should carry the db.go persist wrap: %v", err)
	}
	if !errors.Is(err, errDBBoundaryDirFsync) {
		t.Errorf("wrapped error must still unwrap to the injected fsync cause: %v", err)
	}
	// Post-, not pre-rename: the rename already happened, so active.json is
	// visible on disk (ReadActive returns the just-written tree, not nil).
	got, rerr := db.ReadActive()
	if rerr != nil {
		t.Fatalf("ReadActive: %v", rerr)
	}
	if got == nil {
		t.Error("post-rename: active.json must be visible on disk (the rename succeeded)")
	}
}

// TestCommit_PostRenameThroughRealDBConvergesToC is the end-to-end sibling:
// with NO writeActiveFn seam, a real post-rename dir-fsync failure drives
// db.WriteActive -> writeTreeMarked (`persist %w`) -> WriteFileDurable ->
// *PostRenameSyncError, and Commit must CONVERGE to C (not reject). This
// exercises the whole chain the writeActiveFn-seam converge tests skip. RED
// if the db.go wrap is downgraded to %v (Commit would then reject).
func TestCommit_PostRenameThroughRealDBConvergesToC(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	// Long backoff so the degraded-retry loop does not churn the seam while
	// the assertions run.
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

	addUntrustEdit(t, s)

	// Force the post-rename dir-fsync to fail inside fsatomic AFTER the
	// baseline commit + candidate edit have already persisted normally.
	restore := fsatomic.SetAfterRenameSyncDirForTesting(func(string) error {
		return errDBBoundaryDirFsync
	})
	defer restore()

	compiled, err := s.Commit()
	if err != nil {
		t.Fatalf("post-rename commit via the real DB must converge, not reject: %v", err)
	}
	if compiled == nil {
		t.Fatal("converged commit must return the compiled config for the daemon to apply")
	}
	if _, ok := compiled.Security.Zones["untrust"]; !ok {
		t.Error("compiled config must carry the committed (C) edit")
	}
	if !strings.Contains(s.ShowActiveSet(), "untrust") {
		t.Error("in-memory active must converge to C after a post-rename failure")
	}
	if !s.ConfigPersistDegraded() {
		t.Error("degraded flag must be set after a post-rename durability failure")
	}
	// The rename made C visible before the dir-fsync failed: disk holds C.
	tree, rerr := s.db.ReadActive()
	if rerr != nil {
		t.Fatalf("ReadActive: %v", rerr)
	}
	if tree == nil || !strings.Contains(tree.FormatSet(), "untrust") {
		t.Error("on-disk active must be C (the content the rename already made visible)")
	}
}
