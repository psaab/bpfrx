package configstore

// #5185 post-rename directory-fsync durability semantics.
//
// fsatomic distinguishes a PRE-rename write failure (old active intact on
// disk — a clean rejection is correct) from a POST-rename directory-fsync
// failure (the NEW content C is already visible on disk; a restart would
// load C) via a typed *fsatomic.PostRenameSyncError. Commit and
// CommitConfirmed classify the failure:
//
//   - pre-rename  -> plain rejection, active (A) untouched (existing #1799
//     Option-A behavior, unchanged).
//   - post-rename -> CONVERGE: promote C in memory, return the compiled
//     config so the daemon applies C, and flag the durability uncertainty
//     via the Option-B degraded machinery. This restores the invariant
//     durable==in-memory==applied (all == C), because C is exactly what a
//     restart would load. Returning a plain "commit failed" here would
//     leave durable(C) != memory/applied(A) — the operator told REJECTED
//     while a restart activates C.
//
// These tests FAIL RED if the post-rename classification is reverted (a
// post-rename failure reported as a plain rejection while C is durable).

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

var errPostRenameDirFsync = errors.New("injected: directory fsync after rename failed")

// postRenameFailingWriteActive models a post-rename dir-fsync failure: the
// content actually LANDS on disk (the rename succeeded — s.db.WriteActive
// performs the full durable write) but the call reports the typed
// *fsatomic.PostRenameSyncError so the durability of the rename is
// "unknown". A restart therefore loads C, exactly the real failure's state.
func postRenameFailingWriteActive(s *Store) func(*config.ConfigTree) error {
	return func(tree *config.ConfigTree) error {
		if err := s.db.WriteActive(tree); err != nil {
			return err
		}
		return &fsatomic.PostRenameSyncError{Path: "active.json", Err: errPostRenameDirFsync}
	}
}

// addUntrustEdit stages the standard "untrust" edit used across these tests.
func addUntrustEdit(t *testing.T, s *Store) {
	t.Helper()
	if err := s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24"); err != nil {
		t.Fatalf("SetFromInput (iface): %v", err)
	}
	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput (zone): %v", err)
	}
}

// TestCommit_PostRenameConvergesToC: a post-rename dir-fsync failure on a
// PLAIN commit must NOT be a rejection. The commit converges to C —
// compiled returned (daemon applies), in-memory active == C — and the
// degraded flag is raised.
func TestCommit_PostRenameConvergesToC(t *testing.T) {
	for _, variant := range []string{"commit", "commit-with-description"} {
		t.Run(variant, func(t *testing.T) {
			s := newTestStore(t)
			commitBaseline(t, s)
			// Long backoff: the degraded-retry loop must not churn the seam
			// mid-assertion.
			s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

			addUntrustEdit(t, s)
			s.SetWriteActiveForTesting(postRenameFailingWriteActive(s))

			var compiled *config.Config
			var err error
			if variant == "commit" {
				compiled, err = s.Commit()
			} else {
				compiled, err = s.CommitWithDescription("post-rename change")
			}

			// (a) Typed degraded-SUCCESS, not a plain rejection.
			if err != nil {
				t.Fatalf("post-rename commit must not be a plain rejection: %v", err)
			}
			if compiled == nil {
				t.Fatal("post-rename commit must return the compiled config for the daemon to apply")
			}
			if _, ok := compiled.Security.Zones["untrust"]; !ok {
				t.Error("compiled config must carry the committed (C) edit")
			}

			// (b) In-memory/applied active converged to C.
			if !strings.Contains(s.ShowActiveSet(), "untrust") {
				t.Error("in-memory active must converge to C after a post-rename failure")
			}
			if s.IsDirty() {
				t.Error("candidate should be clean after the converged commit")
			}

			// Durability uncertainty is surfaced.
			if !s.ConfigPersistDegraded() {
				t.Error("degraded flag must be set after a post-rename durability failure")
			}

			// (c) Disk holds C — durable == in-memory == applied.
			tree, rerr := s.db.ReadActive()
			if rerr != nil {
				t.Fatalf("ReadActive: %v", rerr)
			}
			if tree == nil || !strings.Contains(tree.FormatSet(), "untrust") {
				t.Error("on-disk active must be C (the content the rename already made visible)")
			}
		})
	}
}

// TestCommitConfirmed_PostRenameConvergesToC: same classification on the
// commit-confirmed path — converge to C, arm the timer, flag degraded.
func TestCommitConfirmed_PostRenameConvergesToC(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

	addUntrustEdit(t, s)
	s.SetWriteActiveForTesting(postRenameFailingWriteActive(s))

	compiled, err := s.CommitConfirmed(10)
	if err != nil {
		t.Fatalf("post-rename commit-confirmed must not be a plain rejection: %v", err)
	}
	if compiled == nil {
		t.Fatal("post-rename commit-confirmed must return the compiled config")
	}
	if _, ok := compiled.Security.Zones["untrust"]; !ok {
		t.Error("compiled config must carry the committed (C) edit")
	}
	if !strings.Contains(s.ShowActiveSet(), "untrust") {
		t.Error("in-memory active must converge to C")
	}
	if !s.IsConfirmPending() {
		t.Error("commit-confirmed must arm the auto-rollback timer on the converged path")
	}
	if !s.ConfigPersistDegraded() {
		t.Error("degraded flag must be set after a post-rename durability failure")
	}
	tree, rerr := s.db.ReadActive()
	if rerr != nil {
		t.Fatalf("ReadActive: %v", rerr)
	}
	if tree == nil || !strings.Contains(tree.FormatSet(), "untrust") {
		t.Error("on-disk active must be C")
	}
}

// TestRestart_AfterPostRenameLoadsC is the end-to-end invariant: after a
// post-rename failure on a real on-disk DB, a daemon restart (fresh Store +
// Load) serves C — the config the operator's commit converged to — so
// durable == in-memory == applied. Covers BOTH plain commit and
// commit-confirmed. If the classification were reverted (plain rejection),
// memory would hold A while disk/restart holds C: the divergence this test
// pins.
func TestRestart_AfterPostRenameLoadsC(t *testing.T) {
	for _, variant := range []string{"commit", "commit-confirmed"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")

			s1 := newTestStoreAt(t, path)
			commitBaseline(t, s1)
			s1.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

			addUntrustEdit(t, s1)
			s1.SetWriteActiveForTesting(postRenameFailingWriteActive(s1))

			if variant == "commit" {
				if _, err := s1.Commit(); err != nil {
					t.Fatalf("post-rename Commit must converge, not reject: %v", err)
				}
			} else {
				if _, err := s1.CommitConfirmed(10); err != nil {
					t.Fatalf("post-rename CommitConfirmed must converge, not reject: %v", err)
				}
			}
			memActive := s1.ShowActiveSet()
			if !strings.Contains(memActive, "untrust") {
				t.Fatal("in-memory active must be C before the restart")
			}

			// "Restart": fresh store, real Load from disk.
			s2 := newTestStoreAt(t, path)
			if err := s2.Load(); err != nil {
				t.Fatalf("Load: %v", err)
			}
			cfg := s2.ActiveConfig()
			if cfg == nil {
				t.Fatal("loaded config is nil")
			}
			// durable(C) == in-memory(C) == applied(C): the restart loads the
			// converged config, not the pre-commit A.
			if _, ok := cfg.Security.Zones["untrust"]; !ok {
				t.Error("restart must load C (the converged, durable config), not A")
			}
		})
	}
}

// TestCommit_PreRenameStillCleanRejection guards the converse: a PRE-rename
// failure (a plain, non-typed error — old active intact) must still be a
// clean rejection with A untouched, for BOTH commit and commit-confirmed.
// A regression that classified every write error as post-rename would
// wrongly converge here.
func TestCommit_PreRenameStillCleanRejection(t *testing.T) {
	t.Run("commit", func(t *testing.T) {
		s := newTestStore(t)
		commitBaseline(t, s)
		activeBefore := s.ShowActiveSet()

		addUntrustEdit(t, s)
		s.SetWriteActiveForTesting(failingWriteActive) // plain errDiskFull

		compiled, err := s.Commit()
		if err == nil {
			t.Fatal("pre-rename failure must be a clean rejection")
		}
		if compiled != nil {
			t.Error("a rejected commit must not return a compiled config")
		}
		if !errors.Is(err, errDiskFull) {
			t.Errorf("rejection must wrap the underlying error: %v", err)
		}
		if got := s.ShowActiveSet(); got != activeBefore {
			t.Errorf("active changed on a pre-rename rejection:\nbefore: %s\nafter: %s", activeBefore, got)
		}
		if s.ConfigPersistDegraded() {
			t.Error("a pre-rename rejection must NOT set the degraded flag (nothing applied)")
		}
		if !s.IsDirty() {
			t.Error("candidate should remain dirty after a rejected commit")
		}
	})

	t.Run("commit-confirmed", func(t *testing.T) {
		s := newTestStore(t)
		commitBaseline(t, s)
		activeBefore := s.ShowActiveSet()

		addUntrustEdit(t, s)
		s.SetWriteActiveForTesting(failingWriteActive)

		compiled, err := s.CommitConfirmed(10)
		if err == nil {
			t.Fatal("pre-rename failure must be a clean rejection")
		}
		if compiled != nil {
			t.Error("a rejected commit-confirmed must not return a compiled config")
		}
		if s.IsConfirmPending() {
			t.Error("a rejected commit-confirmed must not arm the timer")
		}
		if got := s.ShowActiveSet(); got != activeBefore {
			t.Errorf("active changed on a pre-rename rejection:\nbefore: %s\nafter: %s", activeBefore, got)
		}
		if s.ConfigPersistDegraded() {
			t.Error("a pre-rename rejection must NOT set the degraded flag")
		}
	})
}
