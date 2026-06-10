package configstore

// #1799 persist-failure semantics tests.
//
// Option A (operator commits): a WriteActive failure fails the commit
// BEFORE any in-memory promotion — candidate intact, active unchanged,
// no history/journal/rollback-file side effects. A restart after a
// failed persist therefore loads the PREVIOUS config, never a
// half-committed one.

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

var errDiskFull = errors.New("injected: no space left on device")

// failingWriteActive returns a seam that always fails.
func failingWriteActive(*config.ConfigTree) error { return errDiskFull }

// commitBaseline commits one zone so the store has a non-empty active
// config and returns the store.
func commitBaseline(t *testing.T, s *Store) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone trust interfaces eth0.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("baseline Commit: %v", err)
	}
}

func TestCommit_PersistFailureFailsCommitCleanly(t *testing.T) {
	for _, variant := range []string{"commit", "commit-with-description"} {
		t.Run(variant, func(t *testing.T) {
			s := newTestStore(t)
			commitBaseline(t, s)

			activeBefore := s.ShowActiveSet()
			historyBefore := len(s.ListHistory())
			journalBefore, err := s.ListCommitHistory(0)
			if err != nil {
				t.Fatalf("ListCommitHistory: %v", err)
			}

			if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
				t.Fatalf("SetFromInput: %v", err)
			}
			s.SetWriteActiveForTesting(failingWriteActive)

			var commitErr error
			if variant == "commit" {
				_, commitErr = s.Commit()
			} else {
				_, commitErr = s.CommitWithDescription("test change")
			}
			if commitErr == nil {
				t.Fatal("expected commit to fail on persist failure, got nil")
			}
			if !errors.Is(commitErr, errDiskFull) {
				t.Fatalf("commit error should wrap the persist error: %v", commitErr)
			}

			// Active unchanged in memory.
			if got := s.ShowActiveSet(); got != activeBefore {
				t.Errorf("active changed despite failed commit:\nbefore: %s\nafter: %s", activeBefore, got)
			}
			// Candidate intact (still dirty, still carries the edit).
			if !s.IsDirty() {
				t.Error("candidate should remain dirty after failed commit")
			}
			if !strings.Contains(s.ShowCandidateSet(), "untrust") {
				t.Error("candidate edit lost after failed commit")
			}
			// No history push.
			if got := len(s.ListHistory()); got != historyBefore {
				t.Errorf("history grew on failed commit: %d -> %d", historyBefore, got)
			}
			// No journal entry.
			journalAfter, err := s.ListCommitHistory(0)
			if err != nil {
				t.Fatalf("ListCommitHistory: %v", err)
			}
			if len(journalAfter) != len(journalBefore) {
				t.Errorf("journal grew on failed commit: %d -> %d", len(journalBefore), len(journalAfter))
			}
			// Retry succeeds once the seam is removed.
			s.SetWriteActiveForTesting(nil)
			if _, err := s.Commit(); err != nil {
				t.Fatalf("retry Commit after clearing seam: %v", err)
			}
			if !strings.Contains(s.ShowActiveSet(), "untrust") {
				t.Error("retried commit did not promote the candidate")
			}
		})
	}
}

// TestRestart_AfterFailedOperatorPersistLoadsPreviousConfig proves the
// Option A end-to-end property with a real Load() from the on-disk DB:
// after a failed operator commit, a daemon restart serves the PREVIOUS
// active config — not a half-committed one — and the operator saw an
// error rather than "commit complete".
func TestRestart_AfterFailedOperatorPersistLoadsPreviousConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	s1 := New(path)
	commitBaseline(t, s1)

	if err := s1.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	s1.SetWriteActiveForTesting(failingWriteActive)
	if _, err := s1.Commit(); err == nil {
		t.Fatal("expected commit to fail on persist failure")
	}

	// "Restart": fresh store, real Load from disk.
	s2 := New(path)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg := s2.ActiveConfig()
	if cfg == nil {
		t.Fatal("loaded config is nil")
	}
	if _, ok := cfg.Security.Zones["trust"]; !ok {
		t.Error("restart lost the previously committed config")
	}
	if _, ok := cfg.Security.Zones["untrust"]; ok {
		t.Error("restart loaded the failed (never-committed) config")
	}
}
