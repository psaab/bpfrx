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

// TestCommitConfirmed_NotArmedOnPersistFailure: a persist failure must
// not arm the confirm timer or set any confirm state (#1799).
func TestCommitConfirmed_NotArmedOnPersistFailure(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)

	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	s.SetWriteActiveForTesting(failingWriteActive)

	if _, err := s.CommitConfirmed(1); err == nil {
		t.Fatal("expected CommitConfirmed to fail on persist failure")
	}
	if s.IsConfirmPending() {
		t.Error("confirm timer must not be armed after a failed persist")
	}
	if s.confirmPrevTree != nil || s.confirmPrevCfg != nil {
		t.Error("confirm state must not be set after a failed persist")
	}
	if !s.IsDirty() {
		t.Error("candidate should remain dirty after failed commit confirmed")
	}
	if strings.Contains(s.ShowActiveSet(), "untrust") {
		t.Error("active must not be promoted after failed commit confirmed")
	}
}

// TestCommitConfirmed_PersistFailurePreservesExistingConfirmState: when
// a confirmed commit is already pending, a SECOND CommitConfirmed whose
// persist fails must leave the existing timer and rollback target
// untouched — the pending commit-1 must still auto-roll-back to the
// last confirmed config if never confirmed (#1799 ordering invariant).
func TestCommitConfirmed_PersistFailurePreservesExistingConfirmState(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s) // last confirmed config: trust only
	baseSet := s.ShowActiveSet()

	// Pending confirmed commit 1 (succeeds).
	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed 1: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("commit 1 should be pending")
	}
	prevTreeBefore := s.confirmPrevTree.FormatSet()
	timerBefore := s.confirmTimer

	// Commit 2 fails to persist.
	if err := s.SetFromInput("security zones security-zone dmz interfaces eth2.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	s.SetWriteActiveForTesting(failingWriteActive)
	if _, err := s.CommitConfirmed(1); err == nil {
		t.Fatal("expected CommitConfirmed 2 to fail on persist failure")
	}

	if !s.IsConfirmPending() {
		t.Error("pending commit-1 confirm state must survive a failed commit 2")
	}
	if s.confirmTimer != timerBefore {
		t.Error("commit-1 timer must not be cancelled/replaced by a failed commit 2")
	}
	if got := s.confirmPrevTree.FormatSet(); got != prevTreeBefore {
		t.Errorf("rollback target changed on failed commit 2:\nbefore: %s\nafter: %s", prevTreeBefore, got)
	}
	if got := prevTreeBefore; got != baseSet {
		t.Errorf("rollback target should be the last confirmed config:\nwant: %s\ngot: %s", baseSet, got)
	}
	if strings.Contains(s.ShowActiveSet(), "dmz") {
		t.Error("active must not include the failed commit-2 edit")
	}
}

// TestNestedCommitConfirmed_PreservesLastConfirmedTree pins the nested
// CommitConfirmed defect (#1799 / plan §5.2): a second CommitConfirmed
// while one is pending must keep the LAST CONFIRMED config as the
// rollback target — not the unconfirmed commit-1 tree — so a commit-2
// timeout reverts to a config the operator actually confirmed.
func TestNestedCommitConfirmed_PreservesLastConfirmedTree(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s) // last confirmed config: trust only
	baseSet := s.ShowActiveSet()

	// Pending confirmed commit 1 (never confirmed).
	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed 1: %v", err)
	}

	// Nested confirmed commit 2 (also never confirmed).
	if err := s.SetFromInput("security zones security-zone dmz interfaces eth2.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed 2: %v", err)
	}

	if got := s.confirmPrevTree.FormatSet(); got != baseSet {
		t.Errorf("nested commit overwrote the rollback target:\nwant last confirmed: %s\ngot: %s", baseSet, got)
	}

	// Drive the timer expiry directly: the rollback must land on the
	// last confirmed config, not on the unconfirmed commit-1 tree.
	s.performAutoRollback()
	got := s.ShowActiveSet()
	if got != baseSet {
		t.Errorf("auto-rollback landed on the wrong config:\nwant: %s\ngot: %s", baseSet, got)
	}
	if strings.Contains(got, "untrust") || strings.Contains(got, "dmz") {
		t.Error("auto-rollback must drop both unconfirmed commits")
	}
}
