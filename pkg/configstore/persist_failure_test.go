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
	"sync/atomic"
	"testing"
	"time"

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
	s.performAutoRollback(s.confirmGen)
	got := s.ShowActiveSet()
	if got != baseSet {
		t.Errorf("auto-rollback landed on the wrong config:\nwant: %s\ngot: %s", baseSet, got)
	}
	if strings.Contains(got, "untrust") || strings.Contains(got, "dmz") {
		t.Error("auto-rollback must drop both unconfirmed commits")
	}
}

const syncContent = "security {\n" +
	"    zones {\n" +
	"        security-zone synced {\n" +
	"            interfaces {\n" +
	"                eth3.0;\n" +
	"            }\n" +
	"        }\n" +
	"    }\n" +
	"}\n"

// waitForCondition polls fn until it returns true or the deadline expires.
func waitForCondition(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestSyncApply_DegradesNotFails: Option B (#1799) — the HA config-sync
// receive path must still apply in memory on persist failure (cluster
// convergence wins), flip the degraded flag, and self-heal via the
// background retry, which clears the flag and lands the config on disk.
func TestSyncApply_DegradesNotFails(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	s.ExitConfigure()

	s.SetPersistRetryBackoffForTesting(time.Millisecond, 4*time.Millisecond)

	var failing atomic.Bool
	failing.Store(true)
	s.SetWriteActiveForTesting(func(tree *config.ConfigTree) error {
		if failing.Load() {
			return errDiskFull
		}
		return s.db.WriteActive(tree)
	})

	compiled, err := s.SyncApply(syncContent, nil)
	if err != nil {
		t.Fatalf("SyncApply must not fail on persist failure (Option B): %v", err)
	}
	if compiled == nil {
		t.Fatal("SyncApply returned nil compiled config")
	}
	// In-memory apply succeeded.
	if _, ok := compiled.Security.Zones["synced"]; !ok {
		t.Error("synced zone missing from compiled config")
	}
	if !strings.Contains(s.ShowActiveSet(), "synced") {
		t.Error("synced config not promoted to active despite Option B")
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("degraded flag must be set after a failed sync persist")
	}

	// Heal the disk; the retry loop must clear the flag and persist
	// the CURRENT active config.
	failing.Store(false)
	waitForCondition(t, "degraded flag to clear", func() bool {
		return !s.ConfigPersistDegraded()
	})
	tree, err := s.db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive: %v", err)
	}
	if tree == nil || !strings.Contains(tree.FormatSet(), "synced") {
		t.Error("retry loop did not persist the synced config to disk")
	}
}

// TestSyncApply_PersistFailureRetryIsSingleton: repeated Option-B
// failures must not spawn concurrent retry goroutines racing on disk
// writes — the singleton guard keeps exactly one loop.
func TestSyncApply_PersistFailureRetryIsSingleton(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	s.ExitConfigure()

	// Long backoff so the first loop is still alive across both failures.
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

	var writes atomic.Int32
	s.SetWriteActiveForTesting(func(*config.ConfigTree) error {
		writes.Add(1)
		return errDiskFull
	})

	if _, err := s.SyncApply(syncContent, nil); err != nil {
		t.Fatalf("SyncApply 1: %v", err)
	}
	if _, err := s.SyncApply(syncContent, nil); err != nil {
		t.Fatalf("SyncApply 2: %v", err)
	}

	s.mu.RLock()
	active := s.persistRetryActive
	degraded := s.persistDegraded
	s.mu.RUnlock()
	if !active {
		t.Error("retry goroutine should be active")
	}
	if !degraded {
		t.Error("degraded flag should be set")
	}
	// Only the two SyncApply writes happened — the hour-long backoff
	// means no retry write yet, and a duplicate goroutine would have
	// been observable as state churn in the assertions above.
	if got := writes.Load(); got != 2 {
		t.Errorf("unexpected write count %d, want 2 (sync attempts only)", got)
	}
}

// TestAutoRollback_ProceedsAndFlagsOnPersistFailure: Option B (#1799)
// for the confirm-timer expiry path — the in-memory rollback always
// proceeds (reverting the running config is the safety property), a
// persist failure sets the degraded flag, and the background retry
// heals the disk so a reboot loads the ROLLED-BACK config, not the
// unconfirmed candidate the failed write left behind.
func TestAutoRollback_ProceedsAndFlagsOnPersistFailure(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s) // confirmed base: trust only
	baseSet := s.ShowActiveSet()

	s.SetPersistRetryBackoffForTesting(time.Millisecond, 4*time.Millisecond)

	// Pending confirmed commit (persists fine; disk now holds the
	// unconfirmed candidate).
	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}

	// Disk breaks before the timer fires.
	var failing atomic.Bool
	failing.Store(true)
	s.SetWriteActiveForTesting(func(tree *config.ConfigTree) error {
		if failing.Load() {
			return errDiskFull
		}
		return s.db.WriteActive(tree)
	})

	s.performAutoRollback(s.confirmGen)

	// The in-memory rollback proceeded.
	if got := s.ShowActiveSet(); got != baseSet {
		t.Errorf("rollback did not revert active in memory:\nwant: %s\ngot: %s", baseSet, got)
	}
	if s.IsConfirmPending() {
		t.Error("confirm state should be cleared after auto-rollback")
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("degraded flag must be set after failed rollback persist")
	}

	// Heal the disk: the retry must replace the unconfirmed candidate
	// on disk with the rolled-back config.
	failing.Store(false)
	waitForCondition(t, "degraded flag to clear", func() bool {
		return !s.ConfigPersistDegraded()
	})
	tree, err := s.db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive: %v", err)
	}
	if tree == nil {
		t.Fatal("no active config on disk")
	}
	persisted := tree.FormatSet()
	if strings.Contains(persisted, "untrust") {
		t.Error("disk still holds the unconfirmed candidate after retry healed")
	}
	if persisted != baseSet {
		t.Errorf("disk should hold the rolled-back config:\nwant: %s\ngot: %s", baseSet, persisted)
	}
}

// TestCommit_SuccessClearsDegradedFlag: a successful Option-A commit
// persists the newest active config, so the degraded state ends even
// before the retry loop's next attempt.
func TestCommit_SuccessClearsDegradedFlag(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	s.ExitConfigure()

	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	s.SetWriteActiveForTesting(failingWriteActive)
	if _, err := s.SyncApply(syncContent, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("degraded flag must be set")
	}

	s.SetWriteActiveForTesting(nil)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone trust2 interfaces eth4.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if s.ConfigPersistDegraded() {
		t.Error("successful commit persisted the current config; degraded flag must clear")
	}
}

// TestStaleConfirmTimerCallbackIsNoOp pins the generation guard from
// the Codex review on PR #1817: time.Timer.Stop() cannot un-fire a
// callback that has already started and is blocked on s.mu. A stale
// callback whose generation was superseded — by a nested
// CommitConfirmed re-arm or by ConfirmCommit — must no-op instead of
// rolling a NEWER commit back to an older tree.
func TestStaleConfirmTimerCallbackIsNoOp(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "config"))
	commitBaseline(t, s)

	// Commit 1 confirmed: arms timer generation g1.
	if err := s.SetFromInput("security zones security-zone confirm1 interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed 1: %v", err)
	}
	g1 := s.confirmGen

	// Nested commit 2 confirmed: supersedes g1 with g2.
	if err := s.SetFromInput("security zones security-zone confirm2 interfaces eth2.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed 2: %v", err)
	}

	// Model commit 1's timer callback having fired pre-supersede and
	// only now acquiring the lock: it must not roll anything back.
	s.performAutoRollback(g1)
	cfg := s.ActiveConfig()
	if _, ok := cfg.Security.Zones["confirm2"]; !ok {
		t.Fatal("stale callback rolled back the newer nested confirmed commit")
	}
	if !s.IsConfirmPending() {
		t.Fatal("stale callback cleared the newer commit's confirm state")
	}

	// Same for a confirmed (ConfirmCommit) window: stale callback
	// after explicit confirmation must no-op.
	g2 := s.confirmGen
	if err := s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	s.performAutoRollback(g2)
	cfg = s.ActiveConfig()
	if _, ok := cfg.Security.Zones["confirm2"]; !ok {
		t.Fatal("stale callback rolled back an explicitly confirmed commit")
	}
}
