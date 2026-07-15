package configstore

// #5835: a commit-confirmed CONFIRMATION must not report success while the
// durable removal of confirm.json (the crash-recovery record) has failed — a
// restart would then read the stale record and resurrect a rollback that
// reverts the operator-confirmed config. These tests cover the four required
// corrections:
//
//  1. EXPLICIT confirmation (ConfirmCommit) RETURNS the durable-removal error
//     and retains retry debt.
//  2. The post-unlink dir fsync (#4864) is REACHABLE on an absent-file retry —
//     a sync failure cannot be laundered into success by a later retry.
//  3. The non-returning resolution paths (plain commit / HA sync / demotion /
//     timeout & boot rollback) retain retry debt + expose DEGRADED health until
//     the removal is durable, and converge autonomously.
//  4. The record is bound to the config it guards (GuardedHash), so a stale
//     record cannot revert an unrelated, already-confirmed generation on boot.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

var (
	errInjectedConfirmUnlink  = errors.New("injected confirm.json unlink failure")
	errInjectedConfirmDirSync = errors.New("injected confirm-dir fsync failure")
)

// installConfirmDeleteSeams overrides the package durability seams so a test can
// fail the confirm.json unlink and/or its parent-dir fsync under atomic control
// while leaving every OTHER durability op (rollback slots, active writes)
// intact. Either flag may be nil (that fault is never injected). Seams are
// restored at test end via restoreRollbackSeams' t.Cleanup.
func installConfirmDeleteSeams(t *testing.T, failUnlink, failDirSync *atomic.Bool) {
	t.Helper()
	restoreRollbackSeams(t)
	rbRemove = func(path string) error {
		if failUnlink != nil && failUnlink.Load() && filepath.Base(path) == "confirm.json" {
			return errInjectedConfirmUnlink
		}
		return os.Remove(path)
	}
	rbSyncDir = func(dir string) error {
		if failDirSync != nil && failDirSync.Load() {
			return errInjectedConfirmDirSync
		}
		return fsatomic.SyncDir(dir)
	}
}

// stagePendingConfirmed stages a distinct interface+zone and arms a 1-minute
// commit-confirmed window over it. The staged leaf name is caller-supplied so
// successive commits are structurally distinct (distinct GuardedHash).
func stagePendingConfirmed(t *testing.T, s *Store, ifc, zone string) {
	t.Helper()
	if err := s.SetFromInput("interfaces " + ifc + " unit 0 family inet address 10.9.0.1/24"); err != nil {
		t.Fatalf("SetFromInput iface: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone " + zone + " interfaces " + ifc + ".0"); err != nil {
		t.Fatalf("SetFromInput zone: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("armed confirm.json must exist: rec=%v err=%v", rec, err)
	}
}

// commitPlainChange stages a distinct change and lands it as a plain commit,
// returning the resulting active set text.
func commitPlainChange(t *testing.T, s *Store, ifc, zone string) string {
	t.Helper()
	if err := s.SetFromInput("interfaces " + ifc + " unit 0 family inet address 10.8.0.1/24"); err != nil {
		t.Fatalf("SetFromInput iface: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone " + zone + " interfaces " + ifc + ".0"); err != nil {
		t.Fatalf("SetFromInput zone: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("plain Commit: %v", err)
	}
	return s.ShowActiveSet()
}

// TestExplicitConfirmReturnsErrorOnUnlinkFailure_5835 pins requirement 1: an
// injected confirm.json unlink failure makes the EXPLICIT ConfirmCommit RETURN
// an error (not report a false success) and retain retryable resolution state.
//
// RED on revert: restoring removeConfirmState() to a void/log-only helper makes
// ConfirmCommit return nil (and leaves no retry debt) — both assertions fail.
func TestExplicitConfirmReturnsErrorOnUnlinkFailure_5835(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	var failUnlink atomic.Bool
	installConfirmDeleteSeams(t, &failUnlink, nil)

	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour) // keep the retry dormant

	stagePendingConfirmed(t, s, "eth1", "untrust")

	failUnlink.Store(true)
	err := s.ConfirmCommit()
	if err == nil {
		t.Fatal("ConfirmCommit must RETURN an error when the durable removal of confirm.json " +
			"fails (#5835): a silent success lets a restart resurrect the stale rollback")
	}
	if !s.ConfirmRemovalDegraded() {
		t.Error("a failed confirm.json removal must retain retry debt (ConfirmRemovalDegraded)")
	}
	if !s.ConfigPersistDegraded() {
		t.Error("confirm-removal degradation must surface via ConfigPersistDegraded (/health)")
	}
	if rec, rerr := s.db.ReadConfirm(); rerr != nil || rec == nil {
		t.Fatalf("confirm.json must still be present after a failed removal: rec=%v err=%v", rec, rerr)
	}
	// The window IS resolved in memory (the timer was cancelled) — only the
	// durable removal failed. A subsequent restart is what would resurrect it.
	if s.IsConfirmPending() {
		t.Error("the in-memory confirm window must be resolved after ConfirmCommit despite the failed removal")
	}
}

// TestDeleteConfirmDirSyncFailureNotLaunderedByAbsentRetry_5835 pins
// requirement 4: a post-unlink dir-fsync failure cannot be converted into a
// success by an absent-file retry — the #4864 dir fsync must be reachable AND
// gate success on the retry.
//
// RED on revert: restoring the `os.IsNotExist -> return nil` short-circuit
// before the dir fsync makes the second (absent-file) DeleteConfirm return nil
// while the sync is still failing.
func TestDeleteConfirmDirSyncFailureNotLaunderedByAbsentRetry_5835(t *testing.T) {
	var failDirSync atomic.Bool
	installConfirmDeleteSeams(t, nil, &failDirSync)

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.db.WriteConfirm(&confirmRecord{Deadline: time.Now().Add(10 * time.Minute)}); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}

	failDirSync.Store(true)
	// First attempt: unlink succeeds, the dir fsync fails -> error. The file is
	// now absent on disk but the removal is NOT durable.
	if err := s.db.DeleteConfirm(); err == nil {
		t.Fatal("DeleteConfirm must fail when the post-unlink dir fsync fails")
	}
	if _, err := os.Stat(s.db.confirmPath()); !os.IsNotExist(err) {
		t.Fatalf("confirm.json should be unlinked even though the dir sync failed: err=%v", err)
	}
	// Absent-file RETRY with the sync STILL failing: must still fail, not launder
	// the non-durable removal into a false success.
	if err := s.db.DeleteConfirm(); err == nil {
		t.Fatal("an absent-file DeleteConfirm retry must NOT report success while the dir fsync " +
			"still fails (#5835): the #4864 durability sync must gate success on the retry")
	}
	// Heal: the sync now succeeds -> the removal is durable.
	failDirSync.Store(false)
	if err := s.db.DeleteConfirm(); err != nil {
		t.Fatalf("DeleteConfirm must succeed once the dir fsync succeeds: %v", err)
	}
}

// TestResolutionPathsRetainRetryDebtUntilConvergence_5835 pins requirements 2/3
// for the non-returning resolution paths: plain commit, HA config-sync, and RG0
// demotion. Each must, on a failed confirm.json removal, RETAIN retry debt +
// expose DEGRADED health without irreversibly losing the ability to retry, then
// CONVERGE (record deleted, health cleared) once the fault clears.
//
// RED on revert: restoring removeConfirmState() to void leaves no retry debt so
// ConfirmRemovalDegraded is never set (the "retain" assertion fails).
func TestResolutionPathsRetainRetryDebtUntilConvergence_5835(t *testing.T) {
	cases := []struct {
		name    string
		resolve func(t *testing.T, s *Store)
	}{
		{"plain-commit", func(t *testing.T, s *Store) { commitPlainChange(t, s, "eth3", "dmz") }},
		{"config-sync", func(t *testing.T, s *Store) {
			if _, err := s.SyncApply(syncContent, nil); err != nil {
				t.Fatalf("SyncApply: %v", err)
			}
		}},
		{"demotion", func(t *testing.T, s *Store) {
			if !s.ConfirmPendingOnDemotion() {
				t.Fatal("demotion must resolve the pending window")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			var failUnlink atomic.Bool
			installConfirmDeleteSeams(t, &failUnlink, nil)

			s := newTestStoreAt(t, path)
			commitBaseline(t, s)
			s.SetPersistRetryBackoffForTesting(time.Millisecond, 4*time.Millisecond) // fast heal
			stagePendingConfirmed(t, s, "eth1", "untrust")

			failUnlink.Store(true)
			tc.resolve(t, s)

			// Retry debt is retained and health is degraded.
			if !s.ConfirmRemovalDegraded() {
				t.Fatalf("%s: a failed confirm.json removal must retain retry debt", tc.name)
			}
			if !s.ConfigPersistDegraded() {
				t.Fatalf("%s: retry debt must surface via ConfigPersistDegraded (/health)", tc.name)
			}
			if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
				t.Fatalf("%s: stale confirm.json must be retained until removal is durable: rec=%v err=%v", tc.name, rec, err)
			}

			// Fault clears -> the background retry converges.
			failUnlink.Store(false)
			waitForCondition(t, tc.name+": confirm-removal debt to clear", func() bool {
				return !s.ConfirmRemovalDegraded()
			})
			if rec, err := s.db.ReadConfirm(); err != nil || rec != nil {
				t.Fatalf("%s: confirm.json must be removed once the retry converges: rec=%v err=%v", tc.name, rec, err)
			}
			if s.ConfigPersistDegraded() {
				t.Errorf("%s: health must clear once the removal is durable", tc.name)
			}
		})
	}
}

// TestStaleRecordDoesNotRevertConfirmedGenerationOnBoot_5835 is the headline
// (requirement 5 / test 4): after a resolution whose confirm.json removal
// failed, a fresh Store.Load must NOT roll back a generation that was durably
// committed AFTER the failed removal. The record is bound to the config it
// guards, so once the active config has advanced the record is recognized as
// stale and ignored.
//
// RED on revert: removing the GuardedHash staleness check in
// recoverPendingConfirmLocked makes the deadline-past boot roll the durably
// committed generation back to the pre-confirm target.
func TestStaleRecordDoesNotRevertConfirmedGenerationOnBoot_5835(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	var failUnlink atomic.Bool
	installConfirmDeleteSeams(t, &failUnlink, nil)

	s := newTestStoreAt(t, path)
	commitBaseline(t, s)                                     // A
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour) // dormant: keep the stale record on disk

	stagePendingConfirmed(t, s, "eth1", "untrust") // pending B: confirm.json guards B, rollback A

	// Resolve via a plain commit C while the unlink fails: active advances to C
	// (durably committed) but the stale record lingers guarding B / rollback A.
	failUnlink.Store(true)
	committedSet := commitPlainChange(t, s, "eth3", "dmz")
	if !s.ConfirmRemovalDegraded() {
		t.Fatal("the plain-commit resolution must retain retry debt after the failed removal")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("stale confirm.json must linger after the failed removal: rec=%v err=%v", rec, err)
	}

	// Crash + restart with the deadline forced past, so WITHOUT the generation
	// binding boot recovery would immediately roll C back to A.
	forceConfirmDeadlinePast(t, path)
	failUnlink.Store(false) // let the fresh store actually delete the recognized-stale record

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot Load after crash: %v", err)
	}
	if got := s2.ShowActiveSet(); got != committedSet {
		t.Fatalf("stale confirm.json resurrected a rollback of the durably-committed generation:\n"+
			"want %s\ngot  %s", committedSet, got)
	}
	if rec, err := s2.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("the recognized-stale record must be removed on boot: rec=%v err=%v", rec, err)
	}
}

// TestGenerationBindingNestedAndFirstCommit_5835 extends the generation-binding
// coverage to a NESTED confirmed commit (rollback target stays the original
// last-confirmed config, GuardedHash tracks the re-armed config) and to a
// FIRST-commit window (rollback target is the empty bootstrap tree). In both,
// once the active config advances the lingering record is recognized as stale
// and does not resurrect a rollback.
func TestGenerationBindingNestedAndFirstCommit_5835(t *testing.T) {
	t.Run("nested-confirmed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config")
		var failUnlink atomic.Bool
		installConfirmDeleteSeams(t, &failUnlink, nil)

		s := newTestStoreAt(t, path)
		commitBaseline(t, s) // A
		s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

		stagePendingConfirmed(t, s, "eth1", "untrust") // window B (guards B, rollback A)
		stagePendingConfirmed(t, s, "eth2", "guest")   // NESTED re-arm C (rollback stays A, GuardedHash=C)

		failUnlink.Store(true)
		committedSet := commitPlainChange(t, s, "eth3", "dmz") // resolve -> active D, stale record guards C
		if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
			t.Fatalf("stale nested confirm.json must linger: rec=%v err=%v", rec, err)
		}

		forceConfirmDeadlinePast(t, path)
		failUnlink.Store(false)
		s2 := newTestStoreAt(t, path)
		if err := s2.Load(); err != nil {
			t.Fatalf("boot Load: %v", err)
		}
		if got := s2.ShowActiveSet(); got != committedSet {
			t.Fatalf("nested stale record resurrected a rollback:\nwant %s\ngot  %s", committedSet, got)
		}
	})

	t.Run("first-commit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config")
		var failUnlink atomic.Bool
		installConfirmDeleteSeams(t, &failUnlink, nil)

		s := newTestStoreAt(t, path)
		if err := s.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
		// FIRST commit on a fresh store IS a commit-confirmed (FirstCommit=true,
		// rollback target = empty bootstrap tree).
		stagePendingConfirmed(t, s, "eth1", "untrust")
		if rec, err := s.db.ReadConfirm(); err != nil || rec == nil || !rec.FirstCommit {
			t.Fatalf("first-commit confirm record must have FirstCommit=true: rec=%v err=%v", rec, err)
		}

		failUnlink.Store(true)
		committedSet := commitPlainChange(t, s, "eth3", "dmz") // active advances; stale first-commit record lingers

		forceConfirmDeadlinePast(t, path)
		failUnlink.Store(false)
		s2 := newTestStoreAt(t, path)
		if err := s2.Load(); err != nil {
			t.Fatalf("boot Load: %v", err)
		}
		// Without the binding, boot would roll the committed config back to the
		// EMPTY bootstrap tree (the most destructive resurrection).
		if got := s2.ShowActiveSet(); got != committedSet {
			t.Fatalf("first-commit stale record resurrected a rollback to bootstrap:\nwant %s\ngot  %s", committedSet, got)
		}
		if strings.TrimSpace(s2.ShowActiveSet()) == "" {
			t.Fatal("active config was reverted to the empty bootstrap tree by a stale first-commit record")
		}
	})
}

// TestConfirmRemoveRetryRaceSafe_5835 exercises the confirm-removal retry loop
// concurrently with commits and confirm-state reads under -race: the retry loop
// runs on its own goroutine mutating confirmRemoveDegraded under s.mu while the
// main path commits and reads health. It validates there is no data race on the
// new state and that the loop converges once the fault clears.
func TestConfirmRemoveRetryRaceSafe_5835(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	var failUnlink atomic.Bool
	installConfirmDeleteSeams(t, &failUnlink, nil)

	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(time.Millisecond, 2*time.Millisecond) // churn the retry loop

	stagePendingConfirmed(t, s, "eth1", "untrust")

	// Fail the removal, resolve the window (starts the retry loop), then churn
	// concurrent reads/commits while the loop spins.
	failUnlink.Store(true)
	commitPlainChange(t, s, "eth3", "dmz")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = s.ConfigPersistDegraded()
			_ = s.ConfirmRemovalDegraded()
			_ = s.IsConfirmPending()
		}
	}()
	for i := 0; i < 50; i++ {
		_ = s.ConfirmRemovalDegraded()
	}
	<-done

	// Clear the fault; the retry loop must converge.
	failUnlink.Store(false)
	waitForCondition(t, "confirm-removal debt to clear under concurrency", func() bool {
		return !s.ConfirmRemovalDegraded()
	})
	if rec, err := s.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("confirm.json must be removed once the retry converges: rec=%v err=%v", rec, err)
	}
}
