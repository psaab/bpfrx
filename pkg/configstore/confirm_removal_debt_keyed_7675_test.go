package configstore

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// #7675: the #5835 confirm.json REMOVAL DEBT must know WHICH record it is owed
// for.
//
// # The defect, measured on master before the fix
//
// `resolveConfirmRemovalLocked` retains a debt when a resolved window's
// confirm.json cannot be durably deleted, and the singleton persist-retry loop
// re-drives `removeConfirmState()` until it lands. That call is UNCONDITIONAL:
// it deletes whatever confirm.json is on disk. An operator who arms a
// BRAND-NEW `commit confirmed` while the debt is outstanding therefore has the
// NEW window's crash-recovery file deleted by a retry that believes it is
// clearing the old one.
//
// This is deterministic, not a race — the retry fires on its next backoff tick
// and the file is gone. Nothing looks wrong: the in-memory timer stays armed,
// `IsConfirmPending()` is true, and the operator sees a healthy window. The
// damage is only visible after a restart, at which point the record that was
// supposed to survive the crash is absent and the UNCONFIRMED config stands
// permanently with no rollback — the exact #4577 failure the record exists to
// prevent.
//
// # Why #5835 could not see it and #5473 could
//
// #5473 recognised precisely this shape for the OTHER debt it introduced (the
// deferred resolution, `confirmResolvePendingPersist`) and drains it at every
// arm site BEFORE `writeConfirmState` writes the fresh record — see the comment
// at `CommitConfirmed`'s post-rename branch: *"so the stale flag does not
// survive to make the degraded retry's heal delete E's OWN fresh record"*.
// #5835 then added a SECOND debt and did not extend that drain. The fix here
// keys the debt rather than extending the drain, so it holds for an arm path
// that forgets.
//
// # What binds it
//
// `TestConfirmRemovalDebtDoesNotEatFreshWindow_7675` is the defect. Its
// companion `TestConfirmRemovalDebtStillHealsItsOwnRecord_7675` is the control
// that fails on the OVER-BROAD fix: a supersession predicate that returned true
// unconditionally would satisfy the first cell and silently disable #5835's
// self-healing, leaving a genuinely stale record on disk forever.

// armDebtThenNewWindow drives the real store through: baseline commit ->
// window B armed -> B explicitly confirmed while the unlink fails (debt taken)
// -> a fresh window C armed. Returns the store; the caller drives the retry.
func armDebtThenNewWindow(t *testing.T, path string, failUnlink *atomic.Bool) *Store {
	t.Helper()
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(10*time.Millisecond, 10*time.Millisecond)

	stagePendingConfirmed(t, s, "eth1", "untrust") // window B
	failUnlink.Store(true)
	if err := s.ConfirmCommit(); err == nil {
		t.Fatal("PREMISE: ConfirmCommit must surface the injected unlink failure (#5835); " +
			"without a failure no removal debt is taken and this cell is vacuous")
	}
	if !s.ConfirmRemovalDegraded() {
		t.Fatal("PREMISE: the failed removal must retain retry debt (#5835)")
	}
	return s
}

// waitForRetryPass returns once the persist-retry loop has run at least one
// pass after the unlink seam is restored (the debt either clears or the record
// disappears).
func waitForRetryPass(t *testing.T, s *Store) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !s.ConfirmRemovalDegraded() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the persist-retry loop never cleared the removal debt within 3s")
}

func TestConfirmRemovalDebtDoesNotEatFreshWindow_7675(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	var failUnlink atomic.Bool
	installConfirmDeleteSeams(t, &failUnlink, nil)

	s := armDebtThenNewWindow(t, path, &failUnlink)

	// The operator arms a BRAND-NEW window C while the debt is outstanding.
	stagePendingConfirmed(t, s, "eth2", "guest")
	fresh, err := s.db.ReadConfirm()
	if err != nil || fresh == nil {
		t.Fatalf("PREMISE: the fresh window must have written its own record: rec=%v err=%v", fresh, err)
	}
	freshID := confirmRecordIdentity(fresh)

	// Let the retry loop run with the unlink now working.
	failUnlink.Store(false)
	waitForRetryPass(t, s)

	got, err := s.db.ReadConfirm()
	if err != nil {
		t.Fatalf("ReadConfirm after the retry pass: %v", err)
	}
	if got == nil {
		t.Fatal("#7675: the retry loop DELETED the fresh window's crash-recovery file. " +
			"The in-memory timer is still armed so nothing looks wrong, but a restart " +
			"before the deadline now leaves the UNCONFIRMED config standing with no " +
			"rollback (#4577). The removal debt must only delete the record it was " +
			"taken for.")
	}
	if id := confirmRecordIdentity(got); id != freshID {
		t.Fatalf("#7675: the record on disk is not the fresh window's: got %q want %q", id, freshID)
	}

	// WIRING control: the surviving file must actually restore the window on a
	// restart. Asserting only that "a file exists" would pass on a record the
	// recovery path then rejects, which is the same failure wearing a different
	// shape.
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	if !s2.IsConfirmPending() {
		t.Fatal("#7675: the fresh window did not survive a restart — its record was on disk " +
			"but recovery did not re-arm the rollback timer")
	}
}

func TestConfirmRemovalDebtStillHealsItsOwnRecord_7675(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	var failUnlink atomic.Bool
	installConfirmDeleteSeams(t, &failUnlink, nil)

	s := armDebtThenNewWindow(t, path, &failUnlink)

	// NO new window is armed. The lingering record is genuinely stale and #5835's
	// self-healing must still remove it.
	stale, err := s.db.ReadConfirm()
	if err != nil || stale == nil {
		t.Fatalf("PREMISE: the stale record must linger after the failed removal: rec=%v err=%v", stale, err)
	}

	failUnlink.Store(false)
	waitForRetryPass(t, s)

	got, err := s.db.ReadConfirm()
	if err != nil {
		t.Fatalf("ReadConfirm after the retry pass: %v", err)
	}
	if got != nil {
		t.Fatal("#5835 REGRESSION (#7675 control): the retry loop must still delete the " +
			"record its debt was taken for. A supersession predicate that answers " +
			"\"superseded\" for a record nobody replaced disables the self-healing and " +
			"leaves a stale rollback on disk for the next boot to resurrect.")
	}
	if s.ConfirmRemovalDegraded() {
		t.Fatal("#5835: the debt must clear once the removal lands durably")
	}
}
