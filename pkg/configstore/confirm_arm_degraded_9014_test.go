package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #9014: the ARM write that establishes a commit-confirmed window was the ONE
// confirm-durability leg that raised nothing. It logged a single slog.Warn and
// returned; CommitConfirmed still reported success and /health stayed 200. A
// crash or reboot inside the window then found no record, the unconfirmed
// configuration stood permanently, and nothing had alerted.
//
//	confirm READ at boot   confirmRecoveryReadFailed  journal  —      degraded
//	confirm REMOVAL        confirmRemoveDegraded      journal  retry  degraded
//	confirm ARM (this)     none                       none     none   200 OK

var errInjectedConfirmArm = errors.New("injected confirm.json arm-write failure")

// failConfirmArm fails ONLY the confirm.json durable write, leaving every other
// durability op (active marker, rollback slots, archives) intact — otherwise a
// green result could come from the commit failing for an unrelated reason.
func failConfirmArm(t *testing.T, fail *atomic.Bool) {
	t.Helper()
	restoreRollbackSeams(t)
	prev := rbWriteFileDurable
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if fail.Load() && filepath.Base(path) == "confirm.json" {
			return errInjectedConfirmArm
		}
		return prev(path, data, perm, opts...)
	}
}

func journalHas9014(t *testing.T, s *Store, action string) bool {
	t.Helper()
	entries, err := s.journal.Tail(0)
	if err != nil {
		t.Fatalf("journal.Tail: %v", err)
	}
	for _, e := range entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

// TestArmWriteFailureRaisesDegradedHealth9014 is the defect itself.
func TestArmWriteFailureRaisesDegradedHealth9014(t *testing.T) {
	s := newTestStore(t)
	var fail atomic.Bool
	failConfirmArm(t, &fail)
	commitBaseline(t, s)
	// A very long backoff: this cell is about the FAILURE state, and a retry
	// firing mid-assertion would make it flaky in the healthy direction.
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

	// CONTROL FIRST. Without it, a `true` below could come from the store being
	// degraded for some unrelated reason before the injection.
	if s.ConfigPersistDegraded() {
		t.Fatal("control failed: a fresh store already reports degraded persistence")
	}

	fail.Store(true)
	if err := s.SetFromInput("system host-name armfail"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		// The commit is deliberately NOT failed — see noteConfirmArmFailureLocked.
		t.Fatalf("CommitConfirmed must still succeed on an arm-write failure "+
			"(#1960: the config is applied and correct, only its crash-recovery "+
			"record is missing): %v", err)
	}

	if !s.ConfigPersistDegraded() {
		t.Error("an arm-write failure left /health at 200. A crash inside the confirm " +
			"window would find no record, so the UNCONFIRMED configuration would stand " +
			"permanently with nothing having alerted (#9014)")
	}
	if !journalHas9014(t, s, "confirm_arm_error") {
		t.Error("no `confirm_arm_error` journal entry — the two neighbouring legs both " +
			"journal, and a number in a log line cannot be read as a defect (#9014)")
	}
	// The record really is absent: the assertions above must not pass while the
	// write actually landed.
	if rec, err := s.db.ReadConfirm(); err == nil && rec != nil {
		t.Fatal("fixture did not construct the state it names: confirm.json exists, so " +
			"the arm write did not actually fail")
	}
}

// TestArmWriteDebtSelfHeals9014 pins the retry, which is what makes the
// degraded state converge rather than latch.
func TestArmWriteDebtSelfHeals9014(t *testing.T) {
	s := newTestStore(t)
	var fail atomic.Bool
	failConfirmArm(t, &fail)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)

	fail.Store(true)
	if err := s.SetFromInput("system host-name armheal"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("control failed: the arm-write failure did not raise degraded health, so " +
			"the heal below would prove nothing")
	}

	fail.Store(false) // the underlying fault clears
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !s.ConfigPersistDegraded() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("the arm-write debt did not converge: health is still degraded after the " +
			"underlying fault cleared (#9014)")
	}
	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("the retry cleared the flag WITHOUT writing the record: rec=%v err=%v — "+
			"that is worse than the defect, because health now says the window is durable "+
			"when it is not", rec, err)
	}
	if !journalHas9014(t, s, "confirm_arm_recovered") {
		t.Error("no `confirm_arm_recovered` journal entry for a heal")
	}
}

// TestArmWriteDebtIsNotResurrectedAfterResolution9014 is the cell that matters
// most, and the one this fix could most easily have got wrong.
//
// If the window is CONFIRMED while the arm write is still owed, re-driving that
// write would create a crash-recovery record for a window that no longer
// exists — a restart would then resurrect a rollback the operator had already
// resolved. It is the mirror of #7675 on the removal side, where re-driving a
// delete would have removed a LIVE window's record.
func TestArmWriteDebtIsNotResurrectedAfterResolution9014(t *testing.T) {
	s := newTestStore(t)
	var fail atomic.Bool
	failConfirmArm(t, &fail)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)

	fail.Store(true)
	if err := s.SetFromInput("system host-name armresurrect"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("control failed: no arm-write debt was taken, so nothing could be resurrected")
	}

	// Resolve the window with a plain commit (Junos semantics: a subsequent
	// commit confirms a pending commit confirmed), while the debt is still owed.
	fail.Store(false)
	if err := s.SetFromInput("system host-name armresolved"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if s.IsConfirmPending() {
		t.Fatal("fixture did not construct the state it names: a plain commit must have " +
			"resolved the pending window")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !s.ConfigPersistDegraded() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("the arm-write debt never cleared after its window was resolved")
	}

	// THE ASSERTION. No confirm.json may exist: the window it would describe is
	// gone, and a restart reading it would revert an already-confirmed config.
	rec, err := s.db.ReadConfirm()
	if err == nil && rec != nil {
		t.Errorf("the retry RESURRECTED a crash-recovery record for a window that was "+
			"already confirmed — a restart would now revert the operator's confirmed "+
			"configuration (#9014, mirroring #7675): deadline=%v", rec.Deadline)
	}
	if !journalHas9014(t, s, "confirm_arm_superseded") {
		t.Error("no `confirm_arm_superseded` journal entry — the debt was dropped without " +
			"recording why")
	}
}

// TestSuccessfulReArmDischargesArmDebt9014 pins that a LATER `commit confirmed`
// discharges the debt, because the record it writes is current. Without this,
// health would stay degraded behind a debt that is already satisfied.
func TestSuccessfulReArmDischargesArmDebt9014(t *testing.T) {
	s := newTestStore(t)
	var fail atomic.Bool
	failConfirmArm(t, &fail)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour) // the retry must not do this work

	fail.Store(true)
	if err := s.SetFromInput("system host-name armfirst"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("control failed: no debt was taken")
	}

	fail.Store(false)
	if err := s.SetFromInput("system host-name armsecond"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("re-arm CommitConfirmed: %v", err)
	}
	if s.ConfigPersistDegraded() {
		t.Error("a SUCCESSFUL re-arm left health degraded. The record on disk is current, " +
			"so the debt is satisfied and holding health down misreports a durable " +
			"window as unsafe (#9014)")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("fixture: the re-arm should have written a record: rec=%v err=%v", rec, err)
	}
}

// TestHealthyArmLeavesNoDebt9014 is the negative control for the whole file. A
// guard that fires when nothing is wrong is not measuring the fault.
func TestHealthyArmLeavesNoDebt9014(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	if err := s.SetFromInput("system host-name armclean"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if s.ConfigPersistDegraded() {
		t.Error("an ordinary commit-confirmed reported degraded persistence")
	}
	for _, a := range []string{"confirm_arm_error", "confirm_arm_recovered", "confirm_arm_superseded"} {
		if journalHas9014(t, s, a) {
			t.Errorf("a healthy arm journalled %q", a)
		}
	}
}
