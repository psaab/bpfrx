package daemon

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sync/semaphore"
)

// #9073: the `sshd -t` validation-failure arm logged and fell through without
// noteSSHDReloadResult, so `sshdFailures` never incremented. Under a persistent
// validation failure the count stayed FLAT while the retry owner was running
// and failing every pass — which is precisely the distinction the counters were
// built to make. Their own contract, where they are declared:
//
//	whether the retry owner is RUNNING and failing (count climbing) or wedged
//	(count flat)
func TestSSHDValidationFailureIncrementsTheCounter9073(t *testing.T) {
	origValidate, origReload := sshdValidateCmd, sshdReloadCmd
	t.Cleanup(func() { sshdValidateCmd, sshdReloadCmd = origValidate, origReload })

	var reloadCalls int
	sshdValidateCmd = func() ([]byte, error) {
		return []byte("bad config line 7"), errors.New("sshd: bad configuration")
	}
	sshdReloadCmd = func() ([]byte, error) {
		reloadCalls++
		return nil, nil
	}

	// applySem is required: reassertServiceReloadDebtOnce returns early without
	// it, and every arm below would then pass or fail for that reason instead
	// of the one under test. The existing-behaviour rows caught this.
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.noteSSHDReloadResult(errors.New("initial apply failed"))
	if !d.sshdReloadOwed() {
		t.Fatal("fixture: the debt must be outstanding, or the retry arm never runs")
	}
	before := d.ManagedServiceReloadFailures()["sshd-validate"]
	reloadBefore := d.ManagedServiceReloadFailures()["sshd"]

	// Three retry passes with a persistent validation failure. The counter must
	// CLIMB — a flat count is what an operator reads as "the owner is wedged".
	for i := 0; i < 3; i++ {
		d.reassertServiceReloadDebtOnce(context.Background())
	}

	after := d.ManagedServiceReloadFailures()["sshd-validate"]
	if after != before+3 {
		t.Errorf("sshd VALIDATION failure count %d -> %d over three failing passes, "+
			"want +3. A flat count is exactly what an operator reads as 'the retry "+
			"owner is wedged', which is the opposite of what is happening",
			before, after)
	}
	// And it must NOT inflate the RELOAD count. #6800 pinned that to reload
	// ATTEMPTS -- "a validation failure is not a reload ATTEMPT" -- and a
	// validation failure means no reload was attempted at all. Overloading one
	// counter would buy this issue's distinction by deleting that one.
	if got := d.ManagedServiceReloadFailures()["sshd"]; got != reloadBefore {
		t.Errorf("the reload failure count moved %d -> %d on a VALIDATION failure; "+
			"nothing was reloaded, so no reload attempt failed", reloadBefore, got)
	}
	// The debt must still be outstanding: nothing was reloaded, so nothing is
	// paid. This is the deliberate posture the arm already had and the fix must
	// not disturb it.
	if !d.sshdReloadOwed() {
		t.Error("a validation failure discharged the debt; nothing was reloaded, so " +
			"nothing is paid — and sshd would never be re-asserted")
	}
	// And the reload must NOT have been attempted: `sshd -t` failing is what
	// stops it, because a bad config reloaded can drop the listener and lock an
	// appliance out.
	if reloadCalls != 0 {
		t.Errorf("sshd was reloaded %d times despite failing validation; that is the "+
			"SSH-lockout the validation gate exists to prevent", reloadCalls)
	}
}

// NARROWNESS: a SUCCESSFUL reload must still discharge the debt and must NOT
// move the failure counter. Without this row, "increment on failure" is
// satisfied by incrementing always, which makes the climbing/flat distinction
// meaningless in the other direction.
func TestSSHDSuccessfulReloadDischargesAndDoesNotCount9073(t *testing.T) {
	origValidate, origReload := sshdValidateCmd, sshdReloadCmd
	t.Cleanup(func() { sshdValidateCmd, sshdReloadCmd = origValidate, origReload })

	sshdValidateCmd = func() ([]byte, error) { return nil, nil }
	sshdReloadCmd = func() ([]byte, error) { return nil, nil }

	// applySem is required: reassertServiceReloadDebtOnce returns early without
	// it, and every arm below would then pass or fail for that reason instead
	// of the one under test. The existing-behaviour rows caught this.
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.noteSSHDReloadResult(errors.New("initial apply failed"))
	before := d.ManagedServiceReloadFailures()["sshd"]
	validBefore := d.ManagedServiceReloadFailures()["sshd-validate"]

	d.reassertServiceReloadDebtOnce(context.Background())

	if got := d.ManagedServiceReloadFailures()["sshd-validate"]; got != validBefore {
		t.Errorf("a SUCCESSFUL validation moved the validation count %d -> %d",
			validBefore, got)
	}
	if d.sshdReloadOwed() {
		t.Error("a successful reload did not discharge the debt")
	}
	if after := d.ManagedServiceReloadFailures()["sshd"]; after != before {
		t.Errorf("a SUCCESSFUL reload moved the failure count %d -> %d", before, after)
	}
}

// And a reload that fails AFTER validation passes must count too — the arm that
// already did. Asserted so a refactor cannot swap which arm counts.
func TestSSHDReloadFailureStillCounts9073(t *testing.T) {
	origValidate, origReload := sshdValidateCmd, sshdReloadCmd
	t.Cleanup(func() { sshdValidateCmd, sshdReloadCmd = origValidate, origReload })

	sshdValidateCmd = func() ([]byte, error) { return nil, nil }
	sshdReloadCmd = func() ([]byte, error) { return nil, errors.New("reload failed") }

	// applySem is required: reassertServiceReloadDebtOnce returns early without
	// it, and every arm below would then pass or fail for that reason instead
	// of the one under test. The existing-behaviour rows caught this.
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.noteSSHDReloadResult(errors.New("initial apply failed"))
	before := d.ManagedServiceReloadFailures()["sshd"]

	d.reassertServiceReloadDebtOnce(context.Background())

	if after := d.ManagedServiceReloadFailures()["sshd"]; after != before+1 {
		t.Errorf("a failing reload moved the count %d -> %d, want +1", before, after)
	}
	if !d.sshdReloadOwed() {
		t.Error("a failing reload discharged the debt")
	}
}
