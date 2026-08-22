package ipsec

import (
	"errors"
	"strings"
	"testing"
)

// #6542: a FAILED `swanctl --terminate` for a departed connection must not
// vanish.
//
// promoteConnNames advances prevConnNames to the newly-loaded set the moment
// the reload succeeds, so a departed name is gone from the only record of
// "what was loaded" after exactly one apply. Before this fix,
// terminateRemovedConns was fire-and-forget: a terminate that errored was
// logged at WARN and dropped, Apply still returned nil, and no later
// reconcile ever retried the teardown — the deleted VPN kept forwarding under
// its stale child SA until rekey/lifetime expiry while the commit reported
// success.
//
// These tests drive Manager.Apply against the recording swanctl seam with a
// programmed terminate failure and assert the three properties the fix owes:
// Apply REPORTS the failure, the debt is RETRIED on the next apply, and the
// debt DISCHARGES (rather than latching forever) once the SA is gone or the
// connection comes back into the loaded set.

var errTerminate = errors.New("swanctl: terminate failed")

// applyTwoThenDeleteA loads site-a + site-b, then deletes site-a with both
// SAs live and site-a's terminate programmed to fail. It returns the error
// the delete-Apply reported.
func applyTwoThenDeleteA(t *testing.T, rec *swanctlRecorder) (*Manager, error) {
	t.Helper()
	m := newRecordingManager(t, rec)
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a", "site-b")
	rec.terminateErr = map[string]error{"site-a": errTerminate}
	return m, m.Apply(vpnCfg("site-b"))
}

// TestFailedTerminateIsReported is the first RED-on-revert: restoring the
// pre-fix `m.terminateRemovedConns(removed); return nil` tail makes Apply
// return nil here.
func TestFailedTerminateIsReported(t *testing.T) {
	rec := &swanctlRecorder{}
	_, err := applyTwoThenDeleteA(t, rec)
	if err == nil {
		t.Fatal("Apply returned nil after the terminate of the departed " +
			"connection site-a FAILED — the stale SA is still forwarding " +
			"and the commit reported success")
	}
	if !strings.Contains(err.Error(), "site-a") {
		t.Fatalf("Apply error must name the connection whose teardown "+
			"failed, got %q", err)
	}
	// The surviving connection must not be implicated.
	if strings.Contains(err.Error(), "site-b") {
		t.Fatalf("Apply error names the SURVIVING connection site-b: %q", err)
	}
}

// TestFailedTerminateIsRetriedOnNextApply is the second RED-on-revert: the
// departed name is gone from prevConnNames after the first apply, so without
// the debt set the next apply re-derives an EMPTY removed set and never
// retries — terminateCalls stays at 1.
func TestFailedTerminateIsRetriedOnNextApply(t *testing.T) {
	rec := &swanctlRecorder{}
	m, err := applyTwoThenDeleteA(t, rec)
	if err == nil {
		t.Fatal("delete Apply must report the failed terminate")
	}
	if got := rec.terminateCalls(); len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("delete Apply: want one terminate for site-a, got %v", got)
	}

	// Same config re-applied (a later, unrelated commit). site-a's SA is
	// still live, so the teardown debt must be retried.
	if err := m.Apply(vpnCfg("site-b")); err == nil {
		t.Fatal("second Apply returned nil while site-a's stale SA is " +
			"still live and its terminate still fails")
	}
	got := rec.terminateCalls()
	if len(got) != 2 || got[1] != "site-a" {
		t.Fatalf("teardown debt was not retried on the next Apply: "+
			"terminate calls %v", got)
	}

	// Third apply, terminate now succeeds: the debt discharges and Apply
	// reports success.
	rec.terminateErr = nil
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("third Apply after a SUCCESSFUL retry must succeed: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 3 || got[2] != "site-a" {
		t.Fatalf("third Apply must have retried site-a once more, got %v", got)
	}

	// Fourth apply: the debt is discharged, so no further terminate.
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("fourth Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 3 {
		t.Fatalf("discharged debt must not be retried again, got %v", got)
	}
}

// TestTerminateDebtDischargesWhenSAIsGone: the debt must not latch. Once the
// departed connection no longer appears in --list-sas the fail-open is closed
// (by expiry, by charon restart, by anything) and further commits must report
// success rather than failing forever on a dead name.
func TestTerminateDebtDischargesWhenSAIsGone(t *testing.T) {
	rec := &swanctlRecorder{}
	m, err := applyTwoThenDeleteA(t, rec)
	if err == nil {
		t.Fatal("delete Apply must report the failed terminate")
	}

	// site-a's SA is gone; site-b's remains.
	rec.listSAs = liveSA("site-b")
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("Apply must succeed once the stale SA is gone: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 1 {
		t.Fatalf("a departed connection with no live SA owes no terminate, "+
			"got %v", got)
	}
}

// TestTerminateDebtDischargesWhenConnReloaded: a debt entry is never a licence
// to tear down a LOADED connection. Re-adding the VPN puts site-a back in the
// rendered+loaded set, so strongSwan is enforcing it again and the teardown
// debt must be dropped rather than killing the restored tunnel.
func TestTerminateDebtDischargesWhenConnReloaded(t *testing.T) {
	rec := &swanctlRecorder{}
	m, err := applyTwoThenDeleteA(t, rec)
	if err == nil {
		t.Fatal("delete Apply must report the failed terminate")
	}
	before := len(rec.terminateCalls())

	// Operator re-adds site-a. Its terminate would still fail if issued.
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("re-adding the VPN must succeed: %v", err)
	}
	got := rec.terminateCalls()
	if len(got) != before {
		t.Fatalf("re-added (loaded) connection must not be torn down by a "+
			"stale teardown debt, terminate calls %v", got)
	}
}

// TestClearReportsFailedTerminate covers the Clear()/empty-config path, which
// has its own promote+terminate tail.
func TestClearReportsFailedTerminate(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a")
	rec.terminateErr = map[string]error{"site-a": errTerminate}

	if err := m.Apply(nil); err == nil {
		t.Fatal("clear Apply returned nil after site-a's terminate FAILED")
	}
	// The debt survives into the next reconcile on the clear path too.
	if err := m.Clear(); err == nil {
		t.Fatal("Clear returned nil while site-a's stale SA is still live")
	}
	if got := rec.terminateCalls(); len(got) != 2 {
		t.Fatalf("clear-path teardown debt was not retried, got %v", got)
	}
}
