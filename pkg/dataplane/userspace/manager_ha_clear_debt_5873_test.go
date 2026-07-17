package userspace

import (
	"errors"
	"testing"
)

// #5873: a standalone HA-state clear that FAILS records a pendingHAStateClear
// retry debt (#5487), but that debt has exactly ONE retry consumer — the
// periodic status-loop tick (retryPendingHAStateClearLocked). Both apply-path
// clear sites (manager_compile.go) can return the failure BEFORE reaching the
// normal ensureStatusLoopLocked() call:
//
//   - first-startup full publish: the failed-clear branch returns just ABOVE
//     the ensureStatusLoopLocked() call, so on the very first apply (no loop
//     yet) a failed clear leaves the debt with no worker to retry it;
//   - deferred-XSK resume: that path returns without ever calling
//     ensureStatusLoopLocked().
//
// Either way the debt is orphaned and the stale helper HA groups (owner-RG-0
// transit-drop gate) persist indefinitely, contradicting the eventual-cleanup
// contract. clearHelperHAStateWithDebtEnsureRetryLocked is the shared wrapper
// both sites now use: on a failed clear it records the debt AND ensures the
// status loop is running before the error propagates.
//
// FAIL-ON-REVERT: remove the m.ensureStatusLoopLocked() call from
// clearHelperHAStateWithDebtEnsureRetryLocked (or revert the call sites to the
// bare clearHelperHAStateWithDebtLocked, i.e. move the loop-ensure back after
// the return) and (b) below fails — the loop is not started, so the recorded
// debt can never be retried.

// (a)+(b) A first-startup-style failed standalone clear with NO pre-existing
// status loop must both record the debt AND start the loop that will retry it,
// while still surfacing the error (fail closed).
func TestClearHelperHAStateEnsureRetryStartsLoopOnFailedClear(t *testing.T) {
	m := New()
	// No status loop yet — models first startup / any apply with no loop.
	if m.syncCancel != nil {
		t.Fatal("test precondition: syncCancel should be nil before any apply")
	}
	m.clusterHA = false // standalone

	clearErr := errors.New("update_ha_state boom")
	m.clearHelperHAStateHook = func() error { return clearErr }

	err := m.clearHelperHAStateWithDebtEnsureRetryLocked()

	// The clear still fails closed: the raw error propagates so the apply
	// call sites surface the failure.
	if err == nil {
		t.Fatal("clearHelperHAStateWithDebtEnsureRetryLocked returned nil on clear failure, want error")
	}
	if !errors.Is(err, clearErr) {
		t.Fatalf("returned error = %v, want it to wrap the clear failure", err)
	}
	// (a) The retry debt is recorded.
	if !m.pendingHAStateClear {
		t.Fatal("pendingHAStateClear = false after failed standalone clear; the retry debt was not recorded")
	}
	// (b) The periodic status loop — the debt's ONLY retry consumer — is now
	// running (syncCancel set by ensureStatusLoopLocked). Without this the debt
	// is orphaned: nothing ever retries the idempotent clear and the stale
	// helper HA groups persist. This is the assertion the revert breaks.
	if m.syncCancel == nil {
		t.Fatal("status loop not started after a failed standalone clear (syncCancel == nil); the recorded HA-clear debt is orphaned with no worker to retry it (#5873)")
	}
	// Stop the loop goroutine we started.
	m.syncCancel()
}

// A failed clear must ensure the loop even when a status loop ALREADY exists —
// ensureStatusLoopLocked must be idempotent (safe to call with a running loop)
// so the wrapper can call it unconditionally on the failure path.
func TestClearHelperHAStateEnsureRetryIdempotentWithExistingLoop(t *testing.T) {
	m := New()
	m.clusterHA = false

	// Simulate a pre-existing loop.
	m.ensureStatusLoopLocked()
	firstCancel := m.syncCancel
	if firstCancel == nil {
		t.Fatal("ensureStatusLoopLocked did not set syncCancel")
	}

	m.clearHelperHAStateHook = func() error { return errors.New("still failing") }
	if err := m.clearHelperHAStateWithDebtEnsureRetryLocked(); err == nil {
		t.Fatal("want error on failed clear")
	}
	// The existing loop must NOT be replaced (same cancel func) — idempotent.
	if m.syncCancel == nil {
		t.Fatal("syncCancel cleared by a redundant ensure; ensureStatusLoopLocked is not idempotent")
	}
	m.syncCancel()
}

// The success path records no debt and does NOT start a loop from the wrapper:
// the normal apply path starts the loop itself (ensureStatusLoopLocked at the
// end of Compile). The wrapper only owns the failed-clear ordering.
func TestClearHelperHAStateEnsureRetryNoLoopOnSuccess(t *testing.T) {
	m := New()
	m.clusterHA = false
	m.clearHelperHAStateHook = func() error { return nil }

	if err := m.clearHelperHAStateWithDebtEnsureRetryLocked(); err != nil {
		t.Fatalf("clearHelperHAStateWithDebtEnsureRetryLocked returned %v on success, want nil", err)
	}
	if m.pendingHAStateClear {
		t.Fatal("pendingHAStateClear = true after a successful clear, want false")
	}
	if m.syncCancel != nil {
		m.syncCancel()
		t.Fatal("status loop started on the success path; the wrapper must only ensure the loop on a failed clear")
	}
}
