package userspace

import (
	"errors"
	"testing"
)

// #5487: a standalone HA-state clear that fails must record a retry debt so the
// status poll re-attempts the idempotent empty update_ha_state until it
// succeeds — otherwise a cluster->standalone reconfig with a transient
// control-socket error leaves stale helper HA groups and owner-RG-0 transit
// forwarding stays HAInactive (drop). The clearHelperHAStateHook seam injects
// the clear result so these run unprivileged (no control socket / BPF maps).

// (a) A failed standalone clear sets the debt AND surfaces the error (the apply
// call sites return this error, failing closed).
func TestClearHelperHAStateWithDebtRecordsDebtOnFailure(t *testing.T) {
	m := New()
	clearErr := errors.New("update_ha_state boom")
	m.clearHelperHAStateHook = func() error { return clearErr }

	err := m.clearHelperHAStateWithDebtLocked()
	if err == nil {
		t.Fatal("clearHelperHAStateWithDebtLocked returned nil on clear failure, want error")
	}
	if !errors.Is(err, clearErr) {
		t.Fatalf("returned error = %v, want it to wrap the clear failure", err)
	}
	if !m.pendingHAStateClear {
		t.Fatal("pendingHAStateClear = false after failed standalone clear; the retry debt was not recorded (the clear can never be retried)")
	}
}

// (b) A subsequent poll tick with the debt set retries the clear and clears the
// debt on success.
func TestRetryPendingHAStateClearReconcilesOnPollTick(t *testing.T) {
	m := New()
	m.pendingHAStateClear = true
	m.clusterHA = false

	calls := 0
	m.clearHelperHAStateHook = func() error {
		calls++
		return nil // clear now succeeds
	}

	m.retryPendingHAStateClearLocked()

	if calls != 1 {
		t.Fatalf("clearHelperHAStateLocked called %d times on poll-tick retry, want 1", calls)
	}
	if m.pendingHAStateClear {
		t.Fatal("pendingHAStateClear = true after a successful retry; the debt must clear so the poll stops re-attempting")
	}
}

// (b') A retry that fails again keeps the debt set for the next tick.
func TestRetryPendingHAStateClearKeepsDebtOnRepeatFailure(t *testing.T) {
	m := New()
	m.pendingHAStateClear = true
	m.clusterHA = false

	calls := 0
	m.clearHelperHAStateHook = func() error {
		calls++
		return errors.New("still failing")
	}

	m.retryPendingHAStateClearLocked()

	if calls != 1 {
		t.Fatalf("clearHelperHAStateLocked called %d times, want 1", calls)
	}
	if !m.pendingHAStateClear {
		t.Fatal("pendingHAStateClear = false after a failed retry; the debt must persist so the next tick re-attempts")
	}
}

// (c) The success path records no debt.
func TestClearHelperHAStateWithDebtNoDebtOnSuccess(t *testing.T) {
	m := New()
	m.clearHelperHAStateHook = func() error { return nil }

	if err := m.clearHelperHAStateWithDebtLocked(); err != nil {
		t.Fatalf("clearHelperHAStateWithDebtLocked returned %v on success, want nil", err)
	}
	if m.pendingHAStateClear {
		t.Fatal("pendingHAStateClear = true after a successful clear, want false")
	}
}

// The retry must NOT fire while clustered: retrying an empty update_ha_state on
// a cluster node would wipe the live redundancy-group HA state.
func TestRetryPendingHAStateClearSkippedWhenClustered(t *testing.T) {
	m := New()
	m.pendingHAStateClear = true
	m.clusterHA = true

	calls := 0
	m.clearHelperHAStateHook = func() error {
		calls++
		return nil
	}

	m.retryPendingHAStateClearLocked()

	if calls != 0 {
		t.Fatalf("clearHelperHAStateLocked called %d times while clustered, want 0 (would wipe live HA state)", calls)
	}
	if !m.pendingHAStateClear {
		t.Fatal("pendingHAStateClear cleared while clustered without running the clear; debt state corrupted")
	}
}
