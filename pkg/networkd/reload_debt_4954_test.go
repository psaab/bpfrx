package networkd

import (
	"errors"
	"testing"
)

// TestApply_ReloadDebtRetriedAfterFailure is the #4954 fail-on-revert. A
// `networkctl reload` that fails must leave the Manager owing activation debt
// so an IDENTICAL retry (byte-identical generated files → writeIfChanged sees
// no change) actually RE-ATTEMPTS the reload rather than short-circuiting to a
// false success while the kernel still runs the pre-failure config.
//
// Pre-fix: the second Apply sees changed==false, skips the reload, returns nil
// — masking the un-activated config. With the reload-debt fix the second Apply
// re-runs reload and surfaces the still-failing state; the third (now
// succeeding) Apply activates and clears the debt.
func TestApply_ReloadDebtRetriedAfterFailure(t *testing.T) {
	resetReloadDebtForTest(t)
	dir := t.TempDir()
	m := NewInDir(dir)

	var reloadCalls int
	reloadFails := true
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reload" {
			reloadCalls++
			if reloadFails {
				return errors.New("simulated networkctl reload failure")
			}
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := []InterfaceConfig{
		{Name: "trust0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
	}

	// 1) First Apply writes files, reload FAILS → Apply must return an error.
	if err := m.Apply(ifaces); err == nil {
		t.Fatal("first Apply must fail when networkctl reload fails")
	}
	if reloadCalls != 1 {
		t.Fatalf("first Apply should have attempted reload once, got %d", reloadCalls)
	}

	// 2) Identical retry: files are byte-identical (no change), but the reload
	//    debt must force a re-attempt. Reload still fails → Apply still errors.
	if err := m.Apply(ifaces); err == nil {
		t.Fatal("identical retry after a failed reload must re-attempt and surface the still-failing reload, not return a false success")
	}
	if reloadCalls != 2 {
		t.Fatalf("identical retry must RE-RUN reload (debt), got total reloadCalls=%d (want 2)", reloadCalls)
	}

	// 3) Reload now succeeds: the retry activates and clears the debt.
	reloadFails = false
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("retry after reload recovers should succeed: %v", err)
	}
	if reloadCalls != 3 {
		t.Fatalf("recovering retry must run reload, got total reloadCalls=%d (want 3)", reloadCalls)
	}

	// 4) Debt is now clear: a further identical Apply with unchanged files and
	//    no debt must NOT reload again (no spurious activation).
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("steady-state Apply should succeed: %v", err)
	}
	if reloadCalls != 3 {
		t.Fatalf("steady-state identical Apply must not reload once debt is cleared, got reloadCalls=%d (want 3)", reloadCalls)
	}
}

// TestApply_ReconfigureDebtRetriedAfterFailure covers the mirrored
// `networkctl reconfigure` debt: a reconfigure failure is warn-only (Apply
// still returns nil) but must be retried on the next Apply even with unchanged
// files, then cleared on success.
func TestApply_ReconfigureDebtRetriedAfterFailure(t *testing.T) {
	resetReloadDebtForTest(t)
	dir := t.TempDir()
	m := NewInDir(dir)

	var reconfigureCalls int
	reconfigureFails := true
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			reconfigureCalls++
			if reconfigureFails {
				return errors.New("simulated networkctl reconfigure failure")
			}
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := []InterfaceConfig{
		{Name: "trust0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
	}

	// 1) First Apply: reload OK, reconfigure FAILS → warn-only, Apply returns nil.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("first Apply should succeed (reconfigure is best-effort): %v", err)
	}
	if reconfigureCalls != 1 {
		t.Fatalf("first Apply should attempt reconfigure once, got %d", reconfigureCalls)
	}

	// 2) Identical retry (unchanged files): reconfigure debt must force a
	//    re-attempt even though nothing changed.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("retry Apply should succeed (best-effort reconfigure): %v", err)
	}
	if reconfigureCalls != 2 {
		t.Fatalf("identical retry must RE-RUN reconfigure (debt), got %d (want 2)", reconfigureCalls)
	}

	// 3) Reconfigure now succeeds → debt cleared.
	reconfigureFails = false
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("recovering Apply should succeed: %v", err)
	}
	if reconfigureCalls != 3 {
		t.Fatalf("recovering retry must run reconfigure, got %d (want 3)", reconfigureCalls)
	}

	// 4) Debt cleared: an identical Apply must not reconfigure again.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("steady-state Apply should succeed: %v", err)
	}
	if reconfigureCalls != 3 {
		t.Fatalf("steady-state Apply must not reconfigure once debt is cleared, got %d (want 3)", reconfigureCalls)
	}
}
