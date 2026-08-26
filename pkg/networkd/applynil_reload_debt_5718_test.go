package networkd

import (
	"errors"
	"testing"
)

// TestApplyNil_ReloadDebtRetriedAfterFailure is the #5718 A7-b01-C001
// fail-on-revert, MOVED from Clear onto Apply(nil) by #6852.
//
// The teardown path owns the same #4954 activation-debt obligation any Apply
// does: deleting the
// generated files does not deactivate anything until `networkctl reload`
// succeeds. Until then the kernel still runs the config those files installed
// (addresses, VRF membership, bond/bridge enslavement, interface renames).
//
// Pre-#5718 the teardown recorded no debt on reload failure and returned early
// on an empty glob, so the retry path was structurally unable to report the
// truth: the second call found the files already deleted, returned nil, and told
// the operator the teardown had succeeded while the removed config stayed live.
//
// #6852 retired Clear, whose only caller was this suite. This cell is the
// evidence that retiring lost nothing: it is the SAME four-step sequence, driven
// through Apply(nil), and it still holds. A retirement whose tests were deleted
// rather than moved would have proved only that nobody was looking.
func TestApplyNil_ReloadDebtRetriedAfterFailure_5718(t *testing.T) {
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

	// 0) Land the managed files with a SUCCEEDING reload so the Manager starts
	//    this test with no debt and Clear has real files to remove.
	reloadFails = false
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("setup Apply should succeed: %v", err)
	}
	reloadCalls = 0

	// 1) First Clear removes the files, reload FAILS → Clear must error.
	reloadFails = true
	if err := m.Apply(nil); err == nil {
		t.Fatal("the first teardown must fail when networkctl reload fails")
	}
	if reloadCalls != 1 {
		t.Fatalf("the first teardown should have attempted reload once, got %d", reloadCalls)
	}

	// 2) Second Clear: the glob is now EMPTY (the files were removed in step 1)
	//    but the activation never landed. The debt must force a real reload
	//    retry instead of an early `return nil`. Reload still fails → Clear
	//    must still surface an error.
	if err := m.Apply(nil); err == nil {
		t.Fatal("a second teardown after a failed reload must NOT report success: the " +
			"managed files are gone from disk but the kernel never re-read " +
			"them, so the removed addresses/VRFs/renames are still live")
	}
	if reloadCalls != 2 {
		t.Fatalf("the second teardown must RE-RUN reload from the recorded debt, got total reloadCalls=%d (want 2)", reloadCalls)
	}

	// 3) Reload recovers: Clear re-runs it, succeeds, and discharges the debt.
	reloadFails = false
	if err := m.Apply(nil); err != nil {
		t.Fatalf("the teardown after the reload recovers should succeed: %v", err)
	}
	if reloadCalls != 3 {
		t.Fatalf("the recovering teardown must run reload, got total reloadCalls=%d (want 3)", reloadCalls)
	}

	// 4) Debt discharged: a further Clear with no files and no debt is a
	//    genuine no-op and must not shell out again.
	if err := m.Apply(nil); err != nil {
		t.Fatalf("a teardown with no files and no debt should succeed: %v", err)
	}
	if reloadCalls != 3 {
		t.Fatalf("a teardown with no files and no outstanding debt must not reload, got total reloadCalls=%d (want 3)", reloadCalls)
	}
}
