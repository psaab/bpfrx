package networkd

import (
	"errors"
	"testing"
)

// resetReloadDebtForTest clears the process-scoped #4954 activation debt
// before and after a test. The debt is process-scoped by design (see the
// reloadDebt holder), so a test that deliberately fails a reload must not leak
// the debt into a later test in this package — a leaked debt makes an
// otherwise-unchanged Apply shell out an extra time and breaks call-count
// assertions elsewhere.
func resetReloadDebtForTest(t *testing.T) {
	t.Helper()
	clear := func() {
		reloadDebt.mu.Lock()
		defer reloadDebt.mu.Unlock()
		reloadDebt.pending = false
		reloadDebt.epoch = 0
		reloadDebt.tailPending = false
	}
	clear()
	t.Cleanup(clear)
}

// debtTestIfaces is the fixture for the debt tests below. It is deliberately
// ONE plain interface, and that narrowness is the limit of what those tests
// prove about the activation tail.
//
// READ THIS BEFORE TREATING A GREEN RUN AS COVERAGE. The tests using this
// fixture bind the DEBT mechanism — armed on a failed reload, discharged only
// by a matching-epoch success, never silently dropped. They do NOT bind how the
// activation tail selects or filters interfaces. Three wrong-interface
// regressions were each injected and measured to leave this package GREEN:
//
//   - hardcoding "trust0" in the tail instead of reading the caller's set —
//     invisible, because the fixture only ever contains "trust0";
//   - deleting the unmanaged/disabled filtering — invisible, because nothing
//     here is unmanaged or disabled;
//   - reversing multi-interface accumulation and order — invisible, because
//     one element has no order.
//
// The only activation-tail arm this fixture closes is the bond-member one
// (`&& ifc.BondMaster == ""`), whose deletion reds the activation-tail tests
// with [reconfigure trust0 lag0m]. That arm is closed because a SEPARATE
// fixture supplies a bond member; this one does not.
//
// Widening this fixture to catch the three above is a real improvement, not a
// no-op — but it changes the call-count assertions in every test that uses it,
// so it is its own change. Until then, do not read a pass here as "the tail
// picks the right interfaces".
func debtTestIfaces() []InterfaceConfig {
	return []InterfaceConfig{
		{Name: "trust0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
	}
}

// TestReloadDebt_ExternalOwnerFailureForcesApplyReload_5718 is the #5718 fold
// F2 fail-on-revert: the activation debt has ONE holder that EVERY reload
// owner in the process records into.
//
// This package is not the only owner of `networkctl reload`. pkg/daemon shells
// out to it directly from FIVE production sites — linksetup's post-rename
// reload (warn-only), device-map's rename and teardown reloads, and bootstrap's
// teardown and lifeline reloads — all of them writing or removing the same
// 10-xpf-* files this package generates. With a Manager-scoped debt those
// owners could not record anything, and the disagreement resolved in the
// dangerous direction: their failed reload left the generated files on disk
// unactivated while the Manager's flag stayed false, so the next Apply with
// byte-identical content took the `changed==false && !debt` branch, skipped
// the reload, and reported the #4954 false success the debt exists to prevent.
func TestReloadDebt_ExternalOwnerFailureForcesApplyReload_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	m := NewInDir(t.TempDir())

	var reloadCalls int
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reload" {
			reloadCalls++
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := debtTestIfaces()

	// 1) Land the generated files with a succeeding reload. No debt owed.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("setup Apply should succeed: %v", err)
	}
	if reloadCalls != 1 {
		t.Fatalf("setup Apply should have reloaded once, got %d", reloadCalls)
	}

	// 2) Steady state: an identical Apply sees unchanged files and no debt, so
	//    it must NOT shell out. This is the branch the lost debt hides in.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("steady-state Apply should succeed: %v", err)
	}
	if reloadCalls != 1 {
		t.Fatalf("steady-state Apply must not reload, got %d", reloadCalls)
	}

	// 3) A reload owner OUTSIDE this package runs `networkctl reload` and it
	//    FAILS. This is exactly what pkg/daemon's networkctlReload reports.
	epoch := BeginReload()
	NoteReloadResult(epoch, errors.New("simulated daemon-side networkctl reload failure"))

	// 4) The kernel never re-read the directory, so the config on disk is not
	//    active. The next identical Apply MUST re-run the reload even though
	//    nothing changed.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("Apply after an external reload failure should succeed once the reload works: %v", err)
	}
	if reloadCalls != 2 {
		t.Fatalf("an Apply following an EXTERNAL reload owner's FAILURE must re-run the "+
			"reload from the shared activation debt, got reloadCalls=%d (want 2). A "+
			"Manager-scoped debt cannot see that failure, so the generated files stay "+
			"on disk unactivated while Apply reports success", reloadCalls)
	}

	// 5) That reload succeeded, so the shared debt is discharged and steady
	//    state resumes — the debt is not a permanent latch.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("post-recovery Apply should succeed: %v", err)
	}
	if reloadCalls != 2 {
		t.Fatalf("a successful reload must discharge the external owner's debt, got reloadCalls=%d (want 2)", reloadCalls)
	}
}

// TestReloadDebt_ExternalOwnerSuccessDischargesDebt_5718 is the direction
// control for the test above: NoteReloadResult must record a failure AND
// discharge on success, so an external owner that fixes the activation is not
// forced to leave a permanent debt behind.
func TestReloadDebt_ExternalOwnerSuccessDischargesDebt_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	m := NewInDir(t.TempDir())

	var reloadCalls int
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reload" {
			reloadCalls++
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := debtTestIfaces()
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("setup Apply should succeed: %v", err)
	}

	// An external owner fails, then retries and succeeds.
	NoteReloadResult(BeginReload(), errors.New("simulated failure"))
	NoteReloadResult(BeginReload(), nil)

	reloadCalls = 0
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("Apply should succeed: %v", err)
	}
	if reloadCalls != 0 {
		t.Fatalf("an external owner's SUCCESSFUL reload must discharge the debt it "+
			"recorded, so an unchanged Apply stays a no-op; got reloadCalls=%d (want 0)", reloadCalls)
	}
}

// TestReloadDebt_ConcurrentSuccessCannotClearALaterFailure_5718 is the #5718
// fold F4 fail-on-revert: a blind `pending = false` on a successful reload
// LOSES a debt another owner recorded while that reload was in flight.
//
// The worked interleaving this test reproduces deterministically, driven from
// inside owner B's reload stub:
//
//	T1  owner B (Clear) removes its files and calls `networkctl reload`
//	T2  B's reload re-reads the directory and SUCCEEDS at the syscall level,
//	    but B has not yet recorded its result
//	T3  owner A (Apply) writes NEW generated files to disk
//	T4  A calls `networkctl reload`; it FAILS; A records the activation debt
//	T5  B resumes and blind-stores pending=false            <-- A's debt is lost
//	T6  A retries with byte-identical files: changed==false, debt==false, so
//	    the reload is SKIPPED and Apply returns nil
//
// B's reload provably cannot have activated A's files — it read the directory
// before they existed — so at T6 the kernel is still running the pre-A config
// while the operator is told the commit succeeded. A debt cleared whose work
// never ran is a silent skip of a reload the system believes it performed.
//
// The epoch guard makes T5 a no-op: A's record at T4 advanced the epoch past
// the snapshot B took before its reload, so B's clear is refused.
func TestReloadDebt_ConcurrentSuccessCannotClearALaterFailure_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	mA := NewInDir(t.TempDir()) // the owner whose reload FAILS
	mB := NewInDir(t.TempDir()) // the owner whose reload SUCCEEDS concurrently

	ifaces := debtTestIfaces()

	// phase drives the stub: "ok" succeeds, "A" fails (owner A's reload),
	// "B" is owner B's in-flight reload, which runs A's whole
	// write-then-failed-reload sequence before returning success.
	phase := "ok"
	var reloadCalls int
	var aApplyErr error
	aApplyRan := false

	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) == 0 || args[0] != "reload" {
			return nil
		}
		reloadCalls++
		switch phase {
		case "A":
			return errors.New("simulated reload failure for owner A")
		case "B":
			// B's reload has re-read the directory and succeeded. Before B
			// records that success, owner A writes its files and its own
			// reload fails, recording the debt.
			phase = "A"
			aApplyRan = true
			aApplyErr = mA.Apply(ifaces)
			phase = "B-done"
			return nil
		default:
			return nil
		}
	}
	t.Cleanup(func() { runNetworkctl = orig })

	// Setup: land owner B's files so its teardown has something to remove.
	if err := mB.Apply(ifaces); err != nil {
		t.Fatalf("setup Apply for owner B should succeed: %v", err)
	}

	// T1..T5: B tears down; A's failing Apply runs inside B's reload window.
	// #6852 retired Clear; Apply(nil) is the teardown, and it sweeps the same
	// managed files and runs the same reload.
	phase = "B"
	if err := mB.Apply(nil); err != nil {
		t.Fatalf("owner B's teardown reload succeeds, so it must succeed: %v", err)
	}
	if !aApplyRan {
		t.Fatal("setup: owner A's Apply must have run inside owner B's reload window")
	}
	if aApplyErr == nil {
		t.Fatal("setup: owner A's Apply must fail — its reload fails")
	}

	// T6: A retries with byte-identical files. The debt A recorded at T4 must
	// have survived B's clear, so this retry re-runs the reload (and surfaces
	// the still-failing state) instead of reporting a false success.
	phase = "A"
	callsBefore := reloadCalls
	if err := mA.Apply(ifaces); err == nil {
		t.Fatal("owner A's identical retry reported SUCCESS. Owner B's concurrent " +
			"reload blind-cleared A's activation debt, so the retry saw " +
			"changed==false && debt==false and SKIPPED the reload. B's reload " +
			"re-read the directory before A's files existed, so nothing activated " +
			"them: the kernel is running the pre-A config while the operator is " +
			"told the commit landed. A debt cleared whose work never ran is a " +
			"silent skip of a reload the system believes it performed")
	}
	if reloadCalls != callsBefore+1 {
		t.Fatalf("owner A's retry must RE-RUN the reload from the surviving debt, got %d new calls (want 1)",
			reloadCalls-callsBefore)
	}

	// Recovery: once the reload works, the debt discharges normally.
	phase = "ok"
	if err := mA.Apply(ifaces); err != nil {
		t.Fatalf("owner A's Apply should succeed once the reload recovers: %v", err)
	}
	callsBefore = reloadCalls
	if err := mA.Apply(ifaces); err != nil {
		t.Fatalf("steady-state Apply should succeed: %v", err)
	}
	if reloadCalls != callsBefore {
		t.Fatalf("the debt must discharge on the recovering reload, got %d extra calls", reloadCalls-callsBefore)
	}
}
