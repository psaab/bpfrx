package networkd

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// rpFilterFixture points procSysNetRoot at a temp tree with the slow-path TUN's
// rp_filter pre-set to networkd's post-reload default, and returns a reader for
// it. restoreSlowPathRPFilter writes "0"; anything else means it never ran.
func rpFilterFixture(t *testing.T) func() string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "conf", "xpf-usp0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "conf", "all"), 0o755); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "conf", "all", "rp_filter"), []byte("0\n"), 0o644); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	path := filepath.Join(dir, "rp_filter")
	write := func(v string) {
		if err := os.WriteFile(path, []byte(v), 0o644); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	write("2")
	prev := procSysNetRoot
	procSysNetRoot = root
	t.Cleanup(func() { procSysNetRoot = prev })

	return func() string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading rp_filter: %v", err)
		}
		return string(b)
	}
}

// TestApplyTailSurvivesExternalDebtDischarge_5718 is the #5718 fold r4
// BLOCKER 2 fail-on-revert.
//
// Making the reload debt process-scoped (fold F2) was right for the reload
// itself — `networkctl reload` acts on one systemd-networkd, and pkg/daemon
// runs it too. But Apply's activation pass has a TAIL that only Apply can
// perform: the per-interface `networkctl reconfigure` that applies bond/VLAN
// addresses, and restoreSlowPathRPFilter, which re-disables rp_filter on the
// userspace dataplane's slow-path TUN after networkd resets it. Both sit behind
// `needReload`, which was computed purely from `changed || globalDebt`.
//
// The interleaving that loses them:
//
//  1. Apply writes files; its reload FAILS. It returns early — before the
//     tail — so no reconfigure debt is recorded either.
//  2. pkg/daemon runs a successful `networkctl reload` of its own (linksetup
//     rename, device-map, bootstrap) and reports it, clearing the GLOBAL debt.
//  3. Apply runs again with byte-identical files: changed==false, no reload
//     debt, no reconfigure debt -> the whole block is skipped, nil returned.
//
// The kernel did re-read the directory, so the reload obligation really was
// discharged — but the addresses were never reconfigured and rp_filter is left
// at networkd's default, silently dropping locally-originated traffic via the
// TUN. An external owner discharged a postcondition it cannot perform.
func TestApplyTailSurvivesExternalDebtDischarge_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	readRPFilter := rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	var reloadCalls, reconfigureCalls int
	// #5718 fold r6: record the whole argv, not just a count keyed on args[0].
	// `networkctl reconfigure` NAMES the interfaces it acts on, so counting
	// calls asserts only that the tail ran — a regression that reconfigured the
	// WRONG interfaces (an inverted bond-member exclusion, a stale list, the
	// wrong field read for the name) makes exactly the same number of calls and
	// the guard cannot fire. The argument list is the part that carries the
	// behaviour.
	var reconfigureArgs [][]string
	reloadFails := true
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		switch {
		case len(args) > 0 && args[0] == "reload":
			reloadCalls++
			if reloadFails {
				return errors.New("simulated networkctl reload failure")
			}
		case len(args) > 0 && args[0] == "reconfigure":
			reconfigureCalls++
			reconfigureArgs = append(reconfigureArgs, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := debtTestIfaces()

	// 1) Apply writes the files; its reload fails, so it returns early and
	//    never reaches the tail.
	if err := m.Apply(ifaces); err == nil {
		t.Fatal("setup: Apply must fail when its reload fails")
	}
	if reconfigureCalls != 0 {
		t.Fatalf("setup: a failed reload returns before the tail, got %d reconfigure call(s)", reconfigureCalls)
	}
	if got := readRPFilter(); got != "2" {
		t.Fatalf("setup: rp_filter should still be networkd's default, got %q", got)
	}

	// 2) An external reload owner (pkg/daemon) succeeds and reports it. The
	//    kernel HAS now re-read the directory, so the global debt is genuinely
	//    discharged.
	NoteReloadResult(BeginReload(), nil)
	if reloadDebtOutstanding() {
		t.Fatal("setup: the external success must discharge the global reload debt")
	}

	// 3) The next Apply sees unchanged files and no global debt. It must still
	//    run ITS tail, because nobody else can.
	reloadFails = false
	reloadCalls, reconfigureCalls, reconfigureArgs = 0, 0, nil
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("Apply should succeed: %v", err)
	}

	// The tail must reconfigure the interface this Apply actually wrote a file
	// for. debtTestIfaces() declares exactly one managed, non-bond-member
	// interface, so the production argv is fully determined: ["reconfigure",
	// "trust0"]. Spelled out rather than derived from the fixture — deriving
	// the expectation from the same source the production code reads would
	// make this assertion true by construction.
	wantArgs := []string{"reconfigure", "trust0"}
	if len(reconfigureArgs) != 1 || !slices.Equal(reconfigureArgs[0], wantArgs) {
		t.Fatalf("the activation tail must run %v exactly once; got %v. An address "+
			"application that names the wrong interfaces leaves the real ones unapplied "+
			"while still making the call the count-only assertion was watching for",
			wantArgs, reconfigureArgs)
	}

	if reconfigureCalls == 0 {
		t.Fatal("Apply skipped `networkctl reconfigure` after an EXTERNAL owner discharged " +
			"the global reload debt. Apply's own reload had failed, so the tail never ran " +
			"and no reconfigure debt was recorded; the external reload cleared the only " +
			"remaining signal. Bond and VLAN addresses are never applied and Apply reports " +
			"success (#5718 fold r4 BLOCKER 2)")
	}
	if got := readRPFilter(); got != "0" {
		t.Fatalf("Apply left rp_filter on the slow-path TUN at %q, not \"0\". networkd's "+
			"reload resets it to the default, and restoreSlowPathRPFilter is the only thing "+
			"that puts it back — it sits behind the same gate the external discharge "+
			"skipped, so locally-originated traffic via the TUN stays dropped", got)
	}
}

// TestApplyTailNotRepeatedOnceComplete_5718 is the scope control: the
// Manager-scoped obligation must be discharged by its own completed pass, not
// become a latch that re-runs the tail on every subsequent Apply.
func TestApplyTailNotRepeatedOnceComplete_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	var reloadCalls, reconfigureCalls int
	var reconfigureArgs [][]string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		switch {
		case len(args) > 0 && args[0] == "reload":
			reloadCalls++
		case len(args) > 0 && args[0] == "reconfigure":
			reconfigureCalls++
			reconfigureArgs = append(reconfigureArgs, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := debtTestIfaces()

	// A clean first Apply completes its tail.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if reloadCalls != 1 || reconfigureCalls != 1 {
		t.Fatalf("first Apply should reload once and reconfigure once, got %d/%d",
			reloadCalls, reconfigureCalls)
	}
	// Same reasoning as TestApplyTailSurvivesExternalDebtDischarge_5718: this
	// test's subject is repetition, so the call COUNT is load-bearing here —
	// but a count alone still cannot see a tail that runs the right number of
	// times against the wrong interfaces.
	if want := []string{"reconfigure", "trust0"}; !slices.Equal(reconfigureArgs[0], want) {
		t.Fatalf("first Apply ran %v, want %v", reconfigureArgs[0], want)
	}

	// An identical Apply has nothing to do: files unchanged, no global debt,
	// no reconfigure debt, and the previous pass completed its tail.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("steady-state Apply: %v", err)
	}
	if reloadCalls != 1 || reconfigureCalls != 1 {
		t.Fatalf("a completed activation pass must not leave the Manager owing its tail "+
			"forever; steady-state Apply re-ran networkctl (reload=%d reconfigure=%d, want 1/1)",
			reloadCalls, reconfigureCalls)
	}
}
