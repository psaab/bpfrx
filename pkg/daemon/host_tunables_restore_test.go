// Restore-on-disable tests for #801 Phase-B Step-0 host tunables (B2 +
// I1). Pins the "restore reverts to pre-xpfd value, NOT kernel default"
// semantics so a future refactor can't silently regress the capture.
//
// Also covers the B1 opt-in gate: host-scope knobs (cpu governor +
// netdev_budget + mlx5 adaptive flip) MUST NOT be written when
// `claim-host-tunables` is false — regardless of what the compiler
// resolved for the default values. A kernel-default restore would be
// equally incorrect: if an operator ran `sysctl -w
// net.core.netdev_budget=450` before starting xpfd, that is the value
// restore must write back, not the kernel's hardcoded 300.
package daemon

import (
	"reflect"
	"testing"
)

// TestApplyStep0Tunables_OptInFalse_WritesNothing pins B1: the daemon
// path MUST NOT invoke any host-scope write when claim_host_tunables is
// false, even when governor + budget are explicitly set in config.
func TestApplyStep0Tunables_OptInFalse_WritesNothing(t *testing.T) {
	d := &Daemon{}
	fs := newFakeHostFS()
	fs.cpufreqPaths = []string{"/sys/cpu0/scaling_governor"}
	fs.files["/sys/cpu0/scaling_governor"] = []byte("schedutil")
	fs.files[sysctlPathNetdevBudget] = []byte("300")
	execer := &fakeRSSExecutor{
		drivers:  map[string]string{"mlx0": "mlx5_core"},
		ethtoolC: map[string][]byte{"mlx0": []byte(mlx5CoalesceProbeAdaptiveOn)},
	}

	// claim=false, governor=performance, budget=600 → everything skipped.
	d.applyStep0TunablesWith(
		true,         // userspaceDP
		false,        // claimHostTunables — THE GATE
		"performance", 600,
		true, false, 8, 8,
		[]string{"mlx0"},
		fs, execer,
	)

	if len(fs.writes) != 0 {
		t.Errorf("B1: writes occurred with claim=false: %v", fs.writes)
	}
	for _, c := range execer.calls {
		if len(c) > 0 && c[0] == "-C" {
			t.Errorf("B1: ethtool -C with claim=false: %v", c)
		}
	}
	if d.priorTunablesActive {
		t.Error("B1: priorTunablesActive must stay false when gated off")
	}
}

// TestApplyStep0Tunables_OptInTrue_CapturesAndWrites pins B2 capture:
// the first claimed apply must record pre-xpfd values before writing.
func TestApplyStep0Tunables_OptInTrue_CapturesAndWrites(t *testing.T) {
	d := &Daemon{}
	fs := newFakeHostFS()
	fs.cpufreqPaths = []string{"/sys/cpu0/scaling_governor"}
	fs.files["/sys/cpu0/scaling_governor"] = []byte("schedutil")
	fs.files[sysctlPathNetdevBudget] = []byte("450") // operator override, not kernel default 300
	execer := &fakeRSSExecutor{
		drivers:  map[string]string{"mlx0": "mlx5_core"},
		ethtoolC: map[string][]byte{"mlx0": []byte(mlx5CoalesceProbeAdaptiveOn)},
	}

	d.applyStep0TunablesWith(
		true, true,
		"performance", 600,
		true, false, 8, 8,
		[]string{"mlx0"},
		fs, execer,
	)

	if !d.priorTunablesActive {
		t.Fatal("priorTunablesActive must be true after claimed apply")
	}
	if d.priorTunables == nil {
		t.Fatal("priorTunables must be non-nil after claimed apply")
	}
	// Governor: captured the schedutil value, wrote performance.
	if got := d.priorTunables.governors["/sys/cpu0/scaling_governor"]; got != "schedutil" {
		t.Errorf("want captured governor=schedutil, got %q", got)
	}
	if got := fs.writes["/sys/cpu0/scaling_governor"]; got != "performance" {
		t.Errorf("want wrote governor=performance, got %q", got)
	}
	// Budget: captured 450 (operator-set), wrote 600.
	if got := d.priorTunables.budget; got != "450" {
		t.Errorf("want captured budget=450 (operator), got %q", got)
	}
	if got := fs.writes[sysctlPathNetdevBudget]; got != "600" {
		t.Errorf("want wrote budget=600, got %q", got)
	}
	// mlx5: captured adaptive=on rx=8 tx=8 (from probe), wrote adaptive=off.
	st, ok := d.priorTunables.mlx5Adaptive["mlx0"]
	if !ok {
		t.Fatal("want captured mlx5 state for mlx0")
	}
	if !st.adaptiveRX || !st.adaptiveTX {
		t.Errorf("want captured adaptive RX=TX=on, got %+v", st)
	}
}

// TestApplyStep0Tunables_OptInFlipsToFalse_RestoresPreXpfdValues pins
// B2 restore: when claim_host_tunables flips true → false, every
// captured value is written back. This is the semantic I1 pins: restore
// reverts to the EXACT value xpfd read, not the kernel's compiled default.
func TestApplyStep0Tunables_OptInFlipsToFalse_RestoresPreXpfdValues(t *testing.T) {
	d := &Daemon{}
	fs := newFakeHostFS()
	fs.cpufreqPaths = []string{"/sys/cpu0/scaling_governor"}
	fs.files["/sys/cpu0/scaling_governor"] = []byte("schedutil") // pre-xpfd
	fs.files[sysctlPathNetdevBudget] = []byte("450")             // pre-xpfd (NOT kernel default 300)
	execer := &fakeRSSExecutor{
		drivers:  map[string]string{"mlx0": "mlx5_core"},
		ethtoolC: map[string][]byte{"mlx0": []byte(mlx5CoalesceProbeAdaptiveOn)},
	}

	// Step 1: claim + write (captures schedutil + 450 + adaptive=on).
	d.applyStep0TunablesWith(
		true, true,
		"performance", 600,
		true, false, 8, 8,
		[]string{"mlx0"},
		fs, execer,
	)

	// Sanity: we wrote performance + 600 + adaptive=off.
	if fs.writes["/sys/cpu0/scaling_governor"] != "performance" {
		t.Fatalf("setup: governor write failed: %v", fs.writes)
	}
	if fs.writes[sysctlPathNetdevBudget] != "600" {
		t.Fatalf("setup: budget write failed: %v", fs.writes)
	}

	// Step 2: flip claim to false. Restore path runs.
	fs.writes = map[string]string{} // clear to isolate restore writes
	fs.writeOrder = nil
	execer.calls = nil

	d.applyStep0TunablesWith(
		true,  // still userspaceDP
		false, // flip!
		"performance", 600,
		true, false, 8, 8,
		[]string{"mlx0"},
		fs, execer,
	)

	// I1: restore wrote the pre-xpfd values exactly — NOT kernel default.
	if got := fs.writes["/sys/cpu0/scaling_governor"]; got != "schedutil" {
		t.Errorf("I1 restore: want schedutil (pre-xpfd), got %q", got)
	}
	if got := fs.writes[sysctlPathNetdevBudget]; got != "450" {
		t.Errorf("I1 restore: want 450 (operator pre-xpfd), got %q (should NOT be kernel default 300)", got)
	}
	// mlx5 restore: adaptive-rx/tx=on (pre-xpfd state from probe).
	sawRestoreOn := false
	for _, c := range execer.calls {
		if len(c) < 3 || c[0] != "-C" || c[1] != "mlx0" {
			continue
		}
		adapt := map[string]string{}
		for i := 2; i < len(c)-1; i += 2 {
			adapt[c[i]] = c[i+1]
		}
		if adapt["adaptive-rx"] == "on" && adapt["adaptive-tx"] == "on" &&
			adapt["rx-usecs"] == "8" && adapt["tx-usecs"] == "8" {
			sawRestoreOn = true
		}
	}
	if !sawRestoreOn {
		t.Errorf("I1 restore: want ethtool -C mlx0 adaptive-rx on adaptive-tx on rx-usecs 8 tx-usecs 8, got %v", execer.calls)
	}

	// Snapshot cleared.
	if d.priorTunablesActive {
		t.Error("priorTunablesActive must be false after restore")
	}
	if d.priorTunables != nil {
		t.Error("priorTunables must be nil after restore")
	}
}

// TestApplyStep0Tunables_Reconcile_DoesNotLoseOriginalCapture pins the
// first-apply-wins invariant: a second claimed apply must not overwrite
// the captured pre-xpfd value with xpfd's own write. Otherwise restore
// would revert to "performance" (xpfd's write) not "schedutil" (pre-xpfd).
func TestApplyStep0Tunables_Reconcile_DoesNotLoseOriginalCapture(t *testing.T) {
	d := &Daemon{}
	fs := newFakeHostFS()
	fs.cpufreqPaths = []string{"/sys/cpu0/scaling_governor"}
	fs.files["/sys/cpu0/scaling_governor"] = []byte("schedutil") // pre-xpfd
	execer := &fakeRSSExecutor{}

	// First apply: captures schedutil, writes performance.
	d.applyStep0TunablesWith(
		true, true,
		"performance", 0,
		false, false, 0, 0,
		nil,
		fs, execer,
	)
	// Second apply: fs now has "performance" (xpfd's write). Capture
	// MUST still return schedutil, not performance.
	d.applyStep0TunablesWith(
		true, true,
		"performance", 0,
		false, false, 0, 0,
		nil,
		fs, execer,
	)
	if got := d.priorTunables.governors["/sys/cpu0/scaling_governor"]; got != "schedutil" {
		t.Errorf("first-apply-wins: want schedutil, got %q (lost pre-xpfd capture)", got)
	}
}

// TestRestoreHostTunables_Nil_NoOp: restore must tolerate a nil
// priorHostTunables without panicking — happens when claim was never
// enabled and shutdown triggers the restore path.
func TestRestoreHostTunables_Nil_NoOp(t *testing.T) {
	fs := newFakeHostFS()
	execer := &fakeRSSExecutor{}
	restoreHostTunables(nil, fs, execer) // must not panic
	if len(fs.writes) != 0 {
		t.Errorf("nil restore must not write, got %v", fs.writes)
	}
	if len(execer.calls) != 0 {
		t.Errorf("nil restore must not call ethtool, got %v", execer.calls)
	}
}

// TestRestoreHostTunables_EmptyCapture_NoOp: an initialized but empty
// capture is the shape after first-apply but before any write
// succeeded (theoretical). Must be a no-op, not a blind kernel-default
// write.
func TestRestoreHostTunables_EmptyCapture_NoOp(t *testing.T) {
	fs := newFakeHostFS()
	execer := &fakeRSSExecutor{}
	restoreHostTunables(newPriorHostTunables(), fs, execer)
	if len(fs.writes) != 0 {
		t.Errorf("empty restore must not write, got %v", fs.writes)
	}
	if len(execer.calls) != 0 {
		t.Errorf("empty restore must not call ethtool, got %v", execer.calls)
	}
}

// TestVMHeuristic_HypervisorType pins M1: /sys/hypervisor/type non-empty
// classifies the host as a VM.
func TestVMHeuristic_HypervisorType(t *testing.T) {
	fs := newFakeHostFS()
	fs.files["/sys/hypervisor/type"] = []byte("kvm\n")
	reason := vmHeuristic(fs)
	if reason == "" {
		t.Error("want VM signal from /sys/hypervisor/type=kvm")
	}
}

// TestVMHeuristic_CPUInfoFlag pins M1: the "hypervisor" flag in
// /proc/cpuinfo classifies the host as a VM.
func TestVMHeuristic_CPUInfoFlag(t *testing.T) {
	fs := newFakeHostFS()
	fs.files["/proc/cpuinfo"] = []byte(
		"processor\t: 0\n" +
			"vendor_id\t: GenuineIntel\n" +
			"flags\t\t: fpu vme de hypervisor pclmulqdq ssse3\n",
	)
	reason := vmHeuristic(fs)
	if reason == "" {
		t.Error("want VM signal from cpuinfo hypervisor flag")
	}
}

// TestVMHeuristic_BareMetal_NoSignal: no hypervisor signals → empty
// reason → caller will log Warn per M1.
func TestVMHeuristic_BareMetal_NoSignal(t *testing.T) {
	fs := newFakeHostFS()
	fs.files["/proc/cpuinfo"] = []byte(
		"processor\t: 0\n" +
			"vendor_id\t: GenuineIntel\n" +
			"flags\t\t: fpu vme de pclmulqdq ssse3\n",
	)
	if got := vmHeuristic(fs); got != "" {
		t.Errorf("bare metal: want empty signal, got %q", got)
	}
}

// TestPriorHostTunables_CaptureIdempotence pins first-apply-wins at the
// capture primitive level so a regression is localized.
func TestPriorHostTunables_CaptureIdempotence(t *testing.T) {
	p := newPriorHostTunables()
	p.captureGovernor("/sys/cpu0/scaling_governor", "schedutil")
	p.captureGovernor("/sys/cpu0/scaling_governor", "performance") // should be ignored
	if got := p.governors["/sys/cpu0/scaling_governor"]; got != "schedutil" {
		t.Errorf("capture-idempotence: want schedutil, got %q", got)
	}
	p.captureBudget("450")
	p.captureBudget("600") // should be ignored
	if p.budget != "450" {
		t.Errorf("capture-idempotence: want 450, got %q", p.budget)
	}
	s := mlx5CoalesceState{adaptiveRX: true, adaptiveTX: true, rxUsecs: 8, txUsecs: 8}
	p.captureMlx5Coalesce("mlx0", s)
	s2 := mlx5CoalesceState{adaptiveRX: false, adaptiveTX: false, rxUsecs: 16, txUsecs: 16}
	p.captureMlx5Coalesce("mlx0", s2) // should be ignored
	if got := p.mlx5Adaptive["mlx0"]; !reflect.DeepEqual(got, s) {
		t.Errorf("capture-idempotence: want original mlx5 state, got %+v", got)
	}
}
