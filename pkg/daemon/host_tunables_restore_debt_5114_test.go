// Retain-on-failed-restore tests for #5114.
//
// Invariant: ownership of a host tunable is released only after a
// SUCCESSFUL restore write. When `claim-host-tunables` flips off (or
// userspace-dp is withdrawn) and a captured value's sysfs/proc write
// FAILS, the daemon MUST retain that capture + its active debt so a
// later reconcile retries it — never wipe the snapshot and leave the
// host pinned at xpfd's governor / netdev_budget / lowered neigh
// retrans_time_ms.
//
// The write failure is injected through the fakeHostFS.writeErrs seam.
// RED-on-revert: with the void-swallow + unconditional-clear restored,
// the retain assertions fail because the capture is wiped despite the
// failed write.
package daemon

import (
	"errors"
	"testing"
)

// errWriteDenied is a transient sysfs/proc write failure injected via
// fakeHostFS.writeErrs to exercise the #5114 retain-on-failure path.
var errWriteDenied = errors.New("transient write failure (test)")

// TestApplyStep0_ClaimOff_RetainsFailedGovernorRestore pins the
// host-scope retain-on-failure path: a governor whose restore write
// fails keeps its captured baseline and priorTunablesActive stays true
// (retry debt); the governors that restored and the budget are dropped.
func TestApplyStep0_ClaimOff_RetainsFailedGovernorRestore(t *testing.T) {
	const cpu0 = "/sys/cpu0/scaling_governor"
	const cpu1 = "/sys/cpu1/scaling_governor"
	d := &Daemon{}
	fs := newFakeHostFS()
	fs.cpufreqPaths = []string{cpu0, cpu1}
	fs.files[cpu0] = []byte("schedutil") // pre-xpfd
	fs.files[cpu1] = []byte("schedutil") // pre-xpfd
	fs.files[sysctlPathNetdevBudget] = []byte("450")
	execer := &fakeRSSExecutor{}

	// Phase 1: claim on → capture schedutil x2 + budget 450, write
	// performance + 600.
	d.applyStep0TunablesWith(true, true, "performance", 600,
		false, false, 0, 0, nil, fs, execer)
	if !d.priorTunablesActive {
		t.Fatal("setup: priorTunablesActive must be true after claimed apply")
	}
	if d.priorTunables.governors[cpu1] != "schedutil" {
		t.Fatalf("setup: want captured cpu1=schedutil, got %q", d.priorTunables.governors[cpu1])
	}

	// Phase 2: flip claim off; inject a transient write failure on cpu1's
	// restore. cpu0 + budget restore; cpu1 fails.
	fs.writes = map[string]string{}
	fs.writeOrder = nil
	fs.writeErrs[cpu1] = errWriteDenied

	d.applyStep0TunablesWith(true, false, "performance", 600,
		false, false, 0, 0, nil, fs, execer)

	// cpu0 + budget restored to pre-xpfd values.
	if got := fs.writes[cpu0]; got != "schedutil" {
		t.Errorf("cpu0 should restore to schedutil, got %q", got)
	}
	if got := fs.writes[sysctlPathNetdevBudget]; got != "450" {
		t.Errorf("budget should restore to 450, got %q", got)
	}
	// cpu1 write failed → not recorded.
	if _, ok := fs.writes[cpu1]; ok {
		t.Errorf("cpu1 restore write should have failed, but was recorded: %v", fs.writes)
	}

	// RETAIN the failed capture; DROP the restored ones.
	if got, ok := d.priorTunables.governors[cpu1]; !ok || got != "schedutil" {
		t.Errorf("#5114: failed cpu1 capture must be RETAINED (got %q ok=%v)", got, ok)
	}
	if _, ok := d.priorTunables.governors[cpu0]; ok {
		t.Errorf("#5114: restored cpu0 capture must be dropped, still present: %v", d.priorTunables.governors)
	}
	if d.priorTunables.budget != "" {
		t.Errorf("#5114: restored budget capture must be cleared, got %q", d.priorTunables.budget)
	}
	// Debt remains → ownership NOT released.
	if !d.priorTunablesActive {
		t.Error("#5114: priorTunablesActive must stay TRUE while restore debt remains")
	}

	// Phase 3: retry — the write now succeeds → debt cleared, ownership
	// released.
	fs.writes = map[string]string{}
	fs.writeOrder = nil
	delete(fs.writeErrs, cpu1)

	d.applyStep0TunablesWith(true, false, "performance", 600,
		false, false, 0, 0, nil, fs, execer)

	if got := fs.writes[cpu1]; got != "schedutil" {
		t.Errorf("retry: cpu1 should restore to schedutil, got %q", got)
	}
	if len(d.priorTunables.governors) != 0 {
		t.Errorf("retry: all governor debt must clear, got %v", d.priorTunables.governors)
	}
	if d.priorTunablesActive {
		t.Error("retry: priorTunablesActive must be false once all captures restored")
	}
}

// TestApplyStep0_ClaimOff_AllRestore_ReleasesOwnership pins the
// all-success path: every host-scope capture restores → snapshot fully
// cleared, priorTunablesActive=false.
func TestApplyStep0_ClaimOff_AllRestore_ReleasesOwnership(t *testing.T) {
	const cpu0 = "/sys/cpu0/scaling_governor"
	d := &Daemon{}
	fs := newFakeHostFS()
	fs.cpufreqPaths = []string{cpu0}
	fs.files[cpu0] = []byte("schedutil")
	fs.files[sysctlPathNetdevBudget] = []byte("450")
	execer := &fakeRSSExecutor{}

	d.applyStep0TunablesWith(true, true, "performance", 600,
		false, false, 0, 0, nil, fs, execer)
	d.applyStep0TunablesWith(true, false, "performance", 600,
		false, false, 0, 0, nil, fs, execer)

	if len(d.priorTunables.governors) != 0 {
		t.Errorf("all-restore: governor snapshot must clear, got %v", d.priorTunables.governors)
	}
	if d.priorTunables.budget != "" {
		t.Errorf("all-restore: budget snapshot must clear, got %q", d.priorTunables.budget)
	}
	if d.priorTunablesActive {
		t.Error("all-restore: priorTunablesActive must be false")
	}
}

// TestApplyStep0_DPOff_RetainsFailedNeighRestore pins the neighbor
// retrans_time_ms retain-on-failure path (#5114): when userspace-dp is
// withdrawn and one path's restore write fails, that capture is RETAINED
// (so the branch retries it next reconcile) while the restored paths are
// dropped.
func TestApplyStep0_DPOff_RetainsFailedNeighRestore(t *testing.T) {
	v4em0 := sysctlNeighV4Dir + "/em0/retrans_time_ms"
	v4def := sysctlNeighV4Dir + "/default/retrans_time_ms"
	f := neighFSWithIfaces("1000", "em0")
	d := &Daemon{}
	execer := &fakeRSSExecutor{}

	// Phase 1: userspace-dp on → capture 1000 x4, lower to 250.
	d.applyStep0TunablesWith(true, false, "", 0, false, false, 0, 0, nil, f, execer)
	if f.writes[v4em0] != "250" {
		t.Fatalf("setup: em0 not lowered, got %q", f.writes[v4em0])
	}
	if d.priorTunables.neighRetrans[v4em0] != "1000" {
		t.Fatalf("setup: want captured v4/em0=1000, got %q", d.priorTunables.neighRetrans[v4em0])
	}

	// Phase 2: userspace-dp off; inject a transient failure on v4/em0's
	// restore. The other three paths restore to 1000; v4/em0 fails.
	f.writes = map[string]string{}
	f.writeOrder = nil
	f.writeErrs[v4em0] = errWriteDenied

	d.applyStep0TunablesWith(false, false, "", 0, false, false, 0, 0, nil, f, execer)

	if got := f.writes[v4def]; got != "1000" {
		t.Errorf("v4/default should restore to 1000, got %q", got)
	}
	if _, ok := f.writes[v4em0]; ok {
		t.Errorf("v4/em0 restore write should have failed, but was recorded: %v", f.writes)
	}
	// RETAIN the failed capture; drop the restored ones.
	if got, ok := d.priorTunables.neighRetrans[v4em0]; !ok || got != "1000" {
		t.Errorf("#5114: failed v4/em0 capture must be RETAINED (got %q ok=%v)", got, ok)
	}
	if _, ok := d.priorTunables.neighRetrans[v4def]; ok {
		t.Errorf("#5114: restored v4/default capture must be dropped, still present: %v",
			d.priorTunables.neighRetrans)
	}
	if len(d.priorTunables.neighRetrans) != 1 {
		t.Errorf("#5114: exactly one failed neigh capture must remain, got %v",
			d.priorTunables.neighRetrans)
	}

	// Phase 3: retry — write now succeeds → debt cleared.
	f.writes = map[string]string{}
	f.writeOrder = nil
	delete(f.writeErrs, v4em0)

	d.applyStep0TunablesWith(false, false, "", 0, false, false, 0, 0, nil, f, execer)

	if got := f.writes[v4em0]; got != "1000" {
		t.Errorf("retry: v4/em0 should restore to 1000, got %q", got)
	}
	if len(d.priorTunables.neighRetrans) != 0 {
		t.Errorf("retry: all neigh debt must clear, got %v", d.priorTunables.neighRetrans)
	}
}
