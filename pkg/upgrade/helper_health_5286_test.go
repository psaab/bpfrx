package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeHelperStatus builds a HelperStatusFunc returning a fixed result.
func fakeHelperStatus(enabled, armed bool, pid int, err error) HelperStatusFunc {
	return func(string, time.Duration) (bool, bool, int, error) { return enabled, armed, pid, err }
}

// helperExeAt returns a HelperExeFunc that reports the helper is executing
// versionsDir/<ver>/xpf-userspace-dp — the shape /proc/<pid>/exe resolves to for
// a helper spawned co-located with a versioned xpfd.
func helperExeAt(versionsDir, ver string) HelperExeFunc {
	return func(int) (string, error) {
		return filepath.Join(versionsDir, ver, "xpf-userspace-dp"), nil
	}
}

// TestHelperHealthProbe_ArmedForwardingTargetVersion_Healthy: the happy path —
// unit active AND helper armed+forwarding AND executing the target version's
// binary -> healthy (nil).
func TestHelperHealthProbe_ArmedForwardingTargetVersion_Healthy(t *testing.T) {
	versions := t.TempDir()
	const target = "1.2.3"
	probe := HelperHealthProbe(HelperHealthDeps{
		UnitActive:   func(context.Context) (bool, error) { return true, nil },
		Status:       fakeHelperStatus(true, true, 4242, nil),
		HelperExe:    helperExeAt(versions, target),
		VersionsDir:  versions,
		PollInterval: time.Millisecond,
	})
	if err := probe(target, 500*time.Millisecond); err != nil {
		t.Fatalf("armed+forwarding on the target version must be healthy: %v", err)
	}
}

// TestHelperHealthProbe_ActiveButNotForwarding_FailsClosed is the core #5286
// case: the process is UP (systemctl is-active true) but the helper is NOT
// forwarding (enabled, forwarding_armed=false). The pre-fix is-active-only gate
// reported healthy here; the new gate MUST fail closed.
func TestHelperHealthProbe_ActiveButNotForwarding_FailsClosed(t *testing.T) {
	versions := t.TempDir()
	const target = "1.2.3"
	probe := HelperHealthProbe(HelperHealthDeps{
		UnitActive:   func(context.Context) (bool, error) { return true, nil }, // process reported UP
		Status:       fakeHelperStatus(true, false, 4242, nil),                 // enabled but NOT forwarding
		HelperExe:    helperExeAt(versions, target),
		VersionsDir:  versions,
		PollInterval: time.Millisecond,
	})
	err := probe(target, 40*time.Millisecond)
	if err == nil {
		t.Fatal("helper up but NOT forwarding must FAIL CLOSED (not healthy)")
	}
	if !strings.Contains(err.Error(), "not forwarding") {
		t.Errorf("error should name the not-forwarding cause: %v", err)
	}
}

// TestHelperHealthProbe_StaleVersionHelper_FailsClosed: the helper is
// armed+forwarding, but it is a STALE previous-version helper (its binary lives
// under versions/<old>/), while the cut targets a NEW version. The armed
// witness must be rejected as not-on-target-version.
func TestHelperHealthProbe_StaleVersionHelper_FailsClosed(t *testing.T) {
	versions := t.TempDir()
	const target = "2.0.0"
	probe := HelperHealthProbe(HelperHealthDeps{
		UnitActive:   func(context.Context) (bool, error) { return true, nil },
		Status:       fakeHelperStatus(true, true, 4242, nil), // armed+forwarding...
		HelperExe:    helperExeAt(versions, "1.0.0"),          // ...but the OLD binary
		VersionsDir:  versions,
		PollInterval: time.Millisecond,
	})
	err := probe(target, 40*time.Millisecond)
	if err == nil {
		t.Fatal("an armed helper running the STALE version must FAIL CLOSED")
	}
	if !strings.Contains(err.Error(), "target version") {
		t.Errorf("error should name the target-version mismatch: %v", err)
	}
}

// TestHelperHealthProbe_UnitNotActive_FailsClosed: the precondition (process
// up) is not met -> not healthy, regardless of anything else.
func TestHelperHealthProbe_UnitNotActive_FailsClosed(t *testing.T) {
	versions := t.TempDir()
	probe := HelperHealthProbe(HelperHealthDeps{
		UnitActive:   func(context.Context) (bool, error) { return false, nil }, // process NOT up
		Status:       fakeHelperStatus(true, true, 1, nil),
		HelperExe:    helperExeAt(versions, "1.2.3"),
		VersionsDir:  versions,
		PollInterval: time.Millisecond,
	})
	if err := probe("1.2.3", 30*time.Millisecond); err == nil {
		t.Fatal("unit not active must FAIL CLOSED")
	}
}

// TestHelperHealthProbe_StatusQueryError_FailsClosed: an unreachable helper
// (control-socket dial error) is not healthy.
func TestHelperHealthProbe_StatusQueryError_FailsClosed(t *testing.T) {
	versions := t.TempDir()
	probe := HelperHealthProbe(HelperHealthDeps{
		UnitActive:   func(context.Context) (bool, error) { return true, nil },
		Status:       fakeHelperStatus(false, false, 0, fmt.Errorf("dial unix: connection refused")),
		HelperExe:    helperExeAt(versions, "1.2.3"),
		VersionsDir:  versions,
		PollInterval: time.Millisecond,
	})
	if err := probe("1.2.3", 30*time.Millisecond); err == nil {
		t.Fatal("an unreachable helper (status query error) must FAIL CLOSED")
	}
}

// TestHelperHealthy_RevertToIsActiveOnly_RegressesToFalseHealthy is the #5286
// RED-on-revert guard. With the process reported ACTIVE but the helper NOT
// armed+forwarding, the WIRED probe (NewSystemWithHelperHealth) fails closed,
// while the pre-fix is-active-only System (NewSystem) WRONGLY reports healthy —
// exactly the "cutover commits without a real dataplane" bug. Reverting the
// production wiring to NewSystem regresses to the second behavior.
//
// The is-active check is forced true via the shared unitActiveProbe seam so the
// contrast is observable in a hostless test (the realSystem fallback otherwise
// execs a real `systemctl is-active` that no test unit satisfies).
func TestHelperHealthy_RevertToIsActiveOnly_RegressesToFalseHealthy(t *testing.T) {
	old := unitActiveProbeCtx
	unitActiveProbeCtx = func(context.Context, string) (bool, error) { return true, nil } // process reported UP
	t.Cleanup(func() { unitActiveProbeCtx = old })

	versions := t.TempDir()
	const target = "9.9.9"
	// Helper up but NOT forwarding (enabled, forwarding_armed=false).
	deps := HelperHealthDeps{
		Status:       fakeHelperStatus(true, false, 7, nil),
		HelperExe:    helperExeAt(versions, target),
		VersionsDir:  versions,
		PollInterval: time.Millisecond,
		// UnitActive defaults to unitActiveProbe(DefaultUnit) -> forced true.
	}

	fixed := NewSystemWithHelperHealth("xpfd", HelperHealthProbe(deps))
	if err := fixed.HelperHealthy(target, 40*time.Millisecond); err == nil {
		t.Fatal("FIX: the wired probe must FAIL CLOSED when the helper is up but not forwarding")
	}

	reverted := NewSystem("xpfd") // the pre-fix, is-active-only wiring
	if err := reverted.HelperHealthy(target, 40*time.Millisecond); err != nil {
		t.Fatalf("REVERT contrast: the is-active-only NewSystem reports NOT healthy (%v); "+
			"it must (wrongly) report HEALTHY here — that regression is exactly what the "+
			"fix prevents", err)
	}
}

// TestRun_5286_NotForwardingHelper_DoesNotCommit drives a real cut through
// Run() with the PRODUCTION HelperHealthProbe reporting the helper up but NOT
// forwarding. The cut must NOT commit the new version: it auto-rolls-back to the
// previous version (standalone), so the target is never made live. Under the
// pre-fix is-active-only gate this scenario committed a non-forwarding node.
func TestRun_5286_NotForwardingHelper_DoesNotCommit(t *testing.T) {
	// First cut to 1.0.0 (establishes a rollback target).
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	// Stage 2.0.0, and wire the REAL #5286 probe: process up, helper enabled but
	// forwarding_armed=false (the failure the is-active-only gate missed).
	fs.stagedVersion = "2.0.0"
	writeFakeBin(t, filepath.Join(cfg.StagedDir, "xpfd"), "binary-xpfd-2.0.0")
	for _, b := range managedBins[1:] {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthProbe = HelperHealthProbe(HelperHealthDeps{
		UnitActive:   func(context.Context) (bool, error) { return true, nil },
		Status:       fakeHelperStatus(true, false, 111, nil), // up but NOT forwarding
		HelperExe:    helperExeAt(cfg.VersionsDir, "2.0.0"),
		VersionsDir:  cfg.VersionsDir,
		PollInterval: time.Millisecond,
	})
	// Keep the readiness wait short for the test.
	cfg.StartHealthDeadline = 40 * time.Millisecond
	r2, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if rerr := r2.Run(Options{}); rerr == nil {
		t.Fatal("cut MUST NOT commit when the helper is up but not forwarding")
	}
	// The cut rolled back: `current` is 1.0.0 again; 2.0.0 was never committed.
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("after fail-closed rollback current=%q, want 1.0.0 (2.0.0 must not be committed)", target)
	}
}
