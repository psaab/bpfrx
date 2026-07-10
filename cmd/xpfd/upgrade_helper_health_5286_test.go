package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/upgrade"
)

// TestBuildUpgradeSystem_WiresHelperProbe_5286 proves the production upgrade
// System construction site actually WIRES the helper-readiness probe
// (NewSystemWithHelperHealth), not the pre-fix is-active-only NewSystem whose
// realSystem.HelperHealthy ignored expectVersion and admitted a non-forwarding
// daemon.
//
// It overrides the control-socket status seam with a recorder reporting the
// helper up-but-not-forwarding. The wired System must (a) CONSULT that status
// query (proving the probe is installed) and (b) fail closed. If the site is
// reverted to upgrade.NewSystem(flags.unit), HelperHealthy never calls the
// status query -> statusCalled stays false -> RED.
func TestBuildUpgradeSystem_WiresHelperProbe_5286(t *testing.T) {
	versions := t.TempDir()
	const target = "3.1.4"

	statusCalled := false
	restoreStatus := swapHelperStatus(func(sock string, timeout time.Duration) (bool, bool, int, error) {
		statusCalled = true
		return true, false, 555, nil // process up, but helper NOT forwarding
	})
	defer restoreStatus()

	restoreActive := swapUnitActive(func(string) bool { return true })
	defer restoreActive()

	restoreExe := swapHelperExe(func(int) (string, error) {
		return filepath.Join(versions, target, "xpf-userspace-dp"), nil
	})
	defer restoreExe()

	restoreSock := swapControlSock(func(string) string { return "/unused-in-test.sock" })
	defer restoreSock()

	// Target the REAL production Config assembly (newUpgradeConfig -> Sys) so a
	// revert of the Sys wiring to upgrade.NewSystem turns this RED.
	cfg := newUpgradeConfig(upgradeFlags{unit: "xpfd", versionsDir: versions, configDBDir: t.TempDir()})

	// deadline 0 => exactly one gate evaluation, then fail closed (no sleeps).
	err := cfg.Sys.HelperHealthy(target, 0)
	if err == nil {
		t.Fatal("production System must FAIL CLOSED when the helper is up but not forwarding")
	}
	if !statusCalled {
		t.Fatal("production System did NOT consult the control-socket helper status query — " +
			"NewSystemWithHelperHealth is not wired (regressed to the is-active-only NewSystem)")
	}
}

// TestBuildUpgradeSystem_ArmedForwardingTarget_Healthy: the wired System reports
// healthy when the helper is armed+forwarding and executing the target version.
func TestBuildUpgradeSystem_ArmedForwardingTarget_Healthy(t *testing.T) {
	versions := t.TempDir()
	const target = "3.1.4"

	restoreStatus := swapHelperStatus(func(string, time.Duration) (bool, bool, int, error) {
		return true, true, 777, nil // armed + forwarding
	})
	defer restoreStatus()
	restoreActive := swapUnitActive(func(string) bool { return true })
	defer restoreActive()
	restoreExe := swapHelperExe(func(int) (string, error) {
		return filepath.Join(versions, target, "xpf-userspace-dp"), nil
	})
	defer restoreExe()
	restoreSock := swapControlSock(func(string) string { return "/unused-in-test.sock" })
	defer restoreSock()

	sys := buildUpgradeSystem(upgradeFlags{unit: "xpfd", versionsDir: versions, configDBDir: t.TempDir()})
	if err := sys.HelperHealthy(target, 200*time.Millisecond); err != nil {
		t.Fatalf("armed+forwarding on the target version must be healthy: %v", err)
	}
}

// swap helpers save/restore the package-level probe seams.

func swapHelperStatus(f upgrade.HelperStatusFunc) func() {
	old := upgradeHelperStatus
	upgradeHelperStatus = f
	return func() { upgradeHelperStatus = old }
}

func swapHelperExe(f upgrade.HelperExeFunc) func() {
	old := upgradeHelperExe
	upgradeHelperExe = f
	return func() { upgradeHelperExe = old }
}

func swapUnitActive(f func(string) bool) func() {
	old := upgradeUnitActive
	upgradeUnitActive = f
	return func() { upgradeUnitActive = old }
}

func swapControlSock(f func(string) string) func() {
	old := upgradeControlSock
	upgradeControlSock = f
	return func() { upgradeControlSock = old }
}
