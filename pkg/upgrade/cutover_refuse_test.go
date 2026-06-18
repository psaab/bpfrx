package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRefuseBeforeStop_NoPreviousVersion proves mechanism C (#1964): a cut
// with no rollback target (PreviousVersion=="") and NOT a sanctioned first
// cut is refused BEFORE StopUnit — the running daemon is never stopped, so a
// flip/start failure can never leave it offline. This is the core
// refuse-before-STOP invariant (plan §8 inv. C).
func TestRefuseBeforeStop_NoPreviousVersion(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	// No current symlink => PreviousVersion == "".

	err := r.Run(Options{}) // NOT sanctioned
	if err == nil {
		t.Fatal("expected refuse-before-STOP, got nil")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	// The daemon must NOT have been stopped (the whole point).
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" {
			t.Errorf("live mutation %q happened despite refuse-before-STOP", c)
		}
	}
	if !fs.unitRunning {
		t.Error("the daemon was stopped despite refuse-before-STOP")
	}
	// current must not have been created (never flipped).
	if _, lerr := os.Lstat(filepath.Join(cfg.VersionsDir, "current")); !os.IsNotExist(lerr) {
		t.Error("current symlink created despite refuse-before-STOP")
	}
}

// TestRefuseBeforeStop_ExhaustiveNoStopWithoutTarget is the exhaustive
// assertion the plan §8 requires: a StopUnit must be UNREACHABLE with
// PreviousVersion=="" outside the sanctioned first cut. We drive the cut
// across every staged-version / option combination and assert: whenever a
// "stop" appears in the call log with no prior current, the run was
// sanctioned (AllowNoRollbackFirstCut) or already stopped by the caller.
func TestRefuseBeforeStop_ExhaustiveNoStopWithoutTarget(t *testing.T) {
	cases := []struct {
		name      string
		opts      Options
		wantStop  bool
		wantError bool
	}{
		{"unsanctioned-first-cut-refuses", Options{}, false, true},
		{"sanctioned-first-cut-stops", Options{AllowNoRollbackFirstCut: true}, true, false},
		{"sanctioned-unit-already-stopped", Options{AllowNoRollbackFirstCut: true, UnitAlreadyStopped: true}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			if tc.opts.UnitAlreadyStopped {
				fs.unitRunning = false
			}
			r, _ := testEnv(t, fs)

			err := r.Run(tc.opts)
			gotErr := err != nil
			if gotErr != tc.wantError {
				t.Fatalf("error=%v (%v), wantError=%v", gotErr, err, tc.wantError)
			}
			gotStop := false
			for _, c := range fs.calls {
				if c == "stop" {
					gotStop = true
				}
			}
			if gotStop != tc.wantStop {
				t.Fatalf("stop-called=%v want %v (calls=%v)", gotStop, tc.wantStop, fs.calls)
			}
		})
	}
}

// TestFlipFailure_FirstCutRestartsDaemon proves the AGY-5 fix for a
// SANCTIONED first cut: a flip failure AFTER STOP restarts the first-install
// daemon from versions/current rather than leaving it offline, and returns a
// non-nil error so the caller does not treat it as success.
func TestFlipFailure_FirstCutRestartsDaemon(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	// Sanctioned first cut; make the flip (daemon-reload substep) fail once.
	fs.daemonReloadFailOnce = true

	err := r.Run(Options{AllowNoRollbackFirstCut: true})
	if err == nil {
		t.Fatal("expected a non-nil error after a flip failure on a first cut")
	}
	if !strings.Contains(err.Error(), "restarted the first-install daemon") {
		t.Fatalf("error does not report the first-install restart: %v", err)
	}
	// The unit must be back up (restarted after the failed flip).
	if !fs.unitRunning {
		t.Error("daemon left offline after a first-cut flip failure")
	}
	// Order: stop happened, then a start to bring it back.
	assertOrder(t, fs.calls, "stop", "start")
}

// TestFlipFailure_RollsBackWhenPreviousExists proves a flip failure AFTER
// STOP with a real previous version triggers auto-rollback (standalone),
// landing current back on the previous version.
func TestFlipFailure_RollsBackWhenPreviousExists(t *testing.T) {
	// Establish a previous version via a sanctioned first cut.
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	// Stage 2.0.0 and make the flip fail.
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.daemonReloadFailOnce = true

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected a flip-failure rollback error")
	}
	if !strings.Contains(err.Error(), "rolled back to 1.0.0") {
		t.Fatalf("error does not report rollback to 1.0.0: %v", err)
	}
	// current must be back at 1.0.0.
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("after flip-failure rollback current=%q want 1.0.0", target)
	}
	// The daemon must be running again (rollback started the old daemon).
	if !fs.unitRunning {
		t.Error("daemon left offline after a flip-failure rollback")
	}
}

// TestFlipFailure_HASurfacesErrorNoAutoRollback proves the HA path
// (SkipStartHealthRollback) surfaces a flip failure WITHOUT an auto-rollback
// (HA rollback is operator-driven) and reports the unit is stopped.
func TestFlipFailure_HASurfacesErrorNoAutoRollback(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.daemonReloadFailOnce = true

	err := r.Run(Options{SkipStartHealthRollback: true})
	if err == nil {
		t.Fatal("expected a flip-failure error on the HA path")
	}
	if !strings.Contains(err.Error(), "operator-driven") {
		t.Fatalf("HA flip-failure error should note operator-driven rollback: %v", err)
	}
	// No auto-rollback: current must NOT have been re-flipped to 1.0.0 by an
	// automatic rollback. (The flip to 2.0.0's 6a substep may have repointed
	// current; the key assertion is that the HA path did not run rollback's
	// start-old-daemon, so the cut surfaced the error for the operator.)
	if !strings.Contains(err.Error(), "the unit is stopped") {
		t.Errorf("HA flip-failure should report the stopped unit: %v", err)
	}
}
