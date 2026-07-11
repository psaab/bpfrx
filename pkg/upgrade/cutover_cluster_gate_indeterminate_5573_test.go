package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// injectStatNodeID points the ClusterNodeIDPresent stat seam at a fake that
// returns err for wantPath and delegates to the real os.Stat for everything
// else, restoring the production seam on cleanup. A package var (not a
// mode-000 dir) is the only reliable way to reproduce a NON-ENOENT marker
// lookup failure: the CI test uid is root, and root bypasses DAC — a mode-000
// directory would still stat successfully and never exercise the #5573
// fail-closed path.
func injectStatNodeID(t *testing.T, wantPath string, err error) {
	t.Helper()
	prev := statNodeID
	statNodeID = func(path string) (os.FileInfo, error) {
		if path == wantPath {
			return nil, err
		}
		return prev(path)
	}
	t.Cleanup(func() { statNodeID = prev })
}

// TestClusterNodeIDPresent_TriState pins the #5573 classification contract of
// the exported predicate directly:
//   - a present marker  -> (true,  nil)  [clustered]
//   - ENOENT            -> (false, nil)  [genuinely standalone, proceed]
//   - any other error   -> (false, err)  [indeterminate, caller must fail closed]
//
// RED-on-revert: restore the pre-fix body (`return err == nil, nil`) and the
// EACCES/EIO/ESTALE sub-cases flip to (false,nil) — i.e. "standalone" — so the
// wantErr assertions trip.
func TestClusterNodeIDPresent_TriState(t *testing.T) {
	// Present marker: real file on disk -> clustered.
	dir := t.TempDir()
	present := filepath.Join(dir, "node-id")
	if err := os.WriteFile(present, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := ClusterNodeIDPresent(present); !ok || err != nil {
		t.Fatalf("present marker: got (%v,%v), want (true,nil)", ok, err)
	}

	// ENOENT: genuinely standalone -> proceed, no error.
	absent := filepath.Join(dir, "does-not-exist")
	if ok, err := ClusterNodeIDPresent(absent); ok || err != nil {
		t.Fatalf("ENOENT marker: got (%v,%v), want (false,nil)", ok, err)
	}

	// Non-ENOENT stat failures: indeterminate -> propagate the error so the
	// caller fails closed. Cover the concrete errnos the issue calls out.
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EIO, syscall.ESTALE} {
		injectStatNodeID(t, present, &os.PathError{Op: "stat", Path: present, Err: errno})
		ok, err := ClusterNodeIDPresent(present)
		if ok {
			t.Errorf("%v: marker reported present despite an unreadable stat", errno)
		}
		if err == nil {
			t.Errorf("%v: indeterminate lookup must propagate an error, got nil (fail-OPEN)", errno)
		}
		// os.IsNotExist must NOT be true for these — that is the whole point.
		if os.IsNotExist(err) {
			t.Errorf("%v: classified as not-exist; only ENOENT may collapse to standalone", errno)
		}
	}
}

// TestClusterGate_IndeterminateMembershipFailsClosed is the #5573 core
// invariant at the FINAL privileged boundary: when the cluster-identity marker
// lookup fails with a NON-ENOENT error (EACCES/EIO/ESTALE/LSM/mount fault),
// a BARE standalone cut (r.Run with no ClusterCoordinated flag) is REFUSED
// BEFORE StopUnit — the daemon is never stopped, so an HA node whose marker is
// transiently unreadable cannot be blackholed by an uncoordinated cut.
//
// RED-on-revert: change ClusterNodeIDPresent back to swallow errors
// (`return err == nil, nil`) and the injected EACCES classifies as
// "standalone, absent" -> the bare cut proceeds to StopUnit and completes
// (current -> 2.0.0), tripping the "no live mutation" and "unit still running"
// assertions.
func TestClusterGate_IndeterminateMembershipFailsClosed(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0") // real rollback target => not the no-prev guard

	// The marker lookup itself fails with a permission error (NOT ENOENT):
	// HA membership is UNKNOWN, so the gate must fail closed rather than assume
	// standalone. Inject for cfg.NodeIDPath only; all other stats are real.
	injectStatNodeID(t, cfg.NodeIDPath,
		&os.PathError{Op: "stat", Path: cfg.NodeIDPath, Err: syscall.EACCES})

	err := r.Run(Options{}) // BARE cut, no ClusterCoordinated
	if err == nil {
		t.Fatal("expected the indeterminate-membership cut to be refused, got nil")
	}
	if !strings.Contains(err.Error(), "refuse-standalone-cut-indeterminate-cluster-membership") {
		t.Fatalf("error is not the #5573 indeterminate-membership gate: %v", err)
	}
	if !strings.Contains(err.Error(), "--rolling") {
		t.Fatalf("indeterminate gate must direct the operator to the rolling driver: %v", err)
	}

	// No live mutation may have happened: the gate fires BEFORE the lock,
	// journal, and any stop/start/drop-in/daemon-reload.
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" || c == "daemon-reload" {
			t.Errorf("live mutation %q happened despite the indeterminate-membership refusal", c)
		}
	}
	if !fs.unitRunning {
		t.Error("the daemon was stopped despite the indeterminate-membership refusal (fail-OPEN)")
	}
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Error("a journal was persisted despite the pre-lock indeterminate-membership refusal")
	}
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("current moved off the seeded prior version: %q", target)
	}
}

// TestClusterGate_ENOENTStandaloneStillProceeds is the no-regression companion:
// an ENOENT marker lookup (the genuinely-standalone case) must still be
// classified as "standalone, proceed" through the SAME seam the EACCES test
// injects on — so the fix narrows ONLY non-ENOENT errors, not the legitimate
// absent case. The bare cut runs to completion and stops the unit.
func TestClusterGate_ENOENTStandaloneStillProceeds(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	// Explicit ENOENT through the seam (belt-and-suspenders: testEnv already
	// points NodeIDPath at an absent path, but drive the seam so this asserts
	// the classifier, not just a happens-to-be-missing file).
	injectStatNodeID(t, cfg.NodeIDPath,
		&os.PathError{Op: "stat", Path: cfg.NodeIDPath, Err: syscall.ENOENT})

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("standalone (ENOENT) bare cut must proceed unchanged: %v", err)
	}
	sawStop := false
	for _, c := range fs.calls {
		if c == "stop" {
			sawStop = true
		}
	}
	if !sawStop {
		t.Error("standalone cut did not stop the unit — the ENOENT path regressed")
	}
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "2.0.0" {
		t.Errorf("standalone cut did not flip to 2.0.0: current=%q", target)
	}
}
