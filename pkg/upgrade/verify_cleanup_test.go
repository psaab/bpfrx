package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyFailCleanup_RecopiesOnRetry proves the #1967 verify-fail cleanup:
// a cut that fails VERIFY removes versions/<ver> AND rewinds the journal so a
// same-version retry recopies the (corrected) staged tree and re-verifies it
// — rather than skipping the copy (copyStaged short-circuits when the dir
// exists) and re-verifying the stale failing copy forever.
func TestVerifyFailCleanup_RecopiesOnRetry(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	fs.verifyPass = false // first attempt: verifier rejects.
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0") // seeded host => reaches VERIFY.

	if err := r.Run(Options{}); err == nil {
		t.Fatal("expected verify reject on first run")
	}

	// The copied version dir must be GONE (cleanup ran).
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	if _, err := os.Stat(verDir); !os.IsNotExist(err) {
		t.Fatalf("versions/2.0.0 not removed after verify failure: stat err=%v", err)
	}
	// The journal must be rewound below StateCopied so the retry recopies.
	j, err := r.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State.atLeast(StateCopied) {
		t.Fatalf("journal at %s after verify-fail cleanup; want < COPIED so retry recopies", j.State)
	}

	// Operator drops a CORRECTED staged binary under the SAME version and the
	// verifier now passes. The retry must recopy and complete the cut.
	fs.verifyPass = true
	// Mark staged content as "corrected" so we can confirm the version dir was
	// recopied from the fresh staged bytes (not a leftover).
	writeFakeBin(t, filepath.Join(cfg.StagedDir, "xpfd"), "binary-xpfd-corrected")

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("retry after corrected staged should succeed: %v", err)
	}
	got, rerr := os.ReadFile(filepath.Join(verDir, "xpfd"))
	if rerr != nil {
		t.Fatalf("versions/2.0.0/xpfd missing after successful retry: %v", rerr)
	}
	if string(got) != "binary-xpfd-corrected" {
		t.Errorf("version dir not recopied from corrected staged: got %q", string(got))
	}
	// current must now point at 2.0.0 (the cut committed).
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "2.0.0" {
		t.Errorf("current = %q after retry, want 2.0.0", cur)
	}
}

// TestVerifyFailCleanup_NeverDeletesActiveVersion proves guard (a): when the
// TargetVersion equals the live `current` version (a degenerate same-version
// re-stage), a verify failure must NOT delete the running daemon's version
// dir. The journal still rewinds so a retry re-enters cleanly.
func TestVerifyFailCleanup_NeverDeletesActiveVersion(t *testing.T) {
	// Staged version == the seeded current version (2.0.0): a re-stage of the
	// already-running version that fails verify.
	fs := newFakeSystem(t, "2.0.0")
	fs.verifyPass = false
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "2.0.0") // current == target == 2.0.0.

	if err := r.Run(Options{}); err == nil {
		t.Fatal("expected verify reject")
	}

	// The ACTIVE version dir (== current) must SURVIVE — deleting it would
	// destroy the running daemon's binaries.
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	if _, err := os.Stat(verDir); err != nil {
		t.Fatalf("active version dir versions/2.0.0 deleted on same-version verify-fail: %v", err)
	}
	if _, err := os.Stat(filepath.Join(verDir, "xpfd")); err != nil {
		t.Fatalf("active version binary deleted on same-version verify-fail: %v", err)
	}
	// current must still resolve to 2.0.0.
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "2.0.0" {
		t.Errorf("current moved off the active version: %q", cur)
	}
}

// TestVerifyFailCleanup_NeverDeletesPreviousVersion proves guard (a) for the
// rollback-target case: when TargetVersion == PreviousVersion, the version
// dir backs a recoverable daemon and must not be deleted. (Constructed via a
// hand-built journal so PreviousVersion is forced equal to the target.)
func TestVerifyFailCleanup_NeverDeletesPreviousVersion(t *testing.T) {
	fs := newFakeSystem(t, "3.0.0")
	fs.verifyPass = false
	r, cfg := testEnv(t, fs)

	// Build versions/3.0.0 as if a prior cut had copied it, current -> some
	// other version so the active-version guard does NOT fire (we exercise the
	// PreviousVersion== guard specifically).
	seedInitialCurrent(t, r, cfg, "1.0.0")
	verDir := filepath.Join(cfg.VersionsDir, "3.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-3.0.0")
	}
	// Persist a journal at COPIED with PreviousVersion forced == target so the
	// guard's TargetVersion==PreviousVersion branch is the one under test.
	j := &Journal{State: StateCopied, TargetVersion: "3.0.0", PreviousVersion: "3.0.0"}
	if err := r.saveJournal(j); err != nil {
		t.Fatal(err)
	}

	if err := r.Run(Options{}); err == nil {
		t.Fatal("expected verify reject")
	}
	if _, err := os.Stat(filepath.Join(verDir, "xpfd")); err != nil {
		t.Fatalf("version dir deleted when TargetVersion==PreviousVersion: %v", err)
	}
}

// TestPreStartVersionDirCheck_RollsBack proves the #1967 C3 diagnostic: if
// the flipped-in versions/<ver> loses its binary in the FLIP->START window,
// the cut fails fast with a clear error and auto-rolls-back to the previous
// version (instead of an opaque systemd exec failure). The version dir is
// removed via the healthHook (which fires inside the post-start health probe)
// — but C3 checks BEFORE StartUnit, so we instead remove it via a resume:
// craft a journal at FLIPPED with the target dir already gone, then Run().
func TestPreStartVersionDirCheck_RollsBack(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	// Simulate a crash-resume at FLIPPED: current already points at 2.0.0 and
	// the unit drop-in is templated, BUT versions/2.0.0 has been removed by a
	// concurrent GC/disk event before START. Build that exact state.
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-2.0.0")
	}
	// DB snapshot so rollback can restore (matches a real preflight).
	j := &Journal{
		State:              StateFlipped,
		TargetVersion:      "2.0.0",
		PreviousVersion:    "1.0.0",
		AdvancedStateFloor: false,
	}
	// Point current at the target as flip would have.
	if err := r.flip("2.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	// Now the GC/disk event: remove the target's binary.
	if err := os.RemoveAll(verDir); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected the cut to fail when versions/2.0.0 vanished pre-START")
	}
	// The error must name the concrete missing-binary cause (C3 diagnostic)
	// or the rollback it triggered.
	if !strings.Contains(err.Error(), "incomplete before") && !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("error not a clear pre-start/rollback diagnostic: %v", err)
	}
	// Auto-rollback must have re-flipped current back to 1.0.0.
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "1.0.0" {
		t.Errorf("current = %q after pre-start failure, want rollback to 1.0.0", cur)
	}
}

// TestRemoveAllPartials_FsyncsAfterSweep proves #1967 C4: removeAllPartials
// fsyncs VersionsDir after removing a stray .partial, so the unlink cannot be
// resurrected by a crash before the next parent fsync. It also proves the
// no-partials path does NOT fsync (the gate avoids needless work).
func TestRemoveAllPartials_FsyncsAfterSweep(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Install a recorder for the C4 fsync seam.
	orig := partialSweepSyncDir
	t.Cleanup(func() { partialSweepSyncDir = orig })
	var synced []string
	partialSweepSyncDir = func(dir string) error {
		synced = append(synced, dir)
		return orig(dir)
	}

	// No partials present: sweep must NOT fsync.
	r.removeAllPartials()
	if len(synced) != 0 {
		t.Fatalf("fsync fired with no partials to sweep: %v", synced)
	}

	// Drop a stray .partial dir, then sweep: fsync MUST fire on VersionsDir
	// and the partial must be gone.
	partial := r.partialDir("2.0.0")
	if err := os.MkdirAll(partial, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "x"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.removeAllPartials()
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("stray partial not swept: stat err=%v", err)
	}
	if len(synced) != 1 || synced[0] != cfg.VersionsDir {
		t.Fatalf("expected one fsync of VersionsDir after sweep, got %v", synced)
	}
}
