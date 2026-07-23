package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade/manifest"
)

// writeCompleteVersionDir populates versions/<ver>/ with the full managed
// binary set (a complete, restorable runtime), mirroring seedInitialCurrent's
// dir setup but WITHOUT touching the `current` symlink so a test can point a
// crafted link at it.
func writeCompleteVersionDir(t *testing.T, cfg Config, ver string) {
	t.Helper()
	verDir := filepath.Join(cfg.VersionsDir, ver)
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-"+ver)
	}
}

// TestRestorableCurrentTarget_Cases is the #6374 unit matrix for
// restorableCurrentTarget: only a `current` symlink resolving to a bare,
// existing, lockstep-complete version dir is a restorable rollback target.
// Every corrupt layout (absent, dangling, pathful, non-directory target,
// lockstep-incomplete, non-symlink) MUST resolve to "" so it is never recorded
// as PreviousVersion — recording an unrestorable target lets a flip/start
// failure STOP the running daemon and strand it offline.
//
// FAIL-ON-REVERT: neutralize the fix by making restorableCurrentTarget return
// readCurrentVersion's raw basename and the dangling/pathful/incomplete/
// non-directory subtests wrongly get a nonempty target -> clean ASSERTION RED.
func TestRestorableCurrentTarget_Cases(t *testing.T) {
	linkPath := func(cfg Config) string { return filepath.Join(cfg.VersionsDir, currentLink) }

	t.Run("absent-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, _ := testEnv(t, fs)
		got, err := r.restorableCurrentTarget()
		if err != nil || got != "" {
			t.Fatalf("absent current: got (%q,%v), want (\"\",nil)", got, err)
		}
	})

	t.Run("valid-complete-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		writeCompleteVersionDir(t, cfg, "1.0.0")
		if err := os.Symlink("1.0.0", linkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		got, err := r.restorableCurrentTarget()
		if err != nil || got != "1.0.0" {
			t.Fatalf("valid current: got (%q,%v), want (\"1.0.0\",nil)", got, err)
		}
	})

	t.Run("dangling-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		// Symlink names a version whose dir does NOT exist (storage damage /
		// interrupted repair). os.Readlink succeeds; filepath.Base is nonempty.
		if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("9.9.9", linkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		got, err := r.restorableCurrentTarget()
		if err != nil {
			t.Fatalf("dangling current: unexpected error %v", err)
		}
		if got != "" {
			t.Fatalf("dangling current wrongly accepted as restorable target %q "+
				"(#6374: a broken `current` must resolve to no rollback target)", got)
		}
	})

	t.Run("pathful-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		// A complete dir exists at 1.0.0, but the link target carries path
		// components — filepath.Base would strip them to a segment the link
		// never actually named. Must be rejected as not-in-tree.
		writeCompleteVersionDir(t, cfg, "1.0.0")
		if err := os.Symlink("../versions/1.0.0", linkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		got, err := r.restorableCurrentTarget()
		if err != nil {
			t.Fatalf("pathful current: unexpected error %v", err)
		}
		if got != "" {
			t.Fatalf("pathful current wrongly accepted as restorable target %q", got)
		}
	})

	t.Run("incomplete-dir-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		lock := manifest.LockstepNames()
		if len(lock) == 0 {
			t.Skip("no lockstep binaries in manifest")
		}
		// Dir exists but is missing one managed lockstep binary => incomplete.
		verDir := filepath.Join(cfg.VersionsDir, "1.0.0")
		for _, b := range managedBins {
			if b == lock[0] {
				continue
			}
			writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b)
		}
		if err := os.Symlink("1.0.0", linkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		got, err := r.restorableCurrentTarget()
		if err != nil {
			t.Fatalf("incomplete current: unexpected error %v", err)
		}
		if got != "" {
			t.Fatalf("lockstep-incomplete current wrongly accepted as restorable target %q", got)
		}
	})

	t.Run("non-directory-target", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		// versions/1.0.0 is a regular file, not a directory.
		if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		mkfile(t, filepath.Join(cfg.VersionsDir, "1.0.0"), "not-a-dir")
		if err := os.Symlink("1.0.0", linkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		got, err := r.restorableCurrentTarget()
		if err != nil {
			t.Fatalf("non-dir target: unexpected error %v", err)
		}
		if got != "" {
			t.Fatalf("non-directory target wrongly accepted as restorable %q", got)
		}
	})

	t.Run("non-symlink-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		// `current` exists but is a regular file (a corrupt/interrupted repair
		// left a file where the symlink should be). os.Readlink returns EINVAL;
		// it must resolve to "" (no restorable target), not propagate an error.
		if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		mkfile(t, linkPath(cfg), "not-a-symlink")
		got, err := r.restorableCurrentTarget()
		if err != nil {
			t.Fatalf("non-symlink current: unexpected error %v", err)
		}
		if got != "" {
			t.Fatalf("non-symlink current wrongly accepted as restorable %q", got)
		}
	})
}

// TestRun_DanglingCurrentRefusesBeforeStop is the #6374 headline regression: a
// nonempty but DANGLING `current` symlink (its target dir is missing) must be
// treated as NO restorable rollback target — the cut is refused BEFORE
// StopUnit, so the running daemon is never stopped into an unrestorable
// rollback. Pre-fix, the dangling basename was recorded as PreviousVersion,
// passed every rollback guard, and a start/health failure could strand xpfd
// offline.
//
// FAIL-ON-REVERT: reverting the recording change (restorablePrev -> raw prev)
// records "1.0.0" as PreviousVersion, the refuse-at-init no longer fires, the
// cut runs to STOP -> the "no live mutation" / "unit still running" assertions
// go RED.
func TestRun_DanglingCurrentRefusesBeforeStop(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	// Seed a dangling current: symlink -> 1.0.0 but versions/1.0.0 never exists.
	if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1.0.0", filepath.Join(cfg.VersionsDir, currentLink)); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{}) // NOT sanctioned
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a dangling current, got nil")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	// The daemon must NOT have been stopped / flipped / started.
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" {
			t.Errorf("live mutation %q happened despite a dangling rollback target", c)
		}
	}
	if !fs.unitRunning {
		t.Error("daemon stopped despite an unrestorable (dangling) rollback target")
	}
	// No journal persisted: the refuse happens at INIT before any transition.
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Error("a journal was persisted on the dangling-current refusal")
	}
	// current is untouched (still the dangling 1.0.0, never re-flipped).
	tgt, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(tgt) != "1.0.0" {
		t.Errorf("current changed from the dangling 1.0.0: %q", tgt)
	}
}

// TestRun_ResumedJournalRevalidatesPreviousVersion proves the #6374 pre-STOP
// revalidation: a resumed journal whose PreviousVersion names a version whose
// runtime dir is now missing (a pre-#6374 journal that recorded a dangling
// basename, or storage damage between INIT and resume) is refused BEFORE STOP
// rather than being stopped and rolled back to a missing runtime. A nonempty
// PreviousVersion STRING is not sufficient — the dir must be restorable.
//
// FAIL-ON-REVERT: reverting the pre-STOP revalidation (guard checks only
// PreviousVersion == "") lets the resume proceed past the guard to STOP the
// running daemon -> the "no stop" / "unit still running" assertions go RED.
func TestRun_ResumedJournalRevalidatesPreviousVersion(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	// The target version dir is complete (the cut got as far as VERIFIED), so
	// the ONLY defect is that PreviousVersion's runtime has vanished.
	writeCompleteVersionDir(t, cfg, "2.0.0")
	// Hand-write a VERIFIED journal whose PreviousVersion points at a version
	// with NO dir on disk. TargetVersion matches the staged version so the
	// resume-vs-fresh recovery keeps it (a genuine resume, not a reset).
	j := &Journal{
		State:           StateVerified,
		TargetVersion:   "2.0.0",
		PreviousVersion: "1.0.0", // versions/1.0.0 does NOT exist
	}
	must(t, r.saveJournal(j))

	err := r.Run(Options{}) // unsanctioned
	if err == nil {
		t.Fatal("expected refuse-before-STOP on an unrestorable persisted PreviousVersion")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" {
			t.Errorf("live mutation %q happened despite an unrestorable persisted "+
				"rollback target", c)
		}
	}
	if !fs.unitRunning {
		t.Error("daemon stopped despite an unrestorable persisted rollback target")
	}
}

// TestRollback_RefusesUnrestorablePrevious proves the #6374 pre-rollback
// preflight: rollback() must refuse when PreviousVersion's runtime is missing/
// incomplete BEFORE it stops the daemon or restores the config DB — otherwise
// the re-flip to the missing runtime fails AFTER the DB was already rolled
// back, turning a recoverable new-version failure into a control-plane outage.
//
// FAIL-ON-REVERT: reverting the preflight lets rollback() run StopUnit (and the
// DB restore) before failing on the missing dir -> the "no stop" assertion and
// the "refuse-rollback" error-message assertion go RED.
func TestRollback_RefusesUnrestorablePrevious(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	// PreviousVersion names a version whose dir does not exist. Keep the DB
	// restore out of the picture (AdvancedStateFloor=false) so the ONLY thing
	// under test is the pre-rollback restorability preflight.
	j := &Journal{
		State:              StateStarted,
		TargetVersion:      "2.0.0",
		PreviousVersion:    "1.0.0", // versions/1.0.0 missing
		AdvancedStateFloor: false,
	}
	err := r.rollback(j)
	if err == nil {
		t.Fatal("expected rollback refusal for an unrestorable previous version")
	}
	if !strings.Contains(err.Error(), "refuse-rollback") {
		t.Fatalf("error is not the pre-rollback preflight refusal: %v", err)
	}
	// The destructive steps must NOT have run.
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" {
			t.Errorf("destructive rollback step %q ran despite an unrestorable "+
				"previous version", c)
		}
	}
	if !fs.unitRunning {
		t.Error("daemon stopped despite the pre-rollback preflight refusal")
	}
}
