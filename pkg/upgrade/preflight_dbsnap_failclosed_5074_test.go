package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// #5074: the rollback preflight must NOT misread a transient/permission stat
// error on the config-DB dir as "DB absent". Doing so would leave
// DBSnapshotPath empty (AdvancedStateFloor=false) and let the binary cut
// proceed with NO restorable pre-upgrade DB. The preflight must branch the
// stat explicitly (nil -> snapshot; os.IsNotExist -> skip; ANY OTHER error ->
// fail closed and abort before any live mutation) and must surface dirSize
// failures on a present DB.

// newPreflightJournal builds a fresh INIT journal that drives preflight from
// the live staged/ tree (SourceGeneration empty => sourceDir == StagedDir,
// which testEnv populates).
func newPreflightJournal(fs *fakeSystem) *Journal {
	return &Journal{State: StateInit, TargetVersion: fs.stagedVersion}
}

// injectConfigDBStat overrides the preflight stat seam for the duration of the
// test and restores it on cleanup.
func injectConfigDBStat(t *testing.T, err error) {
	t.Helper()
	orig := statConfigDBDir
	statConfigDBDir = func(string) (os.FileInfo, error) {
		return nil, &os.PathError{Op: "stat", Path: "config-db", Err: err}
	}
	t.Cleanup(func() { statConfigDBDir = orig })
}

// assertNoSnapshotSideEffect proves the aborted preflight left NO cut state:
// no committed snapshot dir, no partial, and DBSnapshotPath still empty.
func assertNoSnapshotSideEffect(t *testing.T, cfg Config, j *Journal) {
	t.Helper()
	if j.DBSnapshotPath != "" {
		t.Errorf("DBSnapshotPath set after aborted preflight: %q", j.DBSnapshotPath)
	}
	if j.AdvancedStateFloor {
		t.Errorf("AdvancedStateFloor set after aborted preflight")
	}
	snapDir := filepath.Join(cfg.VersionsDir, "."+j.TargetVersion+".dbsnap")
	if _, err := os.Stat(snapDir); !os.IsNotExist(err) {
		t.Errorf("snapshot dir exists after aborted preflight: %s (err=%v)", snapDir, err)
	}
	if _, err := os.Stat(snapDir + partialSuffix); !os.IsNotExist(err) {
		t.Errorf("snapshot .partial exists after aborted preflight: %s", snapDir+partialSuffix)
	}
}

// TestPreflight_DBPresent_SnapshotTaken is the happy path: a present config DB
// is snapshotted, DBSnapshotPath is set, and AdvancedStateFloor is raised.
func TestPreflight_DBPresent_SnapshotTaken(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	j := newPreflightJournal(fs)

	if err := r.preflight(j); err != nil {
		t.Fatalf("preflight on present DB: %v", err)
	}
	if j.DBSnapshotPath == "" {
		t.Fatal("DBSnapshotPath empty despite present config DB")
	}
	if _, err := os.Stat(j.DBSnapshotPath); err != nil {
		t.Errorf("snapshot dir missing: %v", err)
	}
	if !j.AdvancedStateFloor {
		t.Errorf("AdvancedStateFloor not raised despite snapshot")
	}
	// The snapshot must carry the pre-upgrade DB content.
	snap := filepath.Join(j.DBSnapshotPath, "active.json")
	if _, err := os.Stat(snap); err != nil {
		t.Errorf("snapshot missing active.json: %v", err)
	}
	_ = cfg
}

// TestPreflight_DBAbsent_SkipsSnapshot proves a GENUINELY absent DB
// (os.IsNotExist) is the only legitimate skip: no error, no snapshot, floor
// stays down, cut may proceed.
func TestPreflight_DBAbsent_SkipsSnapshot(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	if err := os.RemoveAll(cfg.ConfigDBDir); err != nil {
		t.Fatal(err)
	}
	j := newPreflightJournal(fs)

	if err := r.preflight(j); err != nil {
		t.Fatalf("preflight on absent DB should skip, not fail: %v", err)
	}
	if j.DBSnapshotPath != "" {
		t.Errorf("DBSnapshotPath set for absent DB: %q", j.DBSnapshotPath)
	}
	if j.AdvancedStateFloor {
		t.Errorf("AdvancedStateFloor raised for absent DB")
	}
	snapDir := filepath.Join(cfg.VersionsDir, "."+j.TargetVersion+".dbsnap")
	if _, err := os.Stat(snapDir); !os.IsNotExist(err) {
		t.Errorf("snapshot dir created for absent DB: %s", snapDir)
	}
}

// TestPreflight_StatEACCES_FailsClosed proves a non-ENOENT stat error
// (EACCES) ABORTS the preflight with NO snapshot side effect — it must NOT be
// misread as "absent".
func TestPreflight_StatEACCES_FailsClosed(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	injectConfigDBStat(t, syscall.EACCES)
	j := newPreflightJournal(fs)

	err := r.preflight(j)
	if err == nil {
		t.Fatal("preflight proceeded on EACCES stat instead of failing closed")
	}
	if !strings.Contains(err.Error(), "stat config DB") {
		t.Errorf("error is not the fail-closed stat abort: %v", err)
	}
	assertNoSnapshotSideEffect(t, cfg, j)
}

// TestPreflight_StatEIO_FailsClosed proves the same for EIO (transient
// storage / stale mount).
func TestPreflight_StatEIO_FailsClosed(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	injectConfigDBStat(t, syscall.EIO)
	j := newPreflightJournal(fs)

	err := r.preflight(j)
	if err == nil {
		t.Fatal("preflight proceeded on EIO stat instead of failing closed")
	}
	if !strings.Contains(err.Error(), "stat config DB") {
		t.Errorf("error is not the fail-closed stat abort: %v", err)
	}
	assertNoSnapshotSideEffect(t, cfg, j)
}

// TestPreflight_DirSizeErrorOnPresentDB_Surfaced proves a walk/size error on a
// PRESENT config DB (an unreadable subdir) is surfaced, not silently sized as
// 0. Uses a real permission trick, so it is skipped as root (root bypasses
// the directory permission).
func TestPreflight_DirSizeErrorOnPresentDB_Surfaced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions; dirSize would not error")
	}
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	// Make a subdir unreadable/unsearchable so filepath.Walk fails INSIDE a
	// present config DB dir (the top-level stat still succeeds).
	sub := filepath.Join(cfg.ConfigDBDir, "locked")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
	j := newPreflightJournal(fs)

	err := r.preflight(j)
	if err == nil {
		t.Fatal("preflight swallowed a dirSize error on a present DB")
	}
	if !strings.Contains(err.Error(), "size config DB") {
		t.Errorf("error is not the surfaced dirSize failure: %v", err)
	}
	assertNoSnapshotSideEffect(t, cfg, j)
}

// TestRun_PreflightStatEACCES_AbortsNoCutMutation drives the FULL cut and
// proves a non-ENOENT DB stat error aborts before ANY live mutation: no stop,
// no flip drop-in, no start, no copy, no verify, and current is untouched.
func TestRun_PreflightStatEACCES_AbortsNoCutMutation(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	// Seeded host (current exists) so the cut reaches PREFLIGHT rather than
	// the no-rollback-target INIT refuse.
	seedInitialCurrent(t, r, cfg, "1.0.0")
	injectConfigDBStat(t, syscall.EACCES)

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("cut proceeded on EACCES DB stat instead of aborting")
	}
	if !strings.Contains(err.Error(), "preflight") {
		t.Errorf("abort is not a preflight failure: %v", err)
	}
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" || c == "verify" || c == "copy" {
			t.Errorf("cut-state mutation %q ran despite preflight fail-closed abort", c)
		}
	}
	// current must still point at the seeded prior version (never flipped).
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("current moved off 1.0.0 despite preflight abort: %q", target)
	}
	// No target version dir was copied in.
	if _, err := os.Stat(filepath.Join(cfg.VersionsDir, "2.0.0")); !os.IsNotExist(err) {
		t.Errorf("versions/2.0.0 created despite preflight abort")
	}
}
