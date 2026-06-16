package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSystem is an in-memory System for state-machine tests. It records
// the call sequence and lets a test inject failures at any phase.
type fakeSystem struct {
	t *testing.T

	stagedVersion string

	// unitRunning models systemd state.
	unitRunning bool
	// dropinContent is the last drop-in written.
	dropinContent string
	// daemonReloaded counts daemon-reload calls.
	daemonReloaded int

	// free is the value FreeBytes returns.
	free uint64

	// verifyPass controls the verify-dataplane gate result.
	verifyPass bool
	verifyErr  error

	// healthErr is returned by HelperHealthy (nil = healthy).
	healthErr error
	// healthFailVersions: versions for which health fails (overrides
	// healthErr when matched).
	healthFailVersions map[string]bool
	// healthHook, if set, runs at the start of HelperHealthy (used to
	// simulate the new daemon mutating the live config DB post-start).
	healthHook func()

	// calls records the ordered call log for assertions.
	calls []string

	// failAt injects an error AFTER the named call (to simulate a crash
	// where the op succeeded but the journal write / next step did not —
	// the test drives idempotent re-runs).
	now time.Time
}

func newFakeSystem(t *testing.T, ver string) *fakeSystem {
	return &fakeSystem{
		t:                  t,
		stagedVersion:      ver,
		unitRunning:        true,
		free:               1 << 40, // 1 TiB
		verifyPass:         true,
		healthFailVersions: map[string]bool{},
		now:                time.Unix(1_700_000_000, 0),
	}
}

func (f *fakeSystem) log(s string)           { f.calls = append(f.calls, s) }
func (f *fakeSystem) StopUnit(string) error  { f.log("stop"); f.unitRunning = false; return nil }
func (f *fakeSystem) StartUnit(string) error { f.log("start"); f.unitRunning = true; return nil }
func (f *fakeSystem) DaemonReload() error    { f.log("daemon-reload"); f.daemonReloaded++; return nil }
func (f *fakeSystem) FreeBytes(string) (uint64, error) {
	return f.free, nil
}
func (f *fakeSystem) WriteUnitDropin(_, _, content string) error {
	f.log("dropin")
	f.dropinContent = content
	return nil
}
func (f *fakeSystem) VerifyDataplane(string, []string) (bool, error) {
	f.log("verify")
	return f.verifyPass, f.verifyErr
}
func (f *fakeSystem) BinaryVersion(string) (string, error) { return f.stagedVersion, nil }
func (f *fakeSystem) HelperHealthy(ver string, _ time.Duration) error {
	f.log("health:" + ver)
	if f.healthHook != nil {
		f.healthHook()
	}
	if f.healthFailVersions[ver] {
		return fmt.Errorf("health fail for %s", ver)
	}
	return f.healthErr
}
func (f *fakeSystem) Now() time.Time { return f.now }

// testEnv builds a populated staged tree + config DB and returns a Runner
// wired to the fake system.
func testEnv(t *testing.T, fs *fakeSystem) (*Runner, Config) {
	t.Helper()
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(staged, b), "binary-"+b+"-"+fs.stagedVersion)
	}
	cfgdb := filepath.Join(root, "etc", ".configdb")
	mkfile(t, filepath.Join(cfgdb, "active.json"), "#xpf-config-envelope v=1\n{}")

	cfg := Config{
		StagedDir:           staged,
		VersionsDir:         filepath.Join(root, "versions"),
		SbinDir:             filepath.Join(root, "sbin"),
		ConfigDBDir:         cfgdb,
		JournalPath:         filepath.Join(root, "versions", "upgrade.state"),
		Unit:                "xpfd",
		StartHealthDeadline: time.Second,
		Sys:                 fs,
		Logf:                func(format string, a ...any) { t.Logf("LOG "+format, a...) },
	}
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r, cfg
}

func writeFakeBin(t *testing.T, path, content string) {
	t.Helper()
	mkfile(t, path, content)
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func mkfile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRun_FullFreshCutover(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// versions/2.0.0/ exists with all bins.
	for _, b := range managedBins {
		p := filepath.Join(cfg.VersionsDir, "2.0.0", b)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
	// current -> 2.0.0
	target, err := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(target) != "2.0.0" {
		t.Errorf("current points at %q, want 2.0.0", target)
	}
	// sbin links point through current.
	for _, b := range managedBins {
		l, err := os.Readlink(filepath.Join(cfg.SbinDir, b))
		if err != nil {
			t.Errorf("sbin link %s: %v", b, err)
			continue
		}
		if !strings.Contains(l, "current") {
			t.Errorf("sbin %s -> %q, want via current", b, l)
		}
	}
	// drop-in pins the CONCRETE version path (not the symlink).
	if !strings.Contains(fs.dropinContent, filepath.Join(cfg.VersionsDir, "2.0.0", "xpfd")) {
		t.Errorf("drop-in does not pin concrete version path:\n%s", fs.dropinContent)
	}
	// STOP happened before FLIP (dropin/daemon-reload) before START.
	assertOrder(t, fs.calls, "stop", "dropin")
	assertOrder(t, fs.calls, "dropin", "start")
	assertOrder(t, fs.calls, "verify", "stop")
	// Journal cleared on success.
	if _, err := os.Stat(cfg.JournalPath); !os.IsNotExist(err) {
		t.Errorf("journal not cleared after commit")
	}
}

func TestRun_VerifyRejectLeavesLiveUntouched(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	fs.verifyPass = false
	r, cfg := testEnv(t, fs)

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected verify reject error")
	}
	if !strings.Contains(err.Error(), "REJECT") {
		t.Errorf("error not a REJECT: %v", err)
	}
	// No stop, no flip, no start.
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" {
			t.Errorf("live mutation %q happened on a verify REJECT", c)
		}
	}
	// current must not exist (never flipped).
	if _, err := os.Lstat(filepath.Join(cfg.VersionsDir, "current")); !os.IsNotExist(err) {
		t.Errorf("current symlink created despite verify reject")
	}
}

func TestRun_DiskFullAbortsPreMutation(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	fs.free = 1 // 1 byte: nowhere near enough
	r, _ := testEnv(t, fs)

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected disk-full abort")
	}
	if !strings.Contains(err.Error(), "insufficient space") {
		t.Errorf("error not a disk-full abort: %v", err)
	}
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" || c == "verify" || c == "copy" {
			t.Errorf("phase %q ran despite disk-full preflight abort", c)
		}
	}
}

func TestRun_AutoRollbackOnUnhealthyStart(t *testing.T) {
	// First cut to 1.0.0 (establishes a previous version).
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	// Now stage 2.0.0 but make it unhealthy -> must auto-rollback to 1.0.0.
	fs.stagedVersion = "2.0.0"
	writeFakeBin(t, filepath.Join(cfg.StagedDir, "xpfd"), "binary-xpfd-2.0.0")
	for _, b := range managedBins[1:] {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthFailVersions["2.0.0"] = true

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected unhealthy-start error with rollback")
	}
	if !strings.Contains(err.Error(), "rolled back to 1.0.0") {
		t.Errorf("error does not report rollback: %v", err)
	}
	// current must be back at 1.0.0.
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("after rollback current=%q want 1.0.0", target)
	}
	// drop-in must pin 1.0.0 again.
	if !strings.Contains(fs.dropinContent, filepath.Join(cfg.VersionsDir, "1.0.0", "xpfd")) {
		t.Errorf("drop-in not re-pinned to 1.0.0 after rollback:\n%s", fs.dropinContent)
	}
}

// TestRun_RollbackRestoresDBBeforeReflip proves the binary+DB-atomic
// rollback restores the pre-upgrade config-DB snapshot (so an old binary
// never boots against a too-new envelope DB and fatal-rejects it). It
// mutates the live DB to simulate the N+1 daemon writing a new-format
// active.json, then asserts rollback restores the PRE-upgrade content.
func TestRun_RollbackRestoresDBBeforeReflip(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	// Record the pre-upgrade DB content (what PREFLIGHT will snapshot).
	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	preContent := "#xpf-config-envelope v=1\n{}"
	mkfile(t, dbFile, preContent)

	// Stage 2.0.0, unhealthy. The cut's PREFLIGHT snapshots preContent.
	fs.stagedVersion = "2.0.0"
	writeFakeBin(t, filepath.Join(cfg.StagedDir, "xpfd"), "binary-xpfd-2.0.0")
	for _, b := range managedBins[1:] {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthFailVersions["2.0.0"] = true

	// Hook: corrupt the live DB to a too-new format AFTER the snapshot is
	// taken but before rollback. We approximate the N+1 daemon's write by
	// overwriting the live DB right after Run starts; simplest is to make
	// StartUnit (called post-flip, before the failing health check) mutate
	// the DB. We can't inject into the fake easily, so overwrite here is
	// done via a custom health probe that writes the new-format DB then
	// fails.
	newFormatContent := "#xpf-config-envelope v=1 min-reader=99\n{}"
	fs.healthHook = func() {
		mkfile(t, dbFile, newFormatContent)
	}

	_ = r.Run(Options{})

	// After rollback, the DB must be restored to the PRE-upgrade content,
	// not the too-new N+1 content.
	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != preContent {
		t.Errorf("DB not restored to pre-upgrade content after rollback.\n got=%q\nwant=%q", got, preContent)
	}
}

func TestRun_CrashResumeIdempotent(t *testing.T) {
	// Drive the full flow once to get a reference final state.
	fsRef := newFakeSystem(t, "3.0.0")
	rRef, cfgRef := testEnv(t, fsRef)
	if err := rRef.Run(Options{}); err != nil {
		t.Fatalf("reference run: %v", err)
	}
	refTarget, _ := os.Readlink(filepath.Join(cfgRef.VersionsDir, "current"))

	// Now simulate a crash AFTER each journaled state by truncating the
	// journal to that state and re-running; assert idempotent completion.
	for _, crashAfter := range []State{StateStaged, StatePreflight, StateCopied, StateVerified, StateStopped, StateFlipped} {
		t.Run(string(crashAfter), func(t *testing.T) {
			fs := newFakeSystem(t, "3.0.0")
			r, cfg := testEnv(t, fs)

			// Run a partial flow by intercepting: we can't easily stop
			// mid-Run, so instead we craft a journal at crashAfter and the
			// matching on-disk side effects, then re-run.
			seedCrashState(t, r, cfg, fs, crashAfter)

			if err := r.Run(Options{}); err != nil {
				t.Fatalf("resume from %s: %v", crashAfter, err)
			}
			target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
			if filepath.Base(target) != "3.0.0" {
				t.Errorf("resume from %s: current=%q want 3.0.0", crashAfter, target)
			}
			if filepath.Base(refTarget) != "3.0.0" {
				t.Fatalf("reference target unexpected: %q", refTarget)
			}
			// No orphan partials.
			ents, _ := os.ReadDir(cfg.VersionsDir)
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), partialSuffix) {
					t.Errorf("orphan partial after resume from %s: %s", crashAfter, e.Name())
				}
			}
		})
	}
}

// seedCrashState performs the phases up to and including crashAfter, then
// leaves the journal at that state (simulating a crash before the NEXT
// phase). It reuses the Runner's own phase methods so the on-disk state is
// authentic.
func seedCrashState(t *testing.T, r *Runner, cfg Config, fs *fakeSystem, crashAfter State) {
	t.Helper()
	j := &Journal{State: StateInit, TargetVersion: fs.stagedVersion}
	prev, _ := r.readCurrentVersion()
	j.PreviousVersion = prev
	j.StartedAtUnixNano = fs.Now().UnixNano()
	must(t, r.transition(j, StateStaged))
	if crashAfter.atLeast(StatePreflight) {
		must(t, r.preflight(j))
		must(t, r.transition(j, StatePreflight))
	}
	if crashAfter.atLeast(StateCopied) {
		must(t, r.copyStaged(j))
		must(t, r.transition(j, StateCopied))
	}
	if crashAfter.atLeast(StateVerified) {
		must(t, r.verify(j))
		must(t, r.transition(j, StateVerified))
	}
	if crashAfter.atLeast(StateStopped) {
		must(t, fs.StopUnit(cfg.Unit))
		must(t, r.transition(j, StateStopped))
	}
	if crashAfter.atLeast(StateFlipped) {
		must(t, r.flip(j.TargetVersion))
		must(t, r.transition(j, StateFlipped))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func assertOrder(t *testing.T, calls []string, before, after string) {
	t.Helper()
	bi, ai := -1, -1
	for i, c := range calls {
		if c == before && bi == -1 {
			bi = i
		}
		if c == after {
			ai = i
		}
	}
	if bi == -1 {
		t.Errorf("call %q never happened (calls=%v)", before, calls)
		return
	}
	if ai == -1 {
		t.Errorf("call %q never happened (calls=%v)", after, calls)
		return
	}
	if bi >= ai {
		t.Errorf("%q (idx %d) did not happen before %q (idx %d); calls=%v", before, bi, after, ai, calls)
	}
}
