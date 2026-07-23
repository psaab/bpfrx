package upgrade

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func currentLinkPath(cfg Config) string {
	return filepath.Join(cfg.VersionsDir, currentLink)
}

// TestRestorableCurrentTarget_Cases is the #6374 unit matrix for
// restorableCurrentTarget, which returns (ver, present). It must DISTINGUISH a
// genuinely ABSENT `current` (present==false — a legitimate first install,
// sanctionable) from every PRESENT-but-unrestorable layout (present==true —
// there IS a broken rollback target, NEVER sanctionable). ver is nonempty only
// for a fully restorable target (bare in-tree segment, existing dir, complete
// lockstep set).
//
// FAIL-ON-REVERT: collapse the present/absent distinction (e.g. return the raw
// readCurrentVersion basename, or present:=false everywhere) and the
// dangling/pathful/incomplete/non-directory/non-symlink/EACCES subtests get the
// wrong ver or present -> clean ASSERTION RED.
func TestRestorableCurrentTarget_Cases(t *testing.T) {
	t.Run("absent-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, _ := testEnv(t, fs)
		ver, present := r.restorableCurrentTarget()
		if ver != "" || present {
			t.Fatalf("absent current: got (%q,present=%v), want (\"\",false)", ver, present)
		}
	})

	t.Run("valid-complete-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		writeCompleteVersionDir(t, cfg, "1.0.0")
		if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "1.0.0" || !present {
			t.Fatalf("valid current: got (%q,present=%v), want (\"1.0.0\",true)", ver, present)
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
		if err := os.Symlink("9.9.9", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "" {
			t.Fatalf("dangling current wrongly accepted as restorable target %q "+
				"(#6374: a broken `current` must resolve to no rollback target)", ver)
		}
		if !present {
			t.Fatal("dangling current wrongly classified as ABSENT (sanctionable) — a " +
				"present-but-broken `current` must report present=true (#6374)")
		}
	})

	t.Run("pathful-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		// A complete dir exists at 1.0.0, but the link target carries path
		// components — filepath.Base would strip them to a segment the link
		// never actually named. Must be rejected as not-in-tree, present=true.
		writeCompleteVersionDir(t, cfg, "1.0.0")
		if err := os.Symlink("../versions/1.0.0", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "" {
			t.Fatalf("pathful current wrongly accepted as restorable target %q", ver)
		}
		if !present {
			t.Fatal("pathful current wrongly classified as ABSENT (sanctionable)")
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
		if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "" {
			t.Fatalf("lockstep-incomplete current wrongly accepted as restorable target %q", ver)
		}
		if !present {
			t.Fatal("lockstep-incomplete current wrongly classified as ABSENT (sanctionable)")
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
		if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "" {
			t.Fatalf("non-directory target wrongly accepted as restorable %q", ver)
		}
		if !present {
			t.Fatal("non-directory target wrongly classified as ABSENT (sanctionable)")
		}
	})

	t.Run("non-symlink-current", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		// `current` exists but is a regular file (a corrupt/interrupted repair
		// left a file where the symlink should be). os.Readlink returns EINVAL;
		// it must resolve to (ver=="", present==true), not absent.
		if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		mkfile(t, currentLinkPath(cfg), "not-a-symlink")
		ver, present := r.restorableCurrentTarget()
		if ver != "" {
			t.Fatalf("non-symlink current wrongly accepted as restorable %q", ver)
		}
		if !present {
			t.Fatal("non-symlink current wrongly classified as ABSENT (sanctionable) — a " +
				"present regular file where the symlink should be is not a first install (#6374)")
		}
	})

	t.Run("non-enoent-stat-error", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		writeCompleteVersionDir(t, cfg, "1.0.0")
		if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		// Stat of the version dir returns EACCES (indeterminate I/O) — NOT
		// os.IsNotExist. It must fail closed as present (never treated as an
		// absent, sanctionable first install).
		orig := statVersionDir
		defer func() { statVersionDir = orig }()
		statVersionDir = func(p string) (os.FileInfo, error) {
			if filepath.Base(p) == "1.0.0" {
				return nil, &os.PathError{Op: "stat", Path: p, Err: syscall.EACCES}
			}
			return orig(p)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "" {
			t.Fatalf("EACCES version dir wrongly accepted as restorable %q", ver)
		}
		if !present {
			t.Fatal("EACCES on the version dir wrongly classified as ABSENT (sanctionable) " +
				"— an indeterminate I/O error on the rollback target must fail closed as " +
				"present (#6374)")
		}
	})
}

// firstLockstepBinPath returns versions/<ver>/<first lockstep binary>, skipping
// the test if the manifest declares no lockstep binaries.
func firstLockstepBinPath(t *testing.T, cfg Config, ver string) string {
	t.Helper()
	lock := manifest.LockstepNames()
	if len(lock) == 0 {
		t.Skip("no lockstep binaries in manifest")
	}
	return filepath.Join(cfg.VersionsDir, ver, lock[0])
}

// TestRestorableCurrentTarget_LockstepFileTypes is the #6374 round-4 matrix:
// "restorable" must mean SYSTEMD-STARTABLE, not merely "the path stats OK". The
// flip drop-in execs the literal versions/<ver>/xpfd path, so a lockstep binary
// that is a directory / FIFO / symlink / non-executable file is NOT a startable
// rollback target — validateRestorableVersion must reject it, and
// restorableCurrentTarget must report it as present-but-broken (ver=="",
// present==true) so it refuses under any sanction, exactly like a dangling
// current.
//
// FAIL-ON-REVERT: revert the mode/type check to stat-only and the
// non-exec/directory/fifo/symlink subtests get a nonempty ver -> clean
// ASSERTION RED.
func TestRestorableCurrentTarget_LockstepFileTypes(t *testing.T) {
	check := func(t *testing.T, why string, mutate func(t *testing.T, binPath string)) {
		t.Helper()
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		writeCompleteVersionDir(t, cfg, "1.0.0")
		mutate(t, firstLockstepBinPath(t, cfg, "1.0.0"))
		if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "" {
			t.Fatalf("%s: lockstep binary wrongly accepted as restorable target %q "+
				"(#6374: the flip drop-in execs the literal path — it must be a "+
				"regular executable file)", why, ver)
		}
		if !present {
			t.Fatalf("%s: wrongly classified as ABSENT (sanctionable)", why)
		}
	}

	t.Run("non-executable", func(t *testing.T) {
		check(t, "non-executable lockstep binary", func(t *testing.T, bp string) {
			if err := os.Chmod(bp, 0o644); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("directory", func(t *testing.T) {
		check(t, "lockstep binary is a directory", func(t *testing.T, bp string) {
			if err := os.Remove(bp); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(bp, 0o755); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("fifo", func(t *testing.T) {
		check(t, "lockstep binary is a FIFO", func(t *testing.T, bp string) {
			if err := os.Remove(bp); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(bp, 0o755); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("socket", func(t *testing.T) {
		check(t, "lockstep binary is a socket", func(t *testing.T, bp string) {
			if err := os.Remove(bp); err != nil {
				t.Fatal(err)
			}
			l, lerr := net.Listen("unix", bp)
			if lerr != nil {
				// A unix socket path over the sun_path limit (long TMPDIR) — the
				// type check is exercised by the other cases; skip rather than
				// misreport.
				t.Skipf("cannot create a unix socket at %s (len %d): %v", bp, len(bp), lerr)
			}
			// Leave the socket file in place (default Close would unlink it).
			if ul, ok := l.(*net.UnixListener); ok {
				ul.SetUnlinkOnClose(false)
			}
			if cerr := l.Close(); cerr != nil {
				t.Fatal(cerr)
			}
		})
	})
	t.Run("symlink", func(t *testing.T) {
		check(t, "lockstep binary is a symlink", func(t *testing.T, bp string) {
			if err := os.Remove(bp); err != nil {
				t.Fatal(err)
			}
			// Point the symlink at a REAL regular executable so os.Stat would
			// FOLLOW it and (wrongly) accept — only Lstat rejecting the symlink
			// itself makes this refuse. A managed runtime is a real copied file;
			// a symlink at this path is corruption/tampering, not a valid
			// startable target (and keeps the fail-on-revert discriminating).
			realTarget := bp + ".real"
			writeFakeBin(t, realTarget, "real-executable")
			if err := os.Symlink(realTarget, bp); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("valid-regular-executable-proceeds", func(t *testing.T) {
		// Control: an untouched complete dir (regular + executable via
		// writeFakeBin's 0755) IS restorable.
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		writeCompleteVersionDir(t, cfg, "1.0.0")
		if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "1.0.0" || !present {
			t.Fatalf("valid regular+executable current: got (%q,present=%v), want (\"1.0.0\",true)", ver, present)
		}
	})
}

// assertNoLiveMutation fails if the cut ran any live-mutating step or stopped
// the daemon — the whole point of a refuse-before-STOP.
func assertNoLiveMutation(t *testing.T, fs *fakeSystem, why string) {
	t.Helper()
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" {
			t.Errorf("live mutation %q happened despite %s", c, why)
		}
	}
	if !fs.unitRunning {
		t.Errorf("daemon stopped despite %s", why)
	}
}

// TestRun_DanglingCurrentRefusesBeforeStop is the #6374 headline regression on
// the UNSANCTIONED path: a nonempty but DANGLING `current` symlink (target dir
// missing) is treated as NO restorable rollback target — the cut is refused
// BEFORE StopUnit, so the running daemon is never stopped into an unrestorable
// rollback.
func TestRun_DanglingCurrentRefusesBeforeStop(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{}) // NOT sanctioned
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a dangling current, got nil")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	assertNoLiveMutation(t, fs, "a dangling rollback target")
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Error("a journal was persisted on the dangling-current refusal")
	}
	tgt, _ := os.Readlink(currentLinkPath(cfg))
	if filepath.Base(tgt) != "1.0.0" {
		t.Errorf("current changed from the dangling 1.0.0: %q", tgt)
	}
}

// TestRun_DanglingCurrentRefusesEvenWhenSanctioned is the Codex round-2 safety
// case: AllowNoRollbackFirstCut sanctions ONLY a genuinely-absent `current` (a
// real first install). A PRESENT-but-dangling `current` still had a rollback
// target that is now broken — stopping the daemon would strand it — so the cut
// must REFUSE before STOP even with the sanction. Pre-fold the sanction wrongly
// bypassed the refusal because restorableCurrentTarget could not tell "absent"
// from "present-but-broken".
//
// FAIL-ON-REVERT: gate the sanction on restorablePrev=="" instead of on
// !present -> a sanctioned dangling cut proceeds to STOP -> the no-live-mutation
// assertions go RED.
func TestRun_DanglingCurrentRefusesEvenWhenSanctioned(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Present but dangling: symlink -> 1.0.0, versions/1.0.0 never created.
	if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{AllowNoRollbackFirstCut: true}) // SANCTIONED
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a sanctioned cut over a PRESENT-but-" +
			"dangling current, got nil")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	assertNoLiveMutation(t, fs, "a present-but-dangling rollback target (sanction must not bypass)")
	// No journal + no FirstCutSanctioned persisted (the sanction never applied).
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Error("a journal was persisted despite refusing a present-but-dangling current")
	}
}

// TestRun_AbsentCurrentSanctionedProceeds is the contrast case: the sanction
// STILL works where it should — a GENUINELY ABSENT `current` + the operator
// flag is a legitimate first install and must PROCEED through STOP to a
// completed cut. This guards the fix from over-refusing (a fail-closed change
// that also broke first install would be a regression).
//
// FAIL-ON-REVERT: make restorableCurrentTarget report present=true for an
// absent current (or refuse regardless of present) -> the first install can no
// longer be sanctioned -> this cut is wrongly refused -> RED.
func TestRun_AbsentCurrentSanctionedProceeds(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	// No `current` at all — the genuine first-install layout.

	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("genuinely-absent current + sanction must complete a first cut: %v", err)
	}
	sawStop := false
	for _, c := range fs.calls {
		if c == "stop" {
			sawStop = true
		}
	}
	if !sawStop {
		t.Error("sanctioned first install did not STOP/cut — the sanction was wrongly refused")
	}
	tgt, _ := os.Readlink(currentLinkPath(cfg))
	if filepath.Base(tgt) != "2.0.0" {
		t.Errorf("sanctioned first cut did not flip current to 2.0.0: %q", tgt)
	}
}

// TestRun_ResumedJournalRevalidatesPreviousVersion proves the #6374 pre-STOP
// revalidation on the UNSANCTIONED resume path: a resumed journal whose
// PreviousVersion names a now-missing runtime dir is refused BEFORE STOP.
func TestRun_ResumedJournalRevalidatesPreviousVersion(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, "2.0.0") // target complete; only prev is broken
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
	assertNoLiveMutation(t, fs, "an unrestorable persisted rollback target")
}

// TestRun_ResumedJournalRefusesBrokenPreviousEvenSanctioned is the Codex
// round-2 resumed-gate variant: a resumed journal that RECORDED a rollback
// target (PreviousVersion != "") which is now broken must refuse before STOP
// REGARDLESS of a first-cut sanction. The sanction covers only a recorded-EMPTY
// target (a genuinely-absent first install), never a recorded-but-broken one.
//
// FAIL-ON-REVERT: fold the recorded-nonempty-broken case back under the shared
// `!sanctioned` gate -> FirstCutSanctioned bypasses the refusal -> the resume
// proceeds to STOP -> RED.
func TestRun_ResumedJournalRefusesBrokenPreviousEvenSanctioned(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, "2.0.0")
	j := &Journal{
		State:              StateVerified,
		TargetVersion:      "2.0.0",
		PreviousVersion:    "1.0.0", // recorded a target; its dir is now MISSING
		FirstCutSanctioned: true,    // and the cut was sanctioned
	}
	must(t, r.saveJournal(j))

	// Sanctioned via BOTH the persisted flag and the invocation flag.
	err := r.Run(Options{AllowNoRollbackFirstCut: true})
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a resumed journal with a recorded-but-" +
			"broken PreviousVersion, even when sanctioned")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	assertNoLiveMutation(t, fs, "a recorded-but-broken rollback target (sanction must not bypass)")
}

// TestRun_ResumedEmptyPreviousDanglingCurrentRefusesPersistedSanction is the
// Codex round-3 residual: the RESUMED empty-previous path must ALSO re-check
// `current` at resume time. A resumed journal with PreviousVersion=="" and a
// PERSISTED FirstCutSanctioned=true (e.g. a poisoned pre-#6374 journal whose
// over-broad sanction was set for a present-but-corrupt current, carried across
// a deploy) reaches the pre-STOP guard; if `current` is present-but-dangling
// NOW, the cut must REFUSE before STOP regardless of that persisted sanction —
// otherwise it STOPs into a box with a broken prior runtime and no recorded
// rollback target (the exact #6374 hazard).
//
// FAIL-ON-REVERT: drop the resume-time `current` re-check (revert to
// refuseNoTarget = !sanctioned) -> the persisted sanction waves the dangling
// resume through to STOP -> the no-live-mutation assertions go RED.
func TestRun_ResumedEmptyPreviousDanglingCurrentRefusesPersistedSanction(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, "2.0.0") // target complete; only `current` is broken
	// Present-but-dangling current: symlink -> 1.0.0, versions/1.0.0 missing.
	if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}
	j := &Journal{
		State:              StateVerified,
		TargetVersion:      "2.0.0",
		PreviousVersion:    "",   // recorded EMPTY (first-cut-shaped)...
		FirstCutSanctioned: true, // ...and the journal claims a first-cut sanction
	}
	must(t, r.saveJournal(j))

	err := r.Run(Options{}) // no invocation flag; only the persisted sanction
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a resumed empty-previous journal whose " +
			"`current` is present-but-dangling, despite the persisted sanction")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	assertNoLiveMutation(t, fs, "a resumed empty-previous cut over a present-but-dangling "+
		"current (persisted sanction must not bypass)")
}

// TestRun_ResumedEmptyPreviousDanglingCurrentRefusesInvocationSanction is the
// invocation-flag variant: the same resumed empty-previous journal, sanctioned
// by THIS invocation's AllowNoRollbackFirstCut, must still refuse when `current`
// is present-but-dangling at resume.
func TestRun_ResumedEmptyPreviousDanglingCurrentRefusesInvocationSanction(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, "2.0.0")
	if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}
	j := &Journal{
		State:           StateVerified,
		TargetVersion:   "2.0.0",
		PreviousVersion: "", // recorded empty, NO persisted sanction
	}
	must(t, r.saveJournal(j))

	err := r.Run(Options{AllowNoRollbackFirstCut: true}) // invocation sanction
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a resumed empty-previous journal whose " +
			"`current` is present-but-dangling, despite the invocation sanction")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	assertNoLiveMutation(t, fs, "a resumed empty-previous cut over a present-but-dangling "+
		"current (invocation sanction must not bypass)")
}

// TestRun_ResumedEmptyPreviousAbsentCurrentSanctionedProceeds is the round-3
// contrast control: the resume-time re-check must NOT over-refuse. A genuinely
// ABSENT `current` (a real first install resuming past VERIFY) + a sanction
// must still PROCEED through STOP to a completed cut. Guards against a
// fail-closed change that also breaks the legit first-cut resume (Codex's
// literal `|| prevPresent` form would have broken the post-flip variant; this
// keys on present-AND-unrestorable, so a genuinely-absent current proceeds).
//
// FAIL-ON-REVERT: gate the resume on `curPresent` instead of
// `curPresent && curVer==""` (or refuse all empty-previous) -> this legit
// first-cut resume is wrongly refused -> RED.
func TestRun_ResumedEmptyPreviousAbsentCurrentSanctionedProceeds(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	// Drive a sanctioned first cut through VERIFY via real transitions (sets
	// SourceGeneration etc.), leaving `current` genuinely absent (no flip yet),
	// then resume. This is the legit first-install resume.
	j := &Journal{State: StateInit, TargetVersion: "2.0.0", FirstCutSanctioned: true}
	must(t, r.transition(j, StateStaged))
	must(t, r.preflight(j))
	must(t, r.transition(j, StatePreflight))
	must(t, r.copyStaged(j))
	must(t, r.transition(j, StateCopied))
	must(t, r.verify(j))
	must(t, r.transition(j, StateVerified))

	if _, lerr := os.Lstat(currentLinkPath(cfg)); !os.IsNotExist(lerr) {
		t.Fatalf("precondition: current must be absent before the resume (lstat: %v)", lerr)
	}

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("genuinely-absent-current sanctioned first-cut resume must complete: %v", err)
	}
	sawStop := false
	for _, c := range fs.calls {
		if c == "stop" {
			sawStop = true
		}
	}
	if !sawStop {
		t.Error("the pre-STOP gate refused a genuinely-absent sanctioned first-cut resume")
	}
	tgt, _ := os.Readlink(currentLinkPath(cfg))
	if filepath.Base(tgt) != "2.0.0" {
		t.Errorf("resumed sanctioned first cut did not flip current to 2.0.0: %q", tgt)
	}
}

// TestRun_NonExecCurrentRefusesEvenWhenSanctioned is the #6374 round-4 INIT
// integration case: a `current` whose rollback runtime's lockstep binary is a
// NON-EXECUTABLE regular file is not systemd-startable, so it is a
// present-but-broken rollback target that must refuse before STOP even under a
// first-cut sanction (an executable-blind check would STOP into an unstartable
// rollback state).
//
// FAIL-ON-REVERT: revert validateRestorableVersion to stat-only -> the
// non-executable xpfd is accepted as restorable, the cut records it and reaches
// STOP -> the no-live-mutation assertions go RED.
func TestRun_NonExecCurrentRefusesEvenWhenSanctioned(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, "1.0.0")
	if err := os.Chmod(firstLockstepBinPath(t, cfg, "1.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{AllowNoRollbackFirstCut: true}) // SANCTIONED
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a current whose rollback xpfd is " +
			"non-executable, even when sanctioned")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	assertNoLiveMutation(t, fs, "a present-but-unstartable (non-executable xpfd) rollback target")
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Error("a journal was persisted despite refusing a non-executable rollback target")
	}
}

// TestRun_ResumedEmptyPreviousNonExecCurrentRefusesSanction is the round-4
// resume variant: a resumed empty-previous sanctioned journal whose `current`
// points at a runtime with a non-executable lockstep binary must refuse before
// STOP — the resume-time re-check keys on the same startable predicate.
func TestRun_ResumedEmptyPreviousNonExecCurrentRefusesSanction(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, "2.0.0") // target complete
	writeCompleteVersionDir(t, cfg, "1.0.0") // rollback dir, but xpfd non-exec below
	if err := os.Chmod(firstLockstepBinPath(t, cfg, "1.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}
	j := &Journal{
		State:              StateVerified,
		TargetVersion:      "2.0.0",
		PreviousVersion:    "",
		FirstCutSanctioned: true,
	}
	must(t, r.saveJournal(j))

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a resumed empty-previous cut whose " +
			"`current` rollback xpfd is non-executable, despite the sanction")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	assertNoLiveMutation(t, fs, "a resumed present-but-unstartable rollback target (sanction must not bypass)")
}

// TestRollback_RefusesUnrestorablePrevious proves the #6374 pre-rollback
// preflight: rollback() refuses when PreviousVersion's runtime is missing/
// incomplete BEFORE it stops the daemon or restores the config DB.
func TestRollback_RefusesUnrestorablePrevious(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
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
	assertNoLiveMutation(t, fs, "an unrestorable previous version at rollback")
}
