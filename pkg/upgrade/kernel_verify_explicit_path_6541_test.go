package upgrade

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// #6541: the kernel promote/rollback gate must exec an EXPLICIT, version-
// resolved xpfd path — never a PATH-resolved bare "xpfd".
//
// The gate runs as root on a candidate boot and its exit status decides
// promote-vs-rollback (KernelRunner.verifyAndPromote Gate 3), so a PATH entry
// ordered ahead of the real location must not be able to author that decision,
// and a stale xpfd in some other directory must not be able to verify the wrong
// build against the candidate kernel.
//
// FAIL-ON-REVERT: revert resolveVerifyGateBin/verifyDataplaneCmd to
//
//	return exec.Command("xpfd", "verify-dataplane"), nil
//
// and TestVerifyDataplaneCmdUsesExplicitResolvedPath FAILS on the argv
// assertion (cmd.Args[0] == "xpfd", not the resolved temp path). It is an
// ASSERTION failure, not a build break: the reverted body still compiles and
// every other test in this file still runs.

// fakeXpfd writes an executable stub at dir/xpfd that exits with the given
// code and returns its path.
func fakeXpfd(t *testing.T, dir string, exitCode int) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	p := filepath.Join(dir, "xpfd")
	script := "#!/bin/sh\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// withGateSeams points the resolver's three seams at test-controlled values and
// restores them afterwards. selfPath == "" makes os.Executable report an error
// (driving the fallback chain). sbinDir is pointed at a non-existent path so a
// caller that only cares about candidates 1 and 3 gets candidate 2 out of the
// way; withGateSeamsSbin sets it explicitly.
func withGateSeams(t *testing.T, selfPath, versionsDir string) {
	t.Helper()
	withGateSeamsSbin(t, selfPath, filepath.Join(t.TempDir(), "no-such-sbin"), versionsDir)
}

// withGateSeamsSbin is withGateSeams with the managed-sbin candidate (2) set.
func withGateSeamsSbin(t *testing.T, selfPath, sbinDir, versionsDir string) {
	t.Helper()
	origExe, origSbin, origVer := osExecutable, gateSbinDir, gateVersionsDir
	t.Cleanup(func() {
		osExecutable, gateSbinDir, gateVersionsDir = origExe, origSbin, origVer
	})
	if selfPath == "" {
		osExecutable = func() (string, error) { return "", os.ErrNotExist }
	} else {
		osExecutable = func() (string, error) { return selfPath, nil }
	}
	gateSbinDir = sbinDir
	gateVersionsDir = versionsDir
}

// TestVerifyDataplaneCmdUsesExplicitResolvedPath is the core RED-on-revert: the
// gate's argv[0] must be the EXPLICIT resolved path, not a bare artifact name.
//
// Asserting on the resolved argv (not on a side effect) is what makes this
// revert-proof. Note cmd.Path alone would NOT be: exec.Command("xpfd", ...)
// runs LookPath, so on a host that happens to have xpfd on PATH the reverted
// code would still produce an ABSOLUTE cmd.Path. cmd.Args[0], by contrast, is
// always verbatim the name exec.Command was given.
func TestVerifyDataplaneCmdUsesExplicitResolvedPath(t *testing.T) {
	root := t.TempDir()
	self := fakeXpfd(t, filepath.Join(root, "versions", "v1.2.3"), 0)
	withGateSeams(t, self, filepath.Join(root, "versions"))

	sys := &realKernelSystem{}
	cmd, err := sys.verifyDataplaneCmd()
	if err != nil {
		t.Fatalf("verifyDataplaneCmd: %v", err)
	}

	if len(cmd.Args) != 2 {
		t.Fatalf("argv = %q, want exactly 2 elements", cmd.Args)
	}
	if cmd.Args[0] == verifyGateBin {
		t.Fatalf("argv[0] = %q — the gate is exec'ing a BARE, PATH-resolved "+
			"artifact name (#6541). It must be an explicit, version-resolved path.",
			cmd.Args[0])
	}
	if !filepath.IsAbs(cmd.Args[0]) {
		t.Fatalf("argv[0] = %q is not an absolute path (#6541)", cmd.Args[0])
	}
	if cmd.Args[0] != self {
		t.Fatalf("argv[0] = %q, want the resolved explicit path %q", cmd.Args[0], self)
	}
	if cmd.Args[1] != "verify-dataplane" {
		t.Fatalf("argv[1] = %q, want \"verify-dataplane\"", cmd.Args[1])
	}
	// cmd.Path must be the same explicit path — i.e. exec.Command skipped
	// LookPath entirely, which it only does for a name containing a separator.
	if cmd.Path != self {
		t.Fatalf("cmd.Path = %q, want %q (a LookPath-resolved Path means the "+
			"name handed to exec.Command was bare)", cmd.Path, self)
	}
}

// TestVerifyDataplaneRunsTheResolvedBinary proves the resolver is actually
// WIRED into the production entry point (VerifyDataplane), not merely
// reachable through the test-only helper. A stub that exits 0 must read as
// PASS and one that exits 3 as REJECT — both routed through the resolved path.
func TestVerifyDataplaneRunsTheResolvedBinary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exitCode int
		wantOK   bool
	}{
		{"pass", 0, true},
		{"reject", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			self := fakeXpfd(t, filepath.Join(root, "versions", "v9"), tc.exitCode)
			withGateSeams(t, self, filepath.Join(root, "versions"))

			ok, err := (&realKernelSystem{}).VerifyDataplane()
			if err != nil {
				t.Fatalf("VerifyDataplane: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("VerifyDataplane ok = %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

// TestResolveVerifyGateBinPrefersRunningBinary: the running xpfd is the
// primary. It is exactly the live build, needs no symlink to be intact, and on
// Linux /proc/self/exe has already resolved sbin -> versions/<ver>/xpfd.
func TestResolveVerifyGateBinPrefersRunningBinary(t *testing.T) {
	root := t.TempDir()
	self := fakeXpfd(t, filepath.Join(root, "versions", "running"), 0)
	// A DIFFERENT, also-valid candidate under versions/current — the running
	// binary must win.
	fakeXpfd(t, filepath.Join(root, "versions", "current"), 0)
	withGateSeams(t, self, filepath.Join(root, "versions"))

	got, err := resolveVerifyGateBin()
	if err != nil {
		t.Fatalf("resolveVerifyGateBin: %v", err)
	}
	if got != self {
		t.Fatalf("resolved %q, want the running binary %q", got, self)
	}
}

// TestResolveVerifyGateBinFallsBackToVersionedRuntime: when os.Executable is
// unusable (no /proc, or a deleted running binary) AND there is no managed sbin
// entry, the resolver falls back to the #1917 version-multiplexed path — still
// explicit, still never PATH.
func TestResolveVerifyGateBinFallsBackToVersionedRuntime(t *testing.T) {
	root := t.TempDir()
	versions := filepath.Join(root, "versions")
	want := fakeXpfd(t, filepath.Join(versions, "current"), 0)
	withGateSeams(t, "", versions) // os.Executable fails, no sbin entry

	got, err := resolveVerifyGateBin()
	if err != nil {
		t.Fatalf("resolveVerifyGateBin: %v", err)
	}
	if got != want {
		t.Fatalf("resolved %q, want the versioned-runtime path %q", got, want)
	}
}

// TestResolveVerifyGateBinPrefersSbinOverDefaultVersionsRoot is the
// RELOCATED-INSTALL regression guard.
//
// `--versions-dir` and `--sbin-dir` are real operator options, and flip step 6b
// repoints <SbinDir>/<bin> -> <VersionsDir>/current/<bin> on every cut
// (flip.go), so the sbin entry tracks the live version wherever the runtime
// lives. Relocating does NOT remove an older /var/lib/xpf/versions/current, so a
// resolver that consulted the hardcoded default root first would pick a STALE
// build and verify the candidate kernel against the wrong dataplane.
//
// This models exactly that: a leftover default-root runtime AND a live sbin
// entry pointing into a relocated root. The sbin entry must win.
func TestResolveVerifyGateBinPrefersSbinOverDefaultVersionsRoot(t *testing.T) {
	root := t.TempDir()

	// The leftover, STALE default runtime.
	staleDefault := fakeXpfd(t, filepath.Join(root, "default-versions", "current"), 0)

	// The LIVE relocated runtime, with the managed sbin entry pointing at it
	// the way flip 6b leaves it.
	live := fakeXpfd(t, filepath.Join(root, "relocated", "versions", "v2"), 0)
	sbinDir := filepath.Join(root, "sbin")
	if err := os.MkdirAll(sbinDir, 0o755); err != nil {
		t.Fatalf("mkdir sbin: %v", err)
	}
	sbinEntry := filepath.Join(sbinDir, verifyGateBin)
	if err := os.Symlink(live, sbinEntry); err != nil {
		t.Fatalf("symlink sbin entry: %v", err)
	}

	// os.Executable unusable, so the fallback ORDER is what decides.
	withGateSeamsSbin(t, "", sbinDir, filepath.Join(root, "default-versions"))

	got, err := resolveVerifyGateBin()
	if err != nil {
		t.Fatalf("resolveVerifyGateBin: %v", err)
	}
	if got == staleDefault {
		t.Fatalf("resolved the STALE default-root runtime %q on a relocated "+
			"install; the managed sbin entry %q tracks the live version and must "+
			"be consulted first (#6541 fold r2)", got, sbinEntry)
	}
	if got != sbinEntry {
		t.Fatalf("resolved %q, want the managed sbin entry %q", got, sbinEntry)
	}
}

// TestResolveVerifyGateBinSkipsDanglingSbinEntry: the sbin entry earns its
// priority only while it resolves. A #2176 dangling symlink (points into a
// removed versions dir) must NOT shadow the versioned-runtime fallback — that
// is the whole reason candidate 3 still exists.
func TestResolveVerifyGateBinSkipsDanglingSbinEntry(t *testing.T) {
	root := t.TempDir()
	versions := filepath.Join(root, "versions")
	want := fakeXpfd(t, filepath.Join(versions, "current"), 0)

	sbinDir := filepath.Join(root, "sbin")
	if err := os.MkdirAll(sbinDir, 0o755); err != nil {
		t.Fatalf("mkdir sbin: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "removed", "xpfd"),
		filepath.Join(sbinDir, verifyGateBin)); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	withGateSeamsSbin(t, "", sbinDir, versions)

	got, err := resolveVerifyGateBin()
	if err != nil {
		t.Fatalf("resolveVerifyGateBin: %v", err)
	}
	if got != want {
		t.Fatalf("resolved %q, want the versioned-runtime fallback %q (a dangling "+
			"sbin symlink must not shadow it)", got, want)
	}
}

// TestResolveVerifyGateBinFallsBackWhenRunningBinaryPathIsGone covers the
// SECOND way candidate (1) can be unusable, distinct from the error branch
// above: os.Executable SUCCEEDS and returns a plausible path, but that path no
// longer resolves. This is what an unlinked running binary actually looks like.
//
// Be precise about the mechanism, because the obvious guess is wrong: Readlink
// on /proc/self/exe appends " (deleted)" for an unlinked binary, but Go TRIMS
// that suffix and returns the original path with a nil error
// (src/os/executable_procfs.go). So there is no suffix to detect, and a test
// seeding a "(deleted)"-suffixed string would be feeding the resolver an input
// the real API cannot produce. The fallback is driven purely by os.Stat
// returning ENOENT — which is exactly what this seeds.
func TestResolveVerifyGateBinFallsBackWhenRunningBinaryPathIsGone(t *testing.T) {
	root := t.TempDir()
	versions := filepath.Join(root, "versions")
	want := fakeXpfd(t, filepath.Join(versions, "current"), 0)

	// A real-shaped path (versions/<ver>/xpfd) that was created and then
	// unlinked — os.Executable would still report it verbatim.
	unlinked := fakeXpfd(t, filepath.Join(versions, "v1.2.3"), 0)
	if err := os.Remove(unlinked); err != nil {
		t.Fatalf("unlink %s: %v", unlinked, err)
	}
	withGateSeams(t, unlinked, versions)

	got, err := resolveVerifyGateBin()
	if err != nil {
		t.Fatalf("resolveVerifyGateBin: %v", err)
	}
	if got != want {
		t.Fatalf("resolved %q, want %q", got, want)
	}
}

// unlinkProbeEnv puts this test file's binary into "child" mode: unlink our own
// executable and report what os.Executable() says afterwards.
const unlinkProbeEnv = "XPF_6541_UNLINK_PROBE"

// TestOsExecutableTrimsDeletedSuffix pins the toolchain behaviour that
// resolveVerifyGateBin's doc comment (and TestResolveVerifyGateBinFallsBack-
// WhenRunningBinaryPathIsGone) assert as fact: on Linux, Readlink of
// /proc/self/exe appends " (deleted)" for an unlinked binary, and Go TRIMS that
// suffix before returning (src/os/executable_procfs.go). If a future release
// stopped trimming, the resolver would still fall back correctly (the suffixed
// path stats to ENOENT) but the documented rationale would silently rot.
//
// This has to actually unlink a running binary to mean anything — asserting
// against the undeleted test binary would be a tautology. So the parent copies
// this test binary to a temp path and re-execs the copy; the child removes its
// own path and prints what os.Executable() returns.
func TestOsExecutableTrimsDeletedSuffix(t *testing.T) {
	if os.Getenv(unlinkProbeEnv) == "1" {
		self, err := os.Executable()
		if err != nil {
			fmt.Printf("PROBE-ERR executable: %v\n", err)
			return
		}
		if err := os.Remove(self); err != nil {
			fmt.Printf("PROBE-ERR unlink: %v\n", err)
			return
		}
		after, err := os.Executable()
		fmt.Printf("PROBE-RESULT %q err=%v\n", after, err)
		return
	}

	src, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable unavailable: %v", err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("cannot read test binary %s: %v", src, err)
	}
	copyPath := filepath.Join(t.TempDir(), "probe.test")
	if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		t.Skipf("cannot stage test-binary copy: %v", err)
	}

	cmd := exec.Command(copyPath, "-test.run", "^TestOsExecutableTrimsDeletedSuffix$")
	cmd.Env = append(os.Environ(), unlinkProbeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("probe child failed (%v): %s", err, out)
	}

	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "PROBE-RESULT ") || strings.HasPrefix(l, "PROBE-ERR ") {
			line = l
			break
		}
	}
	if line == "" {
		t.Skipf("probe child produced no result line: %s", out)
	}
	if strings.HasPrefix(line, "PROBE-ERR ") {
		t.Skipf("probe could not run: %s", line)
	}

	if strings.Contains(line, "(deleted)") {
		t.Fatalf("after unlinking its own binary, os.Executable() reported a "+
			"\" (deleted)\"-suffixed path: %s\n"+
			"The toolchain no longer trims the suffix. resolveVerifyGateBin's "+
			"doc comment and the ENOENT-driven fallback rationale are now wrong "+
			"and must be rewritten (the fallback itself still works).", line)
	}
	if !strings.Contains(line, strconv.Quote(copyPath)) {
		t.Fatalf("probe reported %s, want the original (untrimmed-away) path %q",
			line, copyPath)
	}
	if !strings.Contains(line, "err=<nil>") {
		t.Fatalf("probe reported %s, want a nil error — the doc comment claims "+
			"os.Executable SUCCEEDS for an unlinked binary", line)
	}
}

// TestResolveVerifyGateBinFailsClosed: with NO explicit candidate resolvable,
// the resolver must ERROR rather than fall back to PATH — even when a perfectly
// good xpfd is sitting on PATH. Falling back would reintroduce #6541 exactly.
func TestResolveVerifyGateBinFailsClosed(t *testing.T) {
	root := t.TempDir()
	// Plant an xpfd on PATH. A PATH-resolving implementation would find it.
	pathDir := filepath.Join(root, "hostile-path")
	fakeXpfd(t, pathDir, 0)
	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	withGateSeams(t, "", filepath.Join(root, "no-such-versions"))

	got, err := resolveVerifyGateBin()
	if err == nil {
		t.Fatalf("resolveVerifyGateBin returned %q with no explicit candidate; "+
			"it must fail closed, never PATH-resolve (#6541)", got)
	}
	if strings.HasPrefix(got, pathDir) {
		t.Fatalf("resolver reached into PATH and returned %q (#6541)", got)
	}
	// The error must name the class so an operator reading the revert reason in
	// the journal can tell this apart from a genuine verifier REJECT.
	if !strings.Contains(err.Error(), "#6541") {
		t.Errorf("error %q should cite the fail-closed rationale", err)
	}
}

// TestVerifyDataplaneFailsClosedOnUnresolvableBinary is the caller-visible half
// of the fail-closed contract: VerifyDataplane returns (false, err), and
// KernelRunner.verifyAndPromote (kernel_run.go Gate 3) turns a non-nil error
// into revert() — restore the known-good BootOrder and reboot to the known-good
// slot. On an A/B kernel promote that is the safe direction.
func TestVerifyDataplaneFailsClosedOnUnresolvableBinary(t *testing.T) {
	root := t.TempDir()
	pathDir := filepath.Join(root, "hostile-path")
	fakeXpfd(t, pathDir, 0) // would PASS if the gate PATH-resolved
	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	withGateSeams(t, "", filepath.Join(root, "no-such-versions"))

	ok, err := (&realKernelSystem{}).VerifyDataplane()
	if err == nil {
		t.Fatalf("VerifyDataplane returned ok=%v, nil error with no resolvable "+
			"xpfd; it must fail closed so the caller reverts (#6541)", ok)
	}
	if ok {
		t.Fatalf("VerifyDataplane reported PASS via a PATH-resolved binary (#6541)")
	}
}

// TestValidateGateBinRejectsNonExplicitTargets pins the individual rejections
// the resolver relies on — in particular a BARE name, which is precisely what
// would otherwise be handed to exec.Command and PATH-resolved.
func TestValidateGateBinRejectsNonExplicitTargets(t *testing.T) {
	root := t.TempDir()
	good := fakeXpfd(t, root, 0)

	nonExec := filepath.Join(root, "noexec")
	if err := os.WriteFile(nonExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	dir := filepath.Join(root, "adir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	for _, tc := range []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"explicit executable", good, false},
		{"bare name", verifyGateBin, true},
		{"relative path", "./xpfd", true},
		{"empty", "", true},
		{"missing", filepath.Join(root, "nope"), true},
		{"not regular", dir, true},
		{"not executable", nonExec, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGateBin(tc.path)
			if tc.wantErr && err == nil {
				t.Fatalf("validateGateBin(%q) = nil, want error", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateGateBin(%q) = %v, want nil", tc.path, err)
			}
		})
	}
}

// TestGateResolutionDefaultsToProductionVersionsDir is the OVER-REACH GUARD
// for the fallback candidate: the package default must be the real #1917
// versioned-runtime root, so a normal promote on a real appliance resolves
// through versions/current and not some test-only path. It must stay GREEN
// under revert of the #6541 fix.
func TestGateResolutionDefaultsToProductionVersionsDir(t *testing.T) {
	if gateSbinDir != DefaultSbinDir {
		t.Fatalf("gateSbinDir = %q, want DefaultSbinDir %q", gateSbinDir, DefaultSbinDir)
	}
	if gateVersionsDir != DefaultVersionsDir {
		t.Fatalf("gateVersionsDir = %q, want DefaultVersionsDir %q", gateVersionsDir, DefaultVersionsDir)
	}
	if got := filepath.Join(DefaultSbinDir, verifyGateBin); got != "/usr/local/sbin/xpfd" {
		t.Fatalf("candidate 2 = %q, want /usr/local/sbin/xpfd", got)
	}
	if got := filepath.Join(DefaultVersionsDir, currentLink, verifyGateBin); got != "/var/lib/xpf/versions/current/xpfd" {
		t.Fatalf("candidate 3 = %q, want /var/lib/xpf/versions/current/xpfd", got)
	}
}
