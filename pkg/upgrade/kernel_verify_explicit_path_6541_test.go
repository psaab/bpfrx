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

// withRunningBinary points the resolver's ONE seam — os.Executable — at a
// test-controlled value and restores it afterwards. selfPath == "" makes
// os.Executable report an error.
//
// It used to take a sbin dir and a versions dir too, because the resolver fell
// through to those configured roots. #6620 deleted both fallbacks, so this is
// now the entire seam surface: there is nothing else left for a test to point
// anywhere, and a test that still wanted to would be modelling a resolver
// behaviour that no longer exists.
func withRunningBinary(t *testing.T, selfPath string) {
	t.Helper()
	orig := osExecutable
	t.Cleanup(func() { osExecutable = orig })
	if selfPath == "" {
		osExecutable = func() (string, error) { return "", os.ErrNotExist }
	} else {
		osExecutable = func() (string, error) { return selfPath, nil }
	}
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
	withRunningBinary(t, self)

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
			withRunningBinary(t, self)

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

// TestResolveVerifyGateBinResolvesTheRunningBinary is the ANTI-OVER-REACH
// guard for #6620: on a healthy box the resolver must still succeed.
//
// Refusing on a healthy box is its own outage — a Gate-3 error routes to
// revert(), so an over-strict resolver would reboot every candidate trial back
// to known-good and no kernel could ever be promoted. The refusal added by
// #6620 is only correct because THIS case keeps working.
//
// This test previously also planted a rival binary under versions/current to
// prove the running binary OUTRANKED it. That fixture is deliberately gone
// rather than left in place: with the configured-root fallbacks deleted the
// resolver cannot see such a file at all, so planting one would assert nothing
// while reading like a priority test (a vacuous survivor of the rewrite).
func TestResolveVerifyGateBinResolvesTheRunningBinary(t *testing.T) {
	root := t.TempDir()
	self := fakeXpfd(t, filepath.Join(root, "versions", "running"), 0)
	withRunningBinary(t, self)

	got, err := resolveVerifyGateBin()
	if err != nil {
		t.Fatalf("resolveVerifyGateBin on a healthy box: %v — refusing here "+
			"reverts every candidate trial (#6620 over-reach)", err)
	}
	if got != self {
		t.Fatalf("resolved %q, want the running binary %q", got, self)
	}
}

// pre6620FallbackLabels are the substrings the DELETED fallback chain used to
// put in its aggregated error when it had tried, and failed, to use a
// configured root. They are named here for one purpose: a fail-on-revert that
// does not depend on what happens to exist on the machine running the test.
//
// A refusal test that only asserts `err != nil` is PROBE-BOUNDED. Restore the
// fallbacks and, on a box that has a real /usr/local/sbin/xpfd, the resolver
// returns that path — caught by the empty-path assertion. On a box that has
// neither default, the reverted resolver still errors, and the assertion goes
// green while the defect is fully present. Asserting the error does NOT carry
// these labels closes that second branch: the reverted code emits them
// whenever it reached for a root and could not use it, which is exactly the
// case the empty-path assertion cannot see.
var pre6620FallbackLabels = []string{"managed sbin entry", "versioned runtime"}

// assertRefusedWithoutInference is the shared refusal assertion. Both halves
// matter and they fail on DIFFERENT machines, so neither is redundant.
func assertRefusedWithoutInference(t *testing.T, got string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("resolveVerifyGateBin returned %q with no identifiable running "+
			"xpfd; since #6620 it must REFUSE rather than infer one from a "+
			"configured root", got)
	}
	if got != "" {
		t.Fatalf("resolveVerifyGateBin refused but still returned %q — a caller "+
			"that ignores the error would exec an inferred binary", got)
	}
	for _, label := range pre6620FallbackLabels {
		if strings.Contains(err.Error(), label) {
			t.Fatalf("the refusal names %q, so the resolver still ATTEMPTED a "+
				"configured-root fallback before giving up (#6620). Error: %v",
				label, err)
		}
	}
	if !strings.Contains(err.Error(), "#6620") {
		t.Errorf("refusal %q should cite #6620 so an operator reading the revert "+
			"reason can tell this apart from a genuine verifier REJECT", err)
	}
}

// TestResolveVerifyGateBinRefusesWhenTheRunningBinaryIsUnidentifiable is the
// core #6620 fail-on-revert: os.Executable is the ONLY authority, and when it
// cannot answer the resolver refuses.
//
// Why refusing beats the old fallback, stated as the failure it prevents:
// <SbinDir>/xpfd and <VersionsDir>/current/xpfd are compiled-in defaults, and
// `--sbin-dir`/`--versions-dir` relocate INDEPENDENTLY without removing what
// they leave behind. So on a relocated box a leftover at either default is
// byte-for-byte indistinguishable from a live install — including the
// both-roots-relocated shape where the surviving default symlink still points
// at the surviving default runtime, making the two "candidates" ONE INODE
// exactly like a healthy layout. Executing that leftover verifies the candidate
// KERNEL against the wrong DATAPLANE and then authorizes a permanent promotion
// on the result. Refusing routes to revert(), which is the safe direction.
func TestResolveVerifyGateBinRefusesWhenTheRunningBinaryIsUnidentifiable_6620(t *testing.T) {
	withRunningBinary(t, "") // no /proc: os.Executable errors

	got, err := resolveVerifyGateBin()
	assertRefusedWithoutInference(t, got, err)
}

// TestResolveVerifyGateBinRefusesWhenTheRunningBinaryPathIsGone covers the
// SECOND way the sole authority can be unusable, distinct from the error branch
// above: os.Executable SUCCEEDS and returns a plausible path, but that path no
// longer resolves. This is what an UNLINKED running binary actually looks like,
// and it is the branch most likely to be hit in production — a binary cut that
// replaced the running artifact mid-flight.
//
// Be precise about the mechanism, because the obvious guess is wrong: Readlink
// on /proc/self/exe appends " (deleted)" for an unlinked binary, but Go TRIMS
// that suffix and returns the original path with a nil error
// (src/os/executable_procfs.go). So there is no suffix to detect, and a test
// seeding a "(deleted)"-suffixed string would be feeding the resolver an input
// the real API cannot produce. The refusal is driven purely by os.Stat
// returning ENOENT — which is exactly what this seeds.
//
// This is also the case that makes #6620 more than housekeeping. Before the
// fix, an unlinked running binary fell through to <SbinDir>/xpfd — which after
// a cut is precisely the NEW build, not the one that armed the candidate. The
// gate would then verify the candidate kernel against a dataplane the arming
// never designated, and Gate 2b's arm-record cross-check could not catch it:
// that check compares os.Executable against the record, and os.Executable here
// still reports the OLD path.
func TestResolveVerifyGateBinRefusesWhenTheRunningBinaryPathIsGone_6620(t *testing.T) {
	root := t.TempDir()
	// A real-shaped path (versions/<ver>/xpfd) that was created and then
	// unlinked — os.Executable would still report it verbatim.
	unlinked := fakeXpfd(t, filepath.Join(root, "versions", "v1.2.3"), 0)
	if err := os.Remove(unlinked); err != nil {
		t.Fatalf("unlink %s: %v", unlinked, err)
	}
	// A perfectly usable rival at the shape the DELETED candidate 3 would have
	// built. It is planted to document the case, not to be found: the resolver
	// has no versions-dir seam any more, so nothing can point it here. The
	// assertion that it is never returned is therefore carried by
	// assertRefusedWithoutInference's empty-path check, not by this file.
	fakeXpfd(t, filepath.Join(root, "versions", "current"), 0)

	withRunningBinary(t, unlinked)

	got, err := resolveVerifyGateBin()
	assertRefusedWithoutInference(t, got, err)
}

// TestVerifyDataplaneRefusesRatherThanVerifyingWithAnInferredBinary is the
// caller-visible half: the refusal must reach Gate 3 as an ERROR, because that
// is what routes to revert(). A resolver that refused but let VerifyDataplane
// report PASS would be strictly worse than the fallback it replaced.
func TestVerifyDataplaneRefusesRatherThanVerifyingWithAnInferredBinary_6620(t *testing.T) {
	root := t.TempDir()
	unlinked := fakeXpfd(t, filepath.Join(root, "versions", "v1"), 0)
	if err := os.Remove(unlinked); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	withRunningBinary(t, unlinked)

	ok, err := (&realKernelSystem{}).VerifyDataplane()
	if err == nil {
		t.Fatalf("VerifyDataplane returned ok=%v with a nil error and no "+
			"identifiable xpfd; Gate 3 turns only a NON-NIL error into revert() "+
			"(#6620)", ok)
	}
	if ok {
		t.Fatal("VerifyDataplane reported PASS without running any verifier (#6620)")
	}
	// WHICH layer rejected, not merely THAT one did. Without this the cell is
	// not sensitive to the resolver accepting the path at all: hand
	// exec.Command a path that does not exist and it fails at exec time with
	// its own error, so `err != nil && !ok` holds either way and the assertion
	// cannot tell "refused before exec" from "tried and could not exec".
	//
	// The distinction is the point of the branch. An unusable path happens to
	// fail late as well, but a BARE name does not — exec.Command PATH-resolves
	// it and a planted xpfd would report a clean verify (#6541). The two live
	// in one branch, so the cell must observe the branch, not the outcome.
	const resolverLayer = "resolve verify-dataplane gate binary"
	if !strings.Contains(err.Error(), resolverLayer) {
		t.Fatalf("VerifyDataplane failed with %q, which is not a %q refusal — "+
			"the resolver ACCEPTED the unusable path and the failure came from "+
			"exec instead (#6620)", err, resolverLayer)
	}
	for _, label := range pre6620FallbackLabels {
		if strings.Contains(err.Error(), label) {
			t.Fatalf("VerifyDataplane's error names %q — the configured-root "+
				"fallback is back (#6620): %v", label, err)
		}
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

	withRunningBinary(t, "")

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

	withRunningBinary(t, "")

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

// The pre-#6620 over-reach guard TestGateResolutionDefaultsToProductionVersionsDir
// lived here. It asserted that the fallback package vars defaulted to the real
// #1917 roots (so a normal promote resolved through versions/current rather
// than a test-only path). Those vars no longer exist, so the test could only
// have been kept by re-adding what #6620 deleted.
//
// Its PURPOSE — "the resolver must not over-reach into something test-only" —
// is carried by TestResolveVerifyGateBinResolvesTheRunningBinary above, which
// is the over-reach that is now possible: refusing a healthy box. DefaultSbinDir
// and DefaultVersionsDir themselves remain covered where they are still USED,
// by the flip/cutover tests that exercise the cut writing them.
