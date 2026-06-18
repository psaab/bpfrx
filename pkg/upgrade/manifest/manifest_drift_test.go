package manifest

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot walks up from this test file's directory until it finds go.mod,
// so the canary reads the tracked shell sites regardless of the test's cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate repo root")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("walked to filesystem root from %s without finding go.mod", filepath.Dir(thisFile))
		}
		dir = parent
	}
}

// readFile reads a repo-relative file and fails the test if it is missing —
// the canary must fail closed: a moved/renamed site is a divergence, not a
// skip.
func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v (the drift canary expects this file to exist; "+
			"if it moved, update the canary)", rel, err)
	}
	return string(b)
}

// binsLine matches a `BINS="word word ..."` assignment, tolerating leading
// whitespace (the test fixtures indent the assignment inside a function).
var binsLine = regexp.MustCompile(`(?m)^[[:space:]]*BINS="([^"]*)"`)

// extractBINS pulls the single BINS="..." word list out of a shell source and
// returns the space-separated fields. It FAILS the test (fail-closed) if no
// BINS= literal is present or if more than one is present (a script that drops
// the literal, or grows a second divergent one, must trip the canary rather
// than be silently skipped — Codex caution against a vacuous regex match).
func extractBINS(t *testing.T, rel, src string) []string {
	t.Helper()
	m := binsLine.FindAllStringSubmatch(src, -1)
	if len(m) == 0 {
		t.Fatalf("%s: no `BINS=\"...\"` literal found — the managed-binary "+
			"drift canary requires every shell site to carry the BINS literal "+
			"(if the mechanism changed, update pkg/upgrade/manifest and this "+
			"canary together)", rel)
	}
	if len(m) > 1 {
		t.Fatalf("%s: found %d `BINS=\"...\"` literals; expected exactly one "+
			"(a second, possibly divergent, list defeats the canary)", rel, len(m))
	}
	return strings.Fields(m[0][1])
}

// rulesInstall matches the `install -m 0755 <src> ... debian/xpf$(STAGED)/<name>`
// lines in debian/rules. The install command may wrap across two physical
// lines (xpf-day0-config does), so we match on the staged destination path
// which is what defines the installed basename.
var rulesInstallDest = regexp.MustCompile(`debian/xpf\$\(STAGED\)/([A-Za-z0-9._-]+)`)

// extractRulesInstall pulls the set of basenames debian/rules installs into
// the staging dir. It scans only the override_dh_auto_install recipe so that
// unrelated debian/xpf$(STAGED) mentions elsewhere do not pollute the set.
func extractRulesInstall(t *testing.T, src string) []string {
	t.Helper()
	const startMarker = "override_dh_auto_install:"
	start := strings.Index(src, startMarker)
	if start < 0 {
		t.Fatalf("debian/rules: %q recipe not found", startMarker)
	}
	body := src[start+len(startMarker):]
	// The recipe ends at the next top-level target/override (a line starting
	// at column 0 that is not blank and not a comment). Recipe lines are
	// TAB-indented.
	if end := nextTopLevel(body); end >= 0 {
		body = body[:end]
	}
	var names []string
	for _, m := range rulesInstallDest.FindAllStringSubmatch(body, -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatal("debian/rules: no `debian/xpf$(STAGED)/<name>` install lines " +
			"found in override_dh_auto_install (the canary expects the managed " +
			"binaries to be installed there)")
	}
	return names
}

// nextTopLevel returns the offset of the first line in body that begins a new
// top-level make construct (column-0, non-blank, non-comment, non-recipe), or
// -1 if none. Recipe lines are TAB-indented; a directory `install -d` that is
// not a managed binary is harmless because it does not match rulesInstallDest.
func nextTopLevel(body string) int {
	lines := strings.SplitAfter(body, "\n")
	off := 0
	for _, ln := range lines {
		trimmedNL := strings.TrimRight(ln, "\n")
		if trimmedNL != "" && !strings.HasPrefix(ln, "\t") &&
			!strings.HasPrefix(strings.TrimSpace(ln), "#") {
			return off
		}
		off += len(ln)
	}
	return -1
}

// besteffortForLoop matches the literal managed-binary `for b in ...` loop in
// test/debian/preinst-besteffort-test.sh. That fixture hardcodes the binary
// list in a for loop rather than a BINS= literal, so it is a drift site the
// canary must cover too (the plan's eight-site list missed it; we cover it
// here). We assert the full-set loop (the one that includes xpfd) matches.
var besteffortFullLoop = regexp.MustCompile(`for b in (xpfd[^;]*); do`)

func extractBesteffortLoop(t *testing.T, src string) []string {
	t.Helper()
	m := besteffortFullLoop.FindStringSubmatch(src)
	if m == nil {
		t.Fatal("preinst-besteffort-test.sh: no `for b in xpfd ...; do` " +
			"managed-binary loop found (the canary expects this fixture to " +
			"iterate the full managed set)")
	}
	return strings.Fields(m[1])
}

// sortedEqual reports whether a and b contain the same elements (order- and
// duplicate-sensitive after sorting). The shell loops are order-free, so the
// canary compares as sets-with-multiplicity.
func sortedEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// TestManagedBinaryDriftCanary is the #1982 drift guard. It FAILS the suite if
// any shell site's managed-binary list diverges from the Go SSOT
// (manifest.Names). Every duplicated edit site is covered.
func TestManagedBinaryDriftCanary(t *testing.T) {
	root := repoRoot(t)
	want := Names()

	// Shell sites carrying a BINS="..." literal.
	binsSites := []string{
		"debian/xpf.preinst",
		"debian/xpf.postinst",
		"debian/xpf.postrm",
		"test/debian/preinst-migrate-test.sh",
		"test/debian/postrm-test.sh",
	}
	for _, rel := range binsSites {
		got := extractBINS(t, rel, readFile(t, root, rel))
		if !sortedEqual(got, want) {
			t.Errorf("%s: BINS=%q diverges from manifest.Names()=%q — update "+
				"pkg/upgrade/manifest/manifest.go and every site together", rel, got, want)
		}
	}

	// debian/rules install set.
	gotRules := extractRulesInstall(t, readFile(t, root, "debian/rules"))
	if !sortedEqual(gotRules, want) {
		t.Errorf("debian/rules: install set %q diverges from manifest.Names()=%q",
			gotRules, want)
	}

	// preinst-besteffort-test.sh literal for-loop.
	gotBE := extractBesteffortLoop(t, readFile(t, root, "test/debian/preinst-besteffort-test.sh"))
	if !sortedEqual(gotBE, want) {
		t.Errorf("test/debian/preinst-besteffort-test.sh: for-loop set %q "+
			"diverges from manifest.Names()=%q", gotBE, want)
	}
}

// TestDriftCanaryComparatorCatchesDivergence is the counter-factual: it proves
// the canary's comparator (extractBINS + sortedEqual) actually REPORTS a
// divergence rather than passing vacuously. If this test ever passes while a
// real script drifts, the guard is worthless — so we feed the parser a drifted
// snippet and assert it does NOT match the SSOT.
func TestDriftCanaryComparatorCatchesDivergence(t *testing.T) {
	want := Names()

	cases := []struct {
		name string
		src  string
	}{
		{"missing-binary", `set -e
BINS="xpfd cli xpf-userspace-dp"
case "$1" in`},
		{"extra-binary", `set -e
BINS="xpfd cli xpf-userspace-dp xpf-day0-config xpf-new-helper"
case "$1" in`},
		{"renamed-binary", `set -e
BINS="xpfd cli xpf-userspace-dp xpf-day0"
case "$1" in`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := binsLine.FindStringSubmatch(tc.src)
			if m == nil {
				t.Fatalf("comparator test setup: BINS not found in %q", tc.src)
			}
			got := strings.Fields(m[1])
			if sortedEqual(got, want) {
				t.Fatalf("comparator FAILED to catch divergence: drifted "+
					"BINS=%q compared equal to manifest %q — the drift canary "+
					"would pass vacuously", got, want)
			}
		})
	}

	// And the inverse: the in-sync literal MUST compare equal (so the canary
	// is not a constant-fail).
	inSync := `set -e
BINS="` + ShellBINS() + `"
case "$1" in`
	m := binsLine.FindStringSubmatch(inSync)
	if m == nil {
		t.Fatal("comparator test: BINS not found in in-sync snippet")
	}
	if !sortedEqual(strings.Fields(m[1]), want) {
		t.Fatalf("comparator rejected an IN-SYNC BINS literal %q vs manifest %q "+
			"— the canary would false-positive", strings.Fields(m[1]), want)
	}
}

// TestManifestShape locks the manifest's basic invariants so a careless edit
// (empty list, duplicate name, blank field) is caught at the SSOT itself.
func TestManifestShape(t *testing.T) {
	if len(Managed) == 0 {
		t.Fatal("manifest.Managed is empty")
	}
	seen := map[string]bool{}
	for i, b := range Managed {
		if b.Name == "" {
			t.Errorf("Managed[%d] has empty Name", i)
		}
		if b.StagedSrc == "" {
			t.Errorf("Managed[%d] (%s) has empty StagedSrc", i, b.Name)
		}
		if seen[b.Name] {
			t.Errorf("Managed[%d] duplicate Name %q", i, b.Name)
		}
		seen[b.Name] = true
	}
	if Managed[0].Name != "xpfd" {
		t.Errorf("Managed[0].Name=%q, want \"xpfd\" (callers rely on the daemon "+
			"being first)", Managed[0].Name)
	}
	if got, want := ShellBINS(), strings.Join(Names(), " "); got != want {
		t.Errorf("ShellBINS()=%q, want %q", got, want)
	}
}

// TestLockstepNames locks the lockstep subset the cut's pre-start
// completeness check (pkg/upgrade.versionDirComplete) derives from the
// manifest. The set must be exactly the daemon + the dataplane helper; a
// regression that flips a LockstepCut flag would change which binaries the
// cut requires present before StartUnit.
func TestLockstepNames(t *testing.T) {
	got := LockstepNames()
	want := []string{"xpfd", "xpf-userspace-dp"}
	if !sortedEqual(got, want) {
		t.Errorf("LockstepNames()=%q, want %q (xpfd + xpf-userspace-dp are the "+
			"version-locked dataplane set)", got, want)
	}
	// Every lockstep name must also be a managed name (a lockstep binary that
	// is not in the managed set would never be staged/copied).
	managed := map[string]bool{}
	for _, n := range Names() {
		managed[n] = true
	}
	for _, n := range got {
		if !managed[n] {
			t.Errorf("LockstepNames() returned %q which is not in Names()", n)
		}
	}
}
