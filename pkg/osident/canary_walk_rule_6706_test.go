package osident

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// fixtureGoDirective is deliberately far BELOW the module's own go directive.
// The fixture uses no language features at all, and a directive newer than the
// running toolchain would make `go list` try to fetch one — which GOTOOLCHAIN
// and GOPROXY below forbid, turning a toolchain bump into a spurious red here.
const fixtureGoDirective = "go 1.21\n"

// canaryWalkFixture is the file tree TestCanaryWalkRuleMatchesTheToolchain_6706
// builds. Every entry exists to pin ONE clause of the traversal rule, and the
// `want` column is what `go list ./...` reports for it — cross-checked against
// the real toolchain by the second half of the test rather than asserted from
// belief.
//
// The two rows this round exists for are `zz_nocgo.go` and `vendor/probe.go`:
// each was a live escape at the previous head, each is reproduced in the review
// (#6706 r7 F1 and F2) with build and vet rc 0 and all three canaries green.
var canaryWalkFixture = []struct {
	path string // slash-relative to the fixture root
	body string
	want bool // must walkCanaryFiles visit it?
	why  string
}{
	{"root.go", "package probe\n", true,
		"an ordinary package file"},
	{"sub/ok.go", "package sub\n", true,
		"an ordinary nested package"},

	// F1 — the cgo axis. The appliance builds CGO_ENABLED=0 (Makefile:37,41),
	// `go test` usually runs cgo-enabled; canaryBuildCtxs unions the two.
	{"zz_nocgo.go", "//go:build !cgo\n\npackage probe\n", true,
		"compiled by the SHIPPED build (CGO_ENABLED=0); invisible under build.Default on a machine with a C compiler"},
	{"zz_cgo.go", "//go:build cgo\n\npackage probe\n", true,
		"compiled by a cgo-enabled build; invisible if CgoEnabled were pinned false"},

	// r8 F1 — MATCHING a build constraint is not the same as BEING COMPILED,
	// and the two halves of the union can select disjoint configurations. The
	// cgo file split (CgoFiles vs IgnoredGoFiles) happens in ImportDir, not in
	// MatchFile, so the MatchFile rule accepted the first row below under the
	// shipped context although NOTHING compiles it — a red no `go build`
	// agrees with. Cross-checked against `go list` by the oracle half, which
	// now reads CgoFiles as well as GoFiles (r8 F3: a legitimate cgo source was
	// never validated by the oracle at all).
	{"zz_nocgo_importsc.go", "//go:build !cgo\n\npackage probe\n\n/*\n*/\nimport \"C\"\n", false,
		"`!cgo` AND `import \"C\"`: CGO_ENABLED=0 ignores it for importing C, CGO_ENABLED=1 for the constraint — no configuration compiles it"},
	{"zz_cgo_importsc.go", "package probe\n\n/*\n*/\nimport \"C\"\n", true,
		"a legitimate cgo source — CgoFiles under CGO_ENABLED=1, and the class the oracle could not see while it read only GoFiles"},

	// F2 — cmd/go adds the vendor DIRECTORY as a package and prunes only its
	// SUBTREE (modload/search.go:139-152).
	{"vendor/probe.go", "package vendor\n", true,
		"the vendor directory's OWN files are compiled — `go list ./...` names the package"},
	{"vendor/sub/deep.go", "package sub\n", false,
		"the vendor SUBTREE is pruned"},

	// The directory clauses that were already right, kept so a regression in
	// them reds here too.
	{"testdata/td.go", "package td\n", false, "testdata is excluded"},
	{"_scratch/sc.go", "package sc\n", false, "`_`-prefixed directory"},
	{".hidden/h.go", "package h\n", false, "`.`-prefixed directory"},
	{"nested/go.mod", "module nested\n\n" + fixtureGoDirective, false, "not a .go file"},
	{"nested/n.go", "package nested\n", false, "inside a NESTED MODULE"},
	{"notmod/go.mod/keep.txt", "not a module marker\n", false, "not a .go file"},
	{"notmod/nm.go", "package notmod\n", true,
		"a go.mod DIRECTORY is not a module marker — the !IsDir() term (#6706 MINOR-1)"},

	// The file clauses.
	{"_ignored.go", "package probe\n", false, "`_`-prefixed FILE"},
	{"zz_windows.go", "//go:build windows\n\npackage probe\n", false,
		"GOOS constraint unsatisfied on linux"},
	{"zz_amd64_test.go", "package probe\n", false, "a _test.go file"},
	{"sub/notes.txt", "not go\n", false, "not a .go file"},
}

// TestCanaryWalkRuleMatchesTheToolchain_6706 drives walkCanaryFiles — the REAL
// traversal every #6701 canary uses, not a copy — over a fixture module, and
// requires its answer to be exactly the toolchain's.
//
// WHY THIS EXISTS. Three separate rounds of this PR shipped a traversal rule
// whose comment claimed equality with cmd/go and whose code diverged from it:
// an invented `node_modules` skip (#6706 review r5 F1), a `vendor` skip that
// pruned one directory too many (r7 F2), and a build context that answered for
// the developer's machine instead of the appliance (r7 F1). Each was found by a
// human planting a file and noticing the canaries stayed green. Each would have
// been caught here.
//
// The assertion has two halves, and the SECOND is what makes the first
// non-circular:
//
//  1. walkCanaryFiles's accepted set over the fixture must equal
//     canaryWalkFixture's `want` column. This binds the rule and needs no
//     toolchain.
//  2. that same `want` column must equal what `go list ./...` reports for the
//     fixture module, unioned over CGO_ENABLED=0 and CGO_ENABLED=1. This is the
//     ORACLE: without it the expectations are just my belief about cmd/go,
//     which is precisely the thing that was wrong three times.
//
// FAIL-ON-REVERT: restore `name == "vendor"` in skipCanaryDir, or
// `build.Default.MatchFile` in compiledByGoBuild, and the corresponding fixture
// row reds by name.
func TestCanaryWalkRuleMatchesTheToolchain_6706(t *testing.T) {
	root := t.TempDir()
	writeCanaryFixture(t, root)

	var visited []string
	if err := walkCanaryFiles(root, func(path string) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Errorf("relativise %s: %v", path, err)
			return
		}
		visited = append(visited, filepath.ToSlash(rel))
	}); err != nil {
		t.Fatalf("walkCanaryFiles: %v", err)
	}
	got := map[string]bool{}
	for _, v := range visited {
		got[v] = true
	}

	for _, f := range canaryWalkFixture {
		if got[f.path] != f.want {
			t.Errorf("walkCanaryFiles visited %s = %v, want %v — %s",
				f.path, got[f.path], f.want, f.why)
		}
	}
	for _, v := range visited {
		if !fixtureDeclares(v) {
			t.Errorf("walkCanaryFiles visited %s, which the fixture does not declare — the "+
				"expectation table is incomplete, so its silence means nothing", v)
		}
	}

	assertFixtureMatchesGoList(t, root)
}

// TestCanaryWalkFollowsASymlinkedRoot_6706 pins the SECOND residual difference
// from cmd/go that #6706 review r8 F2 found — and it was in the silent
// direction, which is the one this walk must never be in.
//
// filepath.WalkDir Lstats its root. A symlink pointing at a checkout is
// therefore not a directory to it: the walk visits the link itself, drops it as
// a non-.go file, and reports NOTHING — no packages, no files, no hits — while
// `go list ./...` run from that same path reports every package the module has.
// A canary walked from such a root is green because it looked at nothing.
//
// Both halves matter and both are asserted here: the walk must FIND the files,
// and it must hand back paths that relativise against the root the CALLER
// passed, since building the traversalSentinels keys is the only thing every
// caller does with them.
//
// FAIL-ON-REVERT: drop the filepath.EvalSymlinks in walkCanaryFiles and this
// reds with an empty visited set; drop rebaseCanaryPath and it reds because
// every path relativises to something outside the link root.
func TestCanaryWalkFollowsASymlinkedRoot_6706(t *testing.T) {
	real := t.TempDir()
	writeCanaryFixture(t, real)

	link := filepath.Join(t.TempDir(), "linkroot")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create a symlink here (%v) — the walk assertions elsewhere still ran", err)
	}

	got := map[string]bool{}
	if err := walkCanaryFiles(link, func(path string) {
		rel, err := filepath.Rel(link, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("walkCanaryFiles handed back %s, which does not relativise against the root "+
				"it was given (%s) — every caller keys on filepath.Rel(root, path)", path, link)
			return
		}
		got[filepath.ToSlash(rel)] = true
	}); err != nil {
		t.Fatalf("walkCanaryFiles through a symlinked root: %v", err)
	}

	for _, f := range canaryWalkFixture {
		if got[f.path] != f.want {
			t.Errorf("through a SYMLINKED root, walkCanaryFiles visited %s = %v, want %v — %s",
				f.path, got[f.path], f.want, f.why)
		}
	}
}

// fixtureDeclares reports whether path has a row in canaryWalkFixture.
func fixtureDeclares(path string) bool {
	for _, f := range canaryWalkFixture {
		if f.path == path {
			return true
		}
	}
	return false
}

// writeCanaryFixture materialises canaryWalkFixture under root, plus the
// module's own go.mod.
func writeCanaryFixture(t *testing.T, root string) {
	t.Helper()
	write := func(rel, body string) {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	write("go.mod", "module canaryprobe\n\n"+fixtureGoDirective)
	for _, f := range canaryWalkFixture {
		write(f.path, f.body)
	}
}

// assertFixtureMatchesGoList is the ORACLE half: it runs the real toolchain
// over the fixture module under both cgo settings and requires the union of the
// files it reports to be exactly canaryWalkFixture's `want` column.
//
// A missing toolchain SKIPS this half with a loud message rather than failing:
// the walk assertion above still binds the rule, and a test binary run without
// a `go` on the box is not evidence of a defect. It is not a hole a decoy can
// hide in — the expectations it validates are asserted unconditionally.
func assertFixtureMatchesGoList(t *testing.T, root string) {
	t.Helper()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		found, lerr := exec.LookPath("go")
		if lerr != nil {
			t.Skipf("ORACLE HALF SKIPPED: no go toolchain (%v / %v) — the walk assertions above "+
				"still ran, but nothing cross-checked them against cmd/go", err, lerr)
		}
		goBin = found
	}

	// GoFiles AND CgoFiles. Reading only GoFiles left an entire class — a
	// legitimate source that imports "C" — declared in the table above and
	// validated by nothing, which is the half of the oracle that makes the
	// table non-circular (#6706 review r8 F3). The template emits one
	// tab-separated field per file rather than a comma-joined list so that a
	// package with no CgoFiles cannot be confused with a malformed line.
	const listFormat = "{{.Dir}}{{range .GoFiles}}\t{{.}}{{end}}{{range .CgoFiles}}\t{{.}}{{end}}"
	oracle := map[string]bool{}
	for _, cgo := range []string{"0", "1"} {
		cmd := exec.Command(goBin, "list", "-f", listFormat, "./...")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgo,
			"GOWORK=off",        // a parent workspace must not redefine the module set
			"GOFLAGS=-mod=mod",  // a root `vendor/` must not switch the go command to -mod=vendor
			"GOPROXY=off",       // the fixture has no dependencies; a network fetch is a bug
			"GOTOOLCHAIN=local") // never download a toolchain to answer this
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (CGO_ENABLED=%s) in the fixture module: %v\n%s", cgo, err, stderr.String())
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fields := strings.Split(strings.TrimSpace(line), "\t")
			if len(fields) < 2 {
				continue // a package with no compiled files
			}
			rel, err := filepath.Rel(root, fields[0])
			if err != nil {
				t.Fatalf("relativise go list dir %s: %v", fields[0], err)
			}
			for _, name := range fields[1:] {
				oracle[filepath.ToSlash(filepath.Join(rel, name))] = true
			}
		}
	}
	if len(oracle) == 0 {
		t.Fatal("go list reported no Go files at all for the fixture module — the oracle is " +
			"not answering, so it cannot be validating anything")
	}

	var wrong []string
	for _, f := range canaryWalkFixture {
		if !strings.HasSuffix(f.path, ".go") {
			continue
		}
		if oracle[f.path] != f.want {
			wrong = append(wrong, f.path+": fixture says want="+boolStr(f.want)+
				" but `go list ./...` says "+boolStr(oracle[f.path])+" ("+f.why+")")
		}
	}
	for path := range oracle {
		if !fixtureDeclares(path) {
			wrong = append(wrong, path+": compiled by the toolchain but absent from the fixture table")
		}
	}
	sort.Strings(wrong)
	for _, w := range wrong {
		t.Errorf("the expectation table disagrees with cmd/go — %s", w)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
