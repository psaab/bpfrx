package refactoraudit

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot walks up from this test file's directory until it finds
// go.mod, so the canary works regardless of the test's cwd (go test runs
// each package with cwd = the package dir) and regardless of whether it
// runs in the main checkout or a git worktree.
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

// runScript runs a repo script under bash from the repo root and returns
// its stdout. The canary fails closed: a missing bash/script or a
// non-zero exit is a divergence, not a skip.
func runScript(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("bash", args...)
	cmd.Dir = root
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bash %s: %v\nstderr:\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

// TestHeatmapNotStale is the drift gate. It regenerates the heatmap with
// the committed generator and asserts the output byte-for-byte matches
// the committed docs/refactoring-audit-current.txt. A refactor that
// resizes/adds/deletes a >=1500 LOC production file without running
// `bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt`
// (or `make audit-check`) fails here. FAIL-ON-REVERT: perturbing any LOC
// number in the committed artifact makes this test RED.
func TestHeatmapNotStale(t *testing.T) {
	root := repoRoot(t)
	committedPath := filepath.Join(root, "docs", "refactoring-audit-current.txt")
	committed, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("read committed heatmap %s: %v", committedPath, err)
	}
	generated := runScript(t, root, "scripts/refactoring-audit.sh")
	if string(committed) != generated {
		t.Fatalf("docs/refactoring-audit-current.txt is STALE.\n"+
			"Regenerate with:\n"+
			"  bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt\n"+
			"then commit the result.\n\n--- committed ---\n%s\n--- generated ---\n%s",
			string(committed), generated)
	}
}

// TestClassifierFilenameShapes pins the exclusion classifier through the
// same thin CLI the generator uses, so the two cannot drift. Every Rust
// test-only filename shape (#6232) must be excluded, every generated/Go
// test shape must be excluded, and — critically — a production file
// whose name merely CONTAINS "test" must stay counted (anchoring
// regression guard).
func TestClassifierFilenameShapes(t *testing.T) {
	root := repoRoot(t)

	// Paths that MUST be excluded (SKIP).
	skip := []string{
		"userspace-dp/src/nat/tests_pool.rs",        // tests_*.rs sibling split
		"userspace-dp/src/afxdp/tests_support.rs",   // tests_*.rs support module
		"userspace-dp/src/afxdp/test_fixtures.rs",   // test_*.rs fixtures
		"userspace-dp/src/afxdp/tx/test_support.rs", // test_*.rs support
		"userspace-dp/src/test_alloc.rs",            // test_*.rs top-level
		"userspace-dp/src/test_zone_ids.rs",         // test_*.rs top-level
		"userspace-dp/src/foo/tests.rs",             // exact tests.rs
		"userspace-dp/src/bar_tests.rs",             // *_tests.rs suffix
		"pkg/foo/bar_test.go",                       // Go test
		"pkg/foo/baz_bpfel.go",                      // bpf2go generated
		"pkg/x/y.pb.go",                             // protobuf generated
		"pkg/x/y_grpc.pb.go",                        // gRPC generated
		"vendor/x/y.go",                             // vendored
		"userspace-dp/target/debug/foo.rs",          // build artifact
	}
	// Paths that MUST be counted (SOURCE). The last three contain the
	// substring "test" but are NOT test files — they guard against an
	// unanchored pattern eating production code.
	source := []string{
		"userspace-dp/src/afxdp/poll_descriptor/mod.rs",
		"pkg/config/compiler.go",
		"userspace-dp/src/policy.rs",
		"userspace-dp/src/attestation.rs",
		"userspace-dp/src/latest_state.rs",
		"userspace-dp/src/contest.rs",
	}

	classify := func(paths []string) map[string]string {
		args := append([]string{"scripts/refactoring-audit-classify.sh", "classify"}, paths...)
		out := runScript(t, root, args...)
		got := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.SplitN(line, " ", 2)
			if len(fields) != 2 {
				t.Fatalf("unexpected classify line %q", line)
			}
			got[fields[1]] = fields[0]
		}
		return got
	}

	for p, verdict := range classify(skip) {
		if verdict != "SKIP" {
			t.Errorf("classifier: %s => %s, want SKIP (test/generated/vendored must be excluded)", p, verdict)
		}
	}
	for p, verdict := range classify(source) {
		if verdict != "SOURCE" {
			t.Errorf("classifier: %s => %s, want SOURCE (production must be counted)", p, verdict)
		}
	}
}

// TestProductionSentinelVisible asserts the negative fixture from the
// #6232 acceptance criteria: a real >=2000 LOC production module stays
// visible in the committed heatmap, and no excluded Rust test file is
// present. If the classifier ever over-excludes and hides real
// production code, or under-excludes and re-admits a test warehouse,
// this fails.
func TestProductionSentinelVisible(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "docs", "refactoring-audit-current.txt"))
	if err != nil {
		t.Fatalf("read committed heatmap: %v", err)
	}
	heatmap := string(b)

	const sentinel = "userspace-dp/src/afxdp/poll_descriptor/mod.rs"
	if !strings.Contains(heatmap, sentinel) {
		t.Errorf("production sentinel %s is missing from the heatmap; the classifier may be over-excluding real production code", sentinel)
	}
	// The sentinel must be a [REFACTOR] (>=2000 LOC) row.
	for _, line := range strings.Split(heatmap, "\n") {
		if strings.HasSuffix(line, sentinel) && !strings.HasPrefix(line, "[REFACTOR]") {
			t.Errorf("sentinel row is not [REFACTOR] tier: %q", line)
		}
	}

	// No excluded test file may reappear.
	for _, bad := range []string{
		"tests_pool.rs", "tests_support.rs", "tests_destination.rs",
		"test_fixtures.rs", "test_support.rs", "/tests.rs", "_tests.rs",
	} {
		if strings.Contains(heatmap, bad) {
			t.Errorf("excluded test file %q leaked into the heatmap", bad)
		}
	}
}

// TestInlineTestBlockNotStripped pins the historical parser-failure
// regression (docs/refactoring-audit.md): the audit measures RAW file
// LOC and must NOT strip an inline `#[cfg(test)] mod tests { ... }`
// block — an earlier awk range-stripper silently erased production code
// that FOLLOWED the test block. A fixture file with production code
// after an inline test block must report its full line count.
func TestInlineTestBlockNotStripped(t *testing.T) {
	root := repoRoot(t)
	fixture := "// production line 1\n" +
		"pub fn before() {}\n" +
		"#[cfg(test)]\n" +
		"mod tests {\n" +
		"    #[test]\n" +
		"    fn t() { assert!(true); }\n" +
		"}\n" +
		"// production line AFTER the inline test block — must be counted\n" +
		"pub fn after() {}\n"
	wantLOC := strings.Count(fixture, "\n") // 9 lines, all newline-terminated

	dir := t.TempDir()
	path := filepath.Join(dir, "inline_fixture.rs")
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out := runScript(t, root, "scripts/refactoring-audit-classify.sh", "loc", path)
	got := strings.TrimSpace(out)
	want := itoa(wantLOC)
	if got != want {
		t.Fatalf("audit_loc stripped or miscounted an inline-test fixture: got %q, want %q\n"+
			"the measurement must count RAW LOC so a stripper cannot erase production code following a test block", got, want)
	}
}

// itoa avoids importing strconv for a single conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
