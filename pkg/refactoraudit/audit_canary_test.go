package refactoraudit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Tier tags and thresholds, mirroring scripts/refactoring-audit.sh.
// `categorize` there pads the WATCH tag for column alignment; the tag
// itself is the unpadded token these constants hold.
const (
	tierRefactor = "[REFACTOR]"
	tierWatch    = "[WATCH]"

	// auditFloor is the LOC at which a file enters the heatmap at all;
	// refactorFloor is the LOC at which it is promoted to [REFACTOR].
	auditFloor    = 1500
	refactorFloor = 2000
)

// auditRow is one parsed heatmap row, e.g.
//
//	[REFACTOR]   2448  userspace-dp/src/afxdp/worker/loop_body/mod.rs
type auditRow struct {
	tier string
	loc  int
	path string
}

// parseHeatmap parses heatmap text into rows. It fails closed: any line
// the generator could not have produced (wrong field count, unknown tier
// tag, non-numeric LOC) is a hard failure rather than a skipped row, so a
// corrupted or hand-mangled artifact can never read as "no drift".
func parseHeatmap(t *testing.T, what, text string) []auditRow {
	t.Helper()
	var rows []auditRow
	for i, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("%s line %d: want 3 fields (tier LOC path), got %d: %q", what, i+1, len(fields), line)
		}
		if fields[0] != tierRefactor && fields[0] != tierWatch {
			t.Fatalf("%s line %d: unknown tier tag %q (want %q or %q)", what, i+1, fields[0], tierRefactor, tierWatch)
		}
		loc, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("%s line %d: LOC field %q is not an integer: %v", what, i+1, fields[1], err)
		}
		rows = append(rows, auditRow{tier: fields[0], loc: loc, path: fields[2]})
	}
	if len(rows) == 0 {
		t.Fatalf("%s parsed to zero rows; this repo always has >=1500 LOC files, so an empty audit means the generator or the artifact is broken", what)
	}
	return rows
}

// tierByPath projects rows onto the audit's *content*: which files are
// audited, and at which tier. This is the merge-stable part of the
// heatmap — see TestHeatmapNotStale.
func tierByPath(rows []auditRow) map[string]string {
	m := make(map[string]string, len(rows))
	for _, r := range rows {
		m[r.path] = r.tier
	}
	return m
}

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
// the committed generator and asserts that the *audit content* — which
// files are audited, and at which tier — matches the tree. A file that
// enters the audit (crosses 1500 LOC), leaves it, or is promoted/demoted
// across the 2000 LOC [REFACTOR] boundary without running
// `bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt`
// (or `make audit-check`) fails here.
//
// # Why this is not a byte-for-byte compare (#6617)
//
// It used to be, and that criterion could not hold. The heatmap is a
// repo-GLOBAL snapshot: its exact LOC column depends on every audited
// file in the tree, not just the ones a PR touches. Under this project's
// parallel-merge workflow a PR that regenerates the artifact correctly at
// its own base still lands stale, because a sibling PR grew a different
// file in between. That is not hypothetical — measured over the 40
// first-parent commits ending at b4605ea9d, master was byte-stale in 26
// of them, and #6602 and #6613 BOTH regenerated the artifact in their own
// merge commit and BOTH still landed red, each disagreeing only on
// pkg/snmp/agent.go, a file neither PR touched (grown by #6596, merged
// between their base and their merge). A gate that reds when the author
// did everything right is noise, and the noise is what let the artifact
// sit 22 rows stale for 21 consecutive commits in the run before that.
//
// Tier and membership do not have that problem: they only change when a
// file actually crosses 1500 or 2000 LOC, which is a real, rare,
// actionable event — and it is exactly the event the project's own rules
// key on (docs/refactoring-audit.md "When to refactor a candidate", and
// the "regen only if it crosses a tier boundary" instruction already used
// in docs/pr/1706 and docs/pr/1732 plans).
//
// The LOC column stays in the artifact for prioritisation, as an advisory
// snapshot refreshed by `make audit-check`. TestHeatmapArtifactWellFormed
// pins each recorded LOC to its tier band, and any band crossing reds this
// test, which forces a regeneration that refreshes every number — but the
// bound that gives is ASYMMETRIC. [WATCH] is 1500-1999, bounded both ways.
// [REFACTOR] is "2000 or more", open above, so a file already past 2000 can
// grow without limit unwatched; this artifact's own
// userspace-dp/src/afxdp/worker/loop_body/mod.rs drifted 2119 -> 2448 with
// no signal. That is tolerable only because the TIER is what the project's
// rules act on and the tier does not go stale — not because the number is
// nearly right.
//
// FAIL-ON-REVERT: retagging any committed row's tier, deleting a row, or
// adding a phantom row makes this test RED.
func TestHeatmapNotStale(t *testing.T) {
	root := repoRoot(t)
	committedPath := filepath.Join(root, "docs", "refactoring-audit-current.txt")
	b, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("read committed heatmap %s: %v", committedPath, err)
	}
	committed := tierByPath(parseHeatmap(t, "committed docs/refactoring-audit-current.txt", string(b)))
	generated := tierByPath(parseHeatmap(t, "freshly generated heatmap", runScript(t, root, "scripts/refactoring-audit.sh")))

	var entered, left, retiered []string
	for path, tier := range generated {
		old, ok := committed[path]
		switch {
		case !ok:
			entered = append(entered, fmt.Sprintf("  %-10s %s", tier, path))
		case old != tier:
			retiered = append(retiered, fmt.Sprintf("  %s: %s -> %s", path, old, tier))
		}
	}
	for path, tier := range committed {
		if _, ok := generated[path]; !ok {
			left = append(left, fmt.Sprintf("  %-10s %s", tier, path))
		}
	}
	if len(entered)+len(left)+len(retiered) == 0 {
		return
	}
	sort.Strings(entered)
	sort.Strings(left)
	sort.Strings(retiered)

	var msg strings.Builder
	msg.WriteString("docs/refactoring-audit-current.txt is STALE: the audited file set / tier\n" +
		"assignment no longer matches the tree.\n")
	for _, section := range []struct {
		title string
		rows  []string
	}{
		{fmt.Sprintf("entered the audit (now >=%d LOC)", auditFloor), entered},
		{fmt.Sprintf("left the audit (now <%d LOC, or renamed/deleted)", auditFloor), left},
		{fmt.Sprintf("changed tier (crossed %d LOC)", refactorFloor), retiered},
	} {
		if len(section.rows) == 0 {
			continue
		}
		fmt.Fprintf(&msg, "\n%s:\n%s\n", section.title, strings.Join(section.rows, "\n"))
	}
	msg.WriteString("\nRegenerate with:\n" +
		"  bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt\n" +
		"then commit the result. `make audit-check` shows the full diff.")
	t.Fatal(msg.String())
}

// TestHeatmapArtifactWellFormed pins the committed artifact's internal
// coherence, which is what makes the advisory LOC column safe to let lag
// (see TestHeatmapNotStale). Every row must record a LOC at or above the
// audit floor whose value agrees with its own tier tag, and the rows must
// still be in generator order. Together with the tier/membership gate this
// bounds LOC staleness to within a tier band: a row can never carry a
// number that contradicts the tier it is filed under, and a real band
// crossing reds TestHeatmapNotStale.
//
// These are hand-edit detectors, not drift detectors. The artifact is
// only ever produced wholesale by scripts/refactoring-audit.sh, which
// emits rows sorted and self-consistent by construction, so ordinary
// staleness — the tree moving on while the artifact keeps its old
// numbers — leaves every check here green. A row whose LOC contradicts
// its tag, or a row out of sort position, means someone edited the
// generated file by hand.
func TestHeatmapArtifactWellFormed(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "docs", "refactoring-audit-current.txt"))
	if err != nil {
		t.Fatalf("read committed heatmap: %v", err)
	}
	rows := parseHeatmap(t, "committed docs/refactoring-audit-current.txt", string(b))

	for _, r := range rows {
		if r.loc < auditFloor {
			t.Errorf("row %s records %d LOC, below the %d LOC audit floor — it should not be in the heatmap at all",
				r.path, r.loc, auditFloor)
		}
		want := tierWatch
		if r.loc >= refactorFloor {
			want = tierRefactor
		}
		if r.tier != want {
			t.Errorf("row %s: %d LOC is tagged %s, want %s (>=%d LOC is %s, %d-%d is %s)",
				r.path, r.loc, r.tier, want, refactorFloor, tierRefactor, auditFloor, refactorFloor-1, tierWatch)
		}
	}

	// Generator order: LOC descending, path ascending on ties
	// (LC_ALL=C sort -k2,2nr -k3,3 in scripts/refactoring-audit.sh).
	for i := 1; i < len(rows); i++ {
		prev, cur := rows[i-1], rows[i]
		if prev.loc < cur.loc || (prev.loc == cur.loc && prev.path > cur.path) {
			t.Errorf("rows %d/%d are out of generator order (LOC desc, path asc): %s (%d) precedes %s (%d)",
				i, i+1, prev.path, prev.loc, cur.path, cur.loc)
		}
	}
}

// TestGeneratorDeterministic asserts two consecutive generations are
// byte-identical (#6617 acceptance criterion). The tier/membership gate
// is only as trustworthy as the generator underneath it: an unstable
// generator — unsorted `find` order leaking through, a timestamp, a
// locale-dependent tie-break — would make the gate flap on an unchanged
// tree and re-create the ignore-this-signal failure #6617 is about.
func TestGeneratorDeterministic(t *testing.T) {
	root := repoRoot(t)
	first := runScript(t, root, "scripts/refactoring-audit.sh")
	second := runScript(t, root, "scripts/refactoring-audit.sh")
	if first != second {
		t.Fatalf("scripts/refactoring-audit.sh is NOT deterministic: two consecutive runs on an\n"+
			"unchanged tree differ. The heatmap gate cannot be trusted until this is fixed.\n\n--- run 1 ---\n%s\n--- run 2 ---\n%s",
			first, second)
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

	// PER-LANGUAGE FLOOR. The sentinel above is a single Rust path, so it
	// survives the Go leg of the generator being broken entirely: drop
	// audit_go(), regenerate, and the Go rows go 25 -> 0 while every test
	// here — and `make audit-check` — still reports success, because each
	// remaining check is satisfied by a Rust-only artifact. A whole language
	// silently leaving the audit is exactly the failure this file exists to
	// catch, so require at least one row from each side.
	var goRows, rustRows int
	for _, line := range strings.Split(heatmap, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		switch path := fields[2]; {
		case strings.HasPrefix(path, "pkg/"), strings.HasPrefix(path, "cmd/"):
			goRows++
		case strings.HasPrefix(path, "userspace-dp/"), strings.HasPrefix(path, "userspace-xdp/"):
			rustRows++
		}
	}
	if goRows == 0 {
		t.Error("no pkg/ or cmd/ rows in the heatmap: the Go leg of the audit " +
			"produced nothing. This repo always has >=1500 LOC Go files, so an " +
			"all-Rust artifact means the generator's Go half is broken, not that " +
			"the Go tree got small.")
	}
	if rustRows == 0 {
		t.Error("no userspace-dp/ or userspace-xdp/ rows in the heatmap: the Rust " +
			"leg of the audit produced nothing.")
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
	want := strconv.Itoa(wantLOC)
	if got != want {
		t.Fatalf("audit_loc stripped or miscounted an inline-test fixture: got %q, want %q\n"+
			"the measurement must count RAW LOC so a stripper cannot erase production code following a test block", got, want)
	}
}
