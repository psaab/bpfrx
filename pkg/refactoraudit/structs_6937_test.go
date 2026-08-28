package refactoraudit

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #6937 canary for the struct-heterogeneity signal.

func repoRoot6937(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// TestStructFloorsMatchShellConstants6937 pins the Go constants against
// refactoring-audit-lib.sh. Two copies of a threshold drift, and the whole
// reason that lib exists is that the generator and the gate must classify
// identically (#6232/#7253).
func TestStructFloorsMatchShellConstants6937(t *testing.T) {
	root := repoRoot6937(t)
	b, err := os.ReadFile(filepath.Join(root, "scripts", "refactoring-audit-lib.sh"))
	if err != nil {
		t.Fatalf("read lib: %v", err)
	}
	for _, tc := range []struct {
		shellVar string
		goConst  int
	}{
		{"AUDIT_STRUCT_FLOOR", StructWatchFloor},
		{"AUDIT_STRUCT_REFACTOR_FLOOR", StructRefactorFloor},
	} {
		// Anchor to a line start so AUDIT_STRUCT_FLOOR cannot match inside
		// AUDIT_STRUCT_REFACTOR_FLOOR or inside a comment mentioning it.
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(tc.shellVar) + `=(\d+)$`)
		m := re.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s not found as a bare assignment in refactoring-audit-lib.sh", tc.shellVar)
		}
		got, _ := strconv.Atoi(string(m[1]))
		if got != tc.goConst {
			t.Errorf("%s = %d in shell but %d in Go — the generator and the gate would "+
				"classify differently", tc.shellVar, got, tc.goConst)
		}
	}
}

// TestStructMetricIsTypesNotFields6937 is the calibration, and it is the
// reason the metric is distinct types rather than field count.
//
// The extremes do not calibrate a threshold; the pair astride it does.
// Engine has FEWER fields than CompileResult and MORE distinct types, so
// only a type-based metric can flag one and pass the other. A field-count
// metric orders them the wrong way round.
func TestStructMetricIsTypesNotFields6937(t *testing.T) {
	root := repoRoot6937(t)
	rows, err := GoStructs(filepath.Join(root, "pkg"), func(string) bool { return true })
	if err != nil {
		t.Fatalf("GoStructs: %v", err)
	}
	byName := map[string]StructRow{}
	for _, r := range rows {
		if strings.HasSuffix(r.Path, "eventengine/engine.go") && r.Name == "Engine" {
			byName["Engine"] = r
		}
		if strings.HasSuffix(r.Path, "dataplane/compiler.go") && r.Name == "CompileResult" {
			byName["CompileResult"] = r
		}
		if strings.HasSuffix(r.Path, "api/metrics.go") && r.Name == "xpfCollector" {
			byName["xpfCollector"] = r
		}
	}
	eng, ok1 := byName["Engine"]
	cr, ok2 := byName["CompileResult"]
	coll, ok3 := byName["xpfCollector"]
	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("calibration fixtures missing: Engine=%v CompileResult=%v xpfCollector=%v",
			ok1, ok2, ok3)
	}

	// The middle pair: just over and just under the watch floor.
	if eng.Tag() == "" {
		t.Errorf("Engine (%d fields, %d types) does not flag; it is the just-OVER "+
			"calibration point for a floor of %d", eng.Fields, eng.DistinctTypes, StructWatchFloor)
	}
	if cr.Tag() != "" {
		t.Errorf("CompileResult (%d fields, %d types) flags; it is the just-UNDER "+
			"calibration point for a floor of %d", cr.Fields, cr.DistinctTypes, StructWatchFloor)
	}
	// ...and the ordering that makes the metric a choice rather than a proxy.
	if !(cr.Fields > eng.Fields && eng.DistinctTypes > cr.DistinctTypes) {
		t.Errorf("the calibration pair no longer inverts: Engine %d fields/%d types vs "+
			"CompileResult %d fields/%d types. A field-count metric would now order them "+
			"the same way, so this test no longer shows why types are measured",
			eng.Fields, eng.DistinctTypes, cr.Fields, cr.DistinctTypes)
	}

	// The false positive that motivated the whole choice: the largest
	// struct in the tree by field count must NOT flag, because it is one
	// *prometheus.Desc per metric and has nothing to decompose.
	if coll.Tag() != "" {
		t.Errorf("xpfCollector (%d fields, %d types) flags. It is the tree's largest "+
			"struct by field count and a legitimate aggregate; if it flags, the signal's "+
			"top row is a false positive and the gate will be ignored",
			coll.Fields, coll.DistinctTypes)
	}
	if coll.Fields <= eng.Fields {
		t.Errorf("xpfCollector has %d fields, no longer dramatically more than the "+
			"flagged Engine's %d — the false-positive demonstration has lost its force",
			coll.Fields, eng.Fields)
	}
}

// TestRustScannerSeesPubInPathStructs6937 pins the miss that produced NO
// ROW AT ALL for ForwardingState — one of the two god-structs #6937 was
// filed about.
//
// The visibility prefix list was hardcoded and did not include
// `pub(in crate::afxdp)`, so the struct was silently invisible: not a
// wrong count, an absent row, with no error. An unreadable declaration
// must never be indistinguishable from one that does not exist.
func TestRustScannerSeesPubInPathStructs6937(t *testing.T) {
	dir := t.TempDir()
	src := `#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ForwardingStateLike {
    pub(in crate::afxdp) local_v4: FastSet<Ipv4Addr>,
    /// a doc comment that must not be counted
    pub(in crate::afxdp) local_v6: FastSet<Ipv6Addr>,
    pub(crate) plain: u32,
    pub other: String,
    bare: bool,
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := RustStructs(dir, func(string) bool { return true })
	if err != nil {
		t.Fatalf("RustStructs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 struct, got %d: %+v — a `pub(in path)` struct that "+
			"produces no row is invisible to the audit, which is how ForwardingState was "+
			"missed entirely", len(rows), rows)
	}
	// 5 fields: the doc comment is not one.
	if rows[0].Fields != 5 {
		t.Errorf("fields = %d, want 5. #6937: `pub(in crate::afxdp)` CONTAINS `::`, so "+
			"splitting the line on its first colon parsed the name as \"pub(in crate\" "+
			"and dropped the field. That reported ForwardingState as 3 fields instead "+
			"of 71 — a wrong number, which is harder to notice than a missing row",
			rows[0].Fields)
	}
	if rows[0].DistinctTypes != 5 {
		t.Errorf("distinct types = %d, want 5 (FastSet<Ipv4Addr>, FastSet<Ipv6Addr>, "+
			"u32, String, bool)", rows[0].DistinctTypes)
	}
}

// TestGoCounterCollapsesAnonymousNestedStructs6937 pins the trap on the Go
// side: printer.Fprint renders a nested `struct { ... }` across multiple
// lines, and counting each rendering as its own type inflated the census
// to "7 structs with >= 100 distinct types" when the truth is 1.
func TestGoCounterCollapsesAnonymousNestedStructs6937(t *testing.T) {
	dir := t.TempDir()
	src := `package x

type Outer struct {
	A int
	Nested struct {
		P string
		Q string
	}
	Other struct {
		R int
	}
	B int
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := GoStructs(dir, func(string) bool { return true })
	if err != nil {
		t.Fatalf("GoStructs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 NAMED struct, got %d: %+v — an ast.Inspect descent "+
			"reports anonymous nested structs as separate structs, which is out of scope",
			len(rows), rows)
	}
	r := rows[0]
	if r.Fields != 4 {
		t.Errorf("fields = %d, want 4 (A, Nested, Other, B) — inner fields are not counted", r.Fields)
	}
	// int, struct{...}, int  -> the two anonymous structs collapse to ONE token.
	if r.DistinctTypes != 2 {
		t.Errorf("distinct types = %d, want 2 (int + a single collapsed struct{...} token). "+
			"Without the collapse each nested struct's multi-line rendering counts as its "+
			"own type and the metric inflates in the alarming direction", r.DistinctTypes)
	}
}
