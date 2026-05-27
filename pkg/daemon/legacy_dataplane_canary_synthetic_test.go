package daemon

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// scanSyntheticSource parses an in-memory Go source string and
// runs the SAME 5-pass scan as TestLegacyDPAccessorRemoved by
// calling the shared scanFileForLegacyDP helper. Gemini's #1559
// code-review-round-1 MAJOR finding flagged the earlier draft of
// this file for duplicating the production canary's logic into a
// parallel copy — fixed by routing both call sites through
// scanFileForLegacyDP. Any change to the production canary's
// scan is exercised by these synthetic negative-pattern tests.
//
// The fake filename "synthetic.go" never matches anything on disk,
// so the production canary's directory walk does not see this
// source. It also doesn't end in _test.go, but that's fine — the
// _test.go suffix filter applies to real files in pkg/daemon, not
// to ad-hoc strings passed to the shared helper.
func scanSyntheticSource(t *testing.T, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", src, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	return scanFileForLegacyDP(fset, file, "synthetic.go")
}

// hasOffenderOnLine returns true if the offender list contains an
// entry that starts with "synthetic.go:<line>:".
func hasOffenderOnLine(offenders []string, line int) bool {
	prefix := "synthetic.go:" + itoa(line) + ":"
	for _, o := range offenders {
		if strings.HasPrefix(o, prefix) {
			return true
		}
	}
	return false
}

// TestCanarySyntheticStructFieldReintroduction — AGY P2 / #1559.
// A sibling field on Daemon named legacyDP must trip Pass 3.
func TestCanarySyntheticStructFieldReintroduction(t *testing.T) {
	t.Parallel()
	src := `package daemon
type fakeDataPlane interface{}
type Daemon struct {
	legacyDP fakeDataPlane
}
`
	offenders := scanSyntheticSource(t, src)
	// Line 4 is the field declaration `legacyDP fakeDataPlane`.
	if !hasOffenderOnLine(offenders, 4) {
		t.Fatalf("expected struct-field reintroduction on line 4 to "+
			"trip canary; got offenders=%v", offenders)
	}
}

// TestCanarySyntheticBareSelectorRead — AGY P2 / #1559.
// `dp := d.legacyDP` (no call) must trip Pass 4.
func TestCanarySyntheticBareSelectorRead(t *testing.T) {
	t.Parallel()
	src := `package daemon
type Daemon struct{ legacyDP int }
func ExampleRead(d *Daemon) {
	dp := d.legacyDP
	_ = dp
}
`
	offenders := scanSyntheticSource(t, src)
	// Line 4 is the bare selector read `dp := d.legacyDP`.
	if !hasOffenderOnLine(offenders, 4) {
		t.Fatalf("expected bare selector read on line 4 to trip "+
			"canary; got offenders=%v", offenders)
	}
}

// TestCanarySyntheticCallSitePreserved — existing v1 behavior.
// `d.legacyDP()` must still trip Pass 2.
func TestCanarySyntheticCallSitePreserved(t *testing.T) {
	t.Parallel()
	src := `package daemon
type fakeDP struct{}
func (f *fakeDP) Probe() {}
type Daemon struct{}
func (d *Daemon) legacyDP() *fakeDP { return nil }
func ExampleCall(d *Daemon) {
	d.legacyDP().Probe()
}
`
	offenders := scanSyntheticSource(t, src)
	// Line 5 is the FuncDecl `func (d *Daemon) legacyDP() *fakeDP`.
	// Line 7 is the callsite `d.legacyDP().Probe()`.
	if !hasOffenderOnLine(offenders, 5) {
		t.Fatalf("expected FuncDecl on line 5 to trip canary; got "+
			"offenders=%v", offenders)
	}
	if !hasOffenderOnLine(offenders, 7) {
		t.Fatalf("expected callsite on line 7 to trip canary; got "+
			"offenders=%v", offenders)
	}
}

// TestCanarySyntheticPackageLevelFuncDecl — Gemini #1559
// plan-round-1 critical finding. A package-level `func legacyDP(d
// *Daemon)` must trip the receiver-agnostic Pass 1.
func TestCanarySyntheticPackageLevelFuncDecl(t *testing.T) {
	t.Parallel()
	src := `package daemon
type Daemon struct{}
func legacyDP(d *Daemon) int { return 0 }
`
	offenders := scanSyntheticSource(t, src)
	// Line 3 is the package-level `func legacyDP(d *Daemon)`.
	if !hasOffenderOnLine(offenders, 3) {
		t.Fatalf("expected package-level FuncDecl on line 3 to trip "+
			"canary; got offenders=%v", offenders)
	}
}

// TestCanarySyntheticBareIdentCallsite — Gemini #1559
// plan-round-1 critical finding. `legacyDP(d)` whose Fun is
// *ast.Ident (no SelectorExpr) must trip Pass 5.
func TestCanarySyntheticBareIdentCallsite(t *testing.T) {
	t.Parallel()
	src := `package daemon
type Daemon struct{}
func legacyDP(d *Daemon) int { return 0 }
func Caller(d *Daemon) {
	_ = legacyDP(d)
}
`
	offenders := scanSyntheticSource(t, src)
	// Line 3 trips Pass 1 (FuncDecl).
	// Line 5 is the bare callsite `_ = legacyDP(d)`.
	if !hasOffenderOnLine(offenders, 3) {
		t.Fatalf("expected FuncDecl on line 3 to trip canary; got "+
			"offenders=%v", offenders)
	}
	if !hasOffenderOnLine(offenders, 5) {
		t.Fatalf("expected bare ident callsite on line 5 to trip "+
			"canary; got offenders=%v", offenders)
	}
}

// TestCanarySyntheticCommentsAndStringsSafe — invariant from #1557.
// `legacyDP` in comments and string literals must NOT trip the
// canary, because parser.ParseFile without parser.ParseComments
// drops *ast.Comment nodes and string literals are *ast.BasicLit
// (whose Value field is a Go string, not descendent ast.Ident).
func TestCanarySyntheticCommentsAndStringsSafe(t *testing.T) {
	t.Parallel()
	src := `package daemon
// legacyDP() was deleted in #1519 (this is a comment).
/* d.legacyDP block-comment mention */
var docString = "legacyDP referenced in a string literal"
`
	offenders := scanSyntheticSource(t, src)
	if len(offenders) != 0 {
		t.Fatalf("expected zero offenders for comments + string "+
			"literals; got %v", offenders)
	}
}

// TestCanarySyntheticDedupOneOffenderPerLine — record-once
// invariant. A struct field declared on one line and read on a
// different line emits exactly ONE offender per line (not 3+),
// because the (file, line) dedup map suppresses the multi-pass
// overlap.
func TestCanarySyntheticDedupOneOffenderPerLine(t *testing.T) {
	t.Parallel()
	src := `package daemon
type Daemon struct {
	legacyDP int
}
func Reader(d *Daemon) int {
	return d.legacyDP
}
`
	offenders := scanSyntheticSource(t, src)
	// Expect 2 offenders total: line 3 (struct field) and line 6
	// (selector read). Multi-pass overlap on each line is collapsed
	// to one by the record-once dedup.
	if len(offenders) != 2 {
		t.Fatalf("expected exactly 2 offenders (one per affected "+
			"line); got %d: %v", len(offenders), offenders)
	}
	if !hasOffenderOnLine(offenders, 3) {
		t.Fatalf("expected field-decl offender on line 3; got %v",
			offenders)
	}
	if !hasOffenderOnLine(offenders, 6) {
		t.Fatalf("expected selector-read offender on line 6; got %v",
			offenders)
	}
}
