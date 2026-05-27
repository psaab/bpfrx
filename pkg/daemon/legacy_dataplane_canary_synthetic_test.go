package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// scanSynthetic mirrors TestLegacyDPAccessorRemoved's 5-pass scan
// against an in-memory Go source string and returns the offender
// list. Keeps the canary's contract testable without writing
// disposable files to pkg/daemon — synthetic Go that intentionally
// reintroduces `legacyDP` must NOT be picked up by the real
// canary's directory scan, which is why the synthetic tests parse
// from a fixed name ("synthetic.go") that doesn't exist on disk.
//
// The function intentionally does not share code with the
// production canary — duplication is the point. If the canary's
// scan ever diverges from this scanner, the synthetic tests will
// silently miss the divergence. The synthetic tests therefore
// assert behavior the canary doc comment promises (which line gets
// recorded, no false positives on comments/strings), not the
// implementation shape.
func scanSynthetic(t *testing.T, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", src, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	var offenders []string
	recorded := make(map[string]bool)
	record := func(pos token.Position, msg string) {
		key := "synthetic.go:" + itoa(pos.Line)
		if recorded[key] {
			return
		}
		recorded[key] = true
		offenders = append(offenders, key+": "+msg)
	}

	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Name == nil || fd.Name.Name != "legacyDP" {
			continue
		}
		record(fset.Position(fd.Name.Pos()), "FuncDecl")
	}

	ast.Inspect(file, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		if st.Fields == nil {
			return true
		}
		for _, field := range st.Fields.List {
			for _, fname := range field.Names {
				if fname == nil || fname.Name != "legacyDP" {
					continue
				}
				record(fset.Position(fname.Pos()), "StructField")
			}
		}
		return true
	})

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel == nil || sel.Sel.Name != "legacyDP" {
			return true
		}
		record(fset.Position(sel.Sel.Pos()), "CallExpr")
		return true
	})

	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel == nil || sel.Sel.Name != "legacyDP" {
			return true
		}
		record(fset.Position(sel.Sel.Pos()), "SelectorExpr")
		return true
	})

	ast.Inspect(file, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name != "legacyDP" {
			return true
		}
		record(fset.Position(ident.Pos()), "Ident")
		return true
	})

	return offenders
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
	offenders := scanSynthetic(t, src)
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
	offenders := scanSynthetic(t, src)
	// Line 4 is the bare selector read `dp := d.legacyDP`.
	if !hasOffenderOnLine(offenders, 4) {
		t.Fatalf("expected bare selector read on line 4 to trip "+
			"canary; got offenders=%v", offenders)
	}
}

// TestCanarySyntheticCallSitePreserved — existing v1 behavior.
// `d.legacyDP()` must still trip Pass 2 / Pass 4.
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
	offenders := scanSynthetic(t, src)
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

// TestCanarySyntheticPackageLevelFuncDecl — Gemini #1559 round-1
// critical finding. A package-level `func legacyDP(d *Daemon)`
// must trip the receiver-agnostic Pass 1.
func TestCanarySyntheticPackageLevelFuncDecl(t *testing.T) {
	t.Parallel()
	src := `package daemon
type Daemon struct{}
func legacyDP(d *Daemon) int { return 0 }
`
	offenders := scanSynthetic(t, src)
	// Line 3 is the package-level `func legacyDP(d *Daemon)`.
	if !hasOffenderOnLine(offenders, 3) {
		t.Fatalf("expected package-level FuncDecl on line 3 to trip "+
			"canary; got offenders=%v", offenders)
	}
}

// TestCanarySyntheticBareIdentCallsite — Gemini #1559 round-1
// critical finding. `legacyDP(d)` whose Fun is *ast.Ident (no
// SelectorExpr) must trip Pass 5.
func TestCanarySyntheticBareIdentCallsite(t *testing.T) {
	t.Parallel()
	src := `package daemon
type Daemon struct{}
func legacyDP(d *Daemon) int { return 0 }
func Caller(d *Daemon) {
	_ = legacyDP(d)
}
`
	offenders := scanSynthetic(t, src)
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
	offenders := scanSynthetic(t, src)
	if len(offenders) != 0 {
		t.Fatalf("expected zero offenders for comments + string "+
			"literals; got %v", offenders)
	}
}

// TestCanarySyntheticDedupOneOffenderPerLine — record-once
// invariant. A struct field declared on one line and read on a
// different line emits ONE offender per line (not 3+), because
// the (file, line) dedup map suppresses the multi-pass overlap.
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
	offenders := scanSynthetic(t, src)
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
