package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanFileForLegacyDP performs the 5-pass AST scan that the
// legacyDP canary contract documents. It is shared between the
// production directory-walker test (TestLegacyDPAccessorRemoved)
// and the synthetic negative-pattern tests in
// legacy_dataplane_canary_synthetic_test.go, so any change to the
// scan logic is exercised by both call sites — the synthetic tests
// genuinely defend the production canary instead of a parallel
// copy of it (Gemini #1559 code-review-round-1 finding).
//
// Passes (most-specific first; record-once dedup keyed on
// (displayName, line) selects the surviving diagnostic):
//
//  1. *ast.FuncDecl named legacyDP (any receiver shape).
//  2. *ast.StructType.Fields with Names[i] == "legacyDP".
//  3. *ast.CallExpr whose Fun is *ast.SelectorExpr with Sel.Name
//     == "legacyDP".
//  4. *ast.SelectorExpr with Sel.Name == "legacyDP" (bare reads).
//  5. *ast.Ident with Name == "legacyDP" (catch-all for
//     `legacyDP(d)` callsites whose Fun is *ast.Ident).
//
// displayName is the prefix used in offender strings (typically the
// scanned filename). The scan never recurses outside the supplied
// *ast.File.
func scanFileForLegacyDP(fset *token.FileSet, file *ast.File, displayName string) []string {
	var offenders []string
	recorded := make(map[string]bool)
	record := func(pos token.Position, msg string) {
		key := displayName + ":" + itoa(pos.Line)
		if recorded[key] {
			return
		}
		recorded[key] = true
		offenders = append(offenders, key+": "+msg)
	}

	// Pass 1 — FuncDecl name match (receiver-agnostic).
	// Closes the package-level `func legacyDP(d *Daemon)` bypass
	// (Gemini #1559 plan-round-1). Record at fd.Name.Pos() so
	// multiline func declarations land on the identifier line, not
	// the `func` keyword (Codex #1559 plan-round-2).
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Name == nil || fd.Name.Name != "legacyDP" {
			continue
		}
		pos := fset.Position(fd.Name.Pos())
		record(pos, "forbidden function/method declaration named "+
			"legacyDP — removed in #1519, see "+
			"docs/pr/1519-daemon-legacydp-shrink/plan-impl.md. "+
			"The identifier is reserved within pkg/daemon "+
			"production code.")
	}

	// Pass 3 — StructType.Fields name match. Catches a sibling
	// `legacyDP T` field reintroduction on any struct in the file
	// (not just Daemon — naming an unrelated struct's field
	// legacyDP is also blocked; the diagnostic does NOT claim
	// "Daemon field" because Pass 3 is struct-agnostic).
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
				pos := fset.Position(fname.Pos())
				record(pos, "forbidden struct field named "+
					"legacyDP — removed in #1519; the "+
					"identifier is reserved within pkg/daemon "+
					"production code. Use a typed probe in "+
					"runtime_probes.go instead.")
			}
		}
		return true
	})

	// Pass 2 — CallExpr selector match. Existing v1 shape,
	// preserved for its more actionable "forbidden call to
	// .legacyDP()" diagnostic. Record at sel.Sel.Pos() so the
	// line aligns with Pass 4 and Pass 5 for multiline
	// d.\n  legacyDP() forms.
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
		pos := fset.Position(sel.Sel.Pos())
		record(pos, "forbidden call to .legacyDP() — removed "+
			"in #1519; use a daemon-local typed probe from "+
			"runtime_probes.go instead.")
		return true
	})

	// Pass 4 — SelectorExpr name match. Catches bare reads
	// `dp := d.legacyDP`, method-values `f := d.legacyDP`, and
	// any other SelectorExpr ending in .legacyDP that is not
	// wrapped in a CallExpr.
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel == nil || sel.Sel.Name != "legacyDP" {
			return true
		}
		pos := fset.Position(sel.Sel.Pos())
		record(pos, "forbidden selector .legacyDP — removed "+
			"in #1519; do not re-introduce as a field, "+
			"method, or accessor. Use a typed probe in "+
			"runtime_probes.go instead.")
		return true
	})

	// Pass 5 — bare *ast.Ident name match. Catch-all for any
	// `legacyDP` token not already named by Pass 1-4. Closes
	// the package-level callsite bypass: `legacyDP(d)` has
	// Fun=*ast.Ident, not *ast.SelectorExpr, so Pass 2 and
	// Pass 4 do not see it. ast.Inspect walks FuncDecl.Name,
	// Field.Names, and SelectorExpr.Sel as ast.Ident, so Pass 5
	// would otherwise duplicate the other passes — record-once
	// dedup suppresses those duplicates.
	ast.Inspect(file, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name != "legacyDP" {
			return true
		}
		pos := fset.Position(ident.Pos())
		record(pos, "forbidden identifier legacyDP — removed "+
			"in #1519; the name is reserved within pkg/daemon "+
			"production code (no field, method, function, "+
			"selector, or bare identifier may use it).")
		return true
	})

	return offenders
}

// TestLegacyDPAccessorRemoved is the #1519 (sub-#1451 S4)
// regression-guard canary: it scans every non-test .go file in
// pkg/daemon and fails if the identifier `legacyDP` reappears in
// any of the AST surfaces documented on scanFileForLegacyDP.
//
// The pre-#1519 daemon used (*Daemon).legacyDP() as an escape
// hatch that re-exposed the full BPF-shaped dataplane.DataPlane to
// internal callers; the capstone PR migrated every consumer to a
// narrow typed probe (runtime_probes.go) and deleted the accessor.
// AGY adversarial review on PR #1557 (adversarial-review-mpm8y8a3-
// 8cbeh2, 2026-05-26) identified two structural bypasses in the v1
// canary — struct-field reintroduction and bare-selector reads.
// Codex+Gemini round-1 of #1559 additionally surfaced the package-
// level FuncDecl + bare-Ident-callsite bypass. The 5-pass canary
// closes all four.
//
// The identifier `legacyDP` is reserved within pkg/daemon
// production code (non-test *.go files only). The canary will fail
// on any field, method, function, selector, or bare identifier
// using this name, regardless of surrounding type or receiver. A
// future architectural review wanting to re-use the name must
// update this canary as part of that review.
//
// Comments are NOT scanned. parser.ParseFile is called without
// parser.ParseComments, so the AST does not include *ast.Comment
// nodes; mentions of legacyDP in // ... or /* ... */ blocks are
// invisible to this canary. String literals are *ast.BasicLit
// whose Value is a string, not descendent *ast.Ident — so string
// literals mentioning legacyDP are also safe.
//
// Out of scope:
//   - _test.go files (tests may legitimately want to reference
//     the symbol for documentation or to assert non-existence).
//   - Cross-package: this canary only inspects pkg/daemon/*.go.
//     The retirement-boundary canary at
//     pkg/dataplane/retirement_boundary_canary_test.go handles the
//     wider package-allowlist boundary.
//
// If a future #1451 phase or follow-up legitimately needs to
// reintroduce a legacy escape hatch, update this canary together
// with the new architectural review.
func TestLegacyDPAccessorRemoved(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read pkg/daemon dir: %v", err)
	}

	fset := token.NewFileSet()
	var offenders []string

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		offenders = append(offenders, scanFileForLegacyDP(fset, file, name)...)
	}

	if len(offenders) > 0 {
		t.Fatalf("legacyDP reintroduced in pkg/daemon production code:\n  %s\n"+
			"this symbol was removed in #1519 (sub-#1451 S4); see "+
			"docs/pr/1519-daemon-legacydp-shrink/plan-impl.md for the "+
			"migration matrix and rationale",
			strings.Join(offenders, "\n  "))
	}
}

// itoa avoids strconv import bloat for a single int->string in the
// failure message; the canary file already imports go/ast and
// path/filepath, so keeping the dep surface narrow is a wash.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
