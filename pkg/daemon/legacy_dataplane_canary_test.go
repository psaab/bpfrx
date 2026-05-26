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

// TestLegacyDPAccessorRemoved is the #1519 (sub-#1451 S4)
// regression-guard canary: it scans every non-test .go file in
// pkg/daemon and fails if a method declaration with name
// legacyDP and receiver *Daemon reappears, OR if any call
// expression of the form receiver.legacyDP() reappears.
//
// The pre-#1519 daemon used (*Daemon).legacyDP() as an escape
// hatch that re-exposed the full BPF-shaped dataplane.DataPlane
// to internal callers; the capstone PR migrated every consumer
// to a narrow typed probe (runtime_probes.go) and deleted the
// accessor. This canary keeps a quiet "I'll just add it back"
// refactor from undoing the boundary work.
//
// Comments are NOT scanned. The pre-#1519 audit and migration
// notes in plan-impl.md / commit messages explicitly mention
// the historical legacyDP() symbol; only AST occurrences in
// real Go code are forbidden.
//
// Scope:
//   - FuncDecl named "legacyDP" with receiver type *Daemon (any
//     other method name is fine; the canary doesn't gate against
//     adding a different escape hatch — that's a separate
//     architectural review).
//   - CallExpr where the SelectorExpr.Sel.Name == "legacyDP"
//     (catches d.legacyDP(), x.daemon.legacyDP(), and any other
//     receiver chain that ends in a call to .legacyDP).
//
// Out of scope:
//   - Comments / docstrings / string literals (no false positives
//     for plan-impl.md or audit references in *.go file
//     comments).
//   - _test.go files (tests may legitimately want to reference
//     the symbol for documentation or to assert non-existence).
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

		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fd.Name == nil || fd.Name.Name != "legacyDP" {
				continue
			}
			if !receiverIsDaemon(fd.Recv) {
				continue
			}
			pos := fset.Position(fd.Pos())
			offenders = append(offenders,
				name+":"+itoa(pos.Line)+": forbidden method declaration "+
					"(*Daemon).legacyDP — removed in #1519, see plan-impl.md")
		}

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
			pos := fset.Position(call.Pos())
			offenders = append(offenders,
				name+":"+itoa(pos.Line)+": forbidden call to .legacyDP() — "+
					"removed in #1519; use a daemon-local typed probe from "+
					"runtime_probes.go instead")
			return true
		})
	}

	if len(offenders) > 0 {
		t.Fatalf("legacyDP() reintroduced in pkg/daemon production code:\n  %s\n"+
			"this symbol was removed in #1519 (sub-#1451 S4); see "+
			"docs/pr/1519-daemon-legacydp-shrink/plan-impl.md for the "+
			"migration matrix and rationale",
			strings.Join(offenders, "\n  "))
	}
}

func receiverIsDaemon(recv *ast.FieldList) bool {
	if recv == nil || len(recv.List) != 1 {
		return false
	}
	expr := recv.List[0].Type
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		// Value receiver (Daemon) — also forbidden.
		ident, ok := expr.(*ast.Ident)
		return ok && ident.Name == "Daemon"
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "Daemon"
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
