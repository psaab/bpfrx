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

// #2114: the runtime dataplane is published ONLY through the dpCell
// atomic.Pointer, and the cell is touched ONLY by the dataplane() /
// setDataplane() accessor pair (plus the Daemon struct field declaration).
// A package-local bypass — a new direct d.dpCell.Load()/Store() outside
// the accessors — would reintroduce an unsynchronized publication path
// with none of the §5.3 snapshot-boundary discipline, so it fails the
// build here the same way the retirement-boundary canary fails a legacy
// eBPF reference (pkg/dataplane/retirement_boundary_canary_test.go).

// dpCellAccessorFuncs names the ONLY functions permitted to reference the
// dpCell field selector.
var dpCellAccessorFuncs = map[string]bool{
	"dataplane":    true,
	"setDataplane": true,
}

// dpCellBypassViolations parses every production .go file under root and
// reports each `.dpCell` selector reference whose enclosing function is not
// one of dpCellAccessorFuncs.
func dpCellBypassViolations(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(root, name)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		// Map every function declaration's body span to its name so a
		// selector can be attributed to its enclosing function.
		type fnSpan struct {
			name string
			body *ast.BlockStmt
		}
		var fns []fnSpan
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				fns = append(fns, fnSpan{name: fn.Name.Name, body: fn.Body})
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "dpCell" {
				return true
			}
			enclosing := "<file scope>"
			for _, fn := range fns {
				if fn.body.Pos() <= sel.Pos() && sel.Pos() < fn.body.End() {
					enclosing = fn.name
					break
				}
			}
			if !dpCellAccessorFuncs[enclosing] {
				pos := fset.Position(sel.Pos())
				violations = append(violations,
					name+":"+pos.String()+" references .dpCell outside the dataplane()/setDataplane() accessors (in "+enclosing+")")
			}
			return true
		})
	}
	return violations
}

// TestDaemonDataplaneCellAccessorBoundary forbids direct dpCell access
// outside the accessor pair across the whole package.
func TestDaemonDataplaneCellAccessorBoundary(t *testing.T) {
	t.Parallel()

	if violations := dpCellBypassViolations(t, "."); len(violations) > 0 {
		t.Fatalf("direct dpCell access outside the #2114 accessors:\n%s", strings.Join(violations, "\n"))
	}
}

// TestDaemonDataplaneCellAccessorBoundarySelfTest drives the violation
// scanner over synthetic fixtures in BOTH directions: an accessor-only
// file is clean, and a file with a bypass method reports the violation.
func TestDaemonDataplaneCellAccessorBoundarySelfTest(t *testing.T) {
	t.Parallel()

	clean := `package daemon

import "sync/atomic"

type dpSlot struct{ v int }

type Daemon struct {
	dpCell atomic.Pointer[dpSlot]
}

func (d *Daemon) dataplane() int {
	if s := d.dpCell.Load(); s != nil {
		return s.v
	}
	return 0
}

func (d *Daemon) setDataplane(v int) {
	d.dpCell.Store(&dpSlot{v: v})
}
`
	bypass := clean + `
func (d *Daemon) sneaky() int {
	return d.dpCell.Load().v
}
`

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("write clean fixture: %v", err)
	}
	if violations := dpCellBypassViolations(t, dir); len(violations) > 0 {
		t.Fatalf("accessor-only fixture reported violations: %v", violations)
	}
	if err := os.WriteFile(filepath.Join(dir, "bypass.go"), []byte(bypass), 0o644); err != nil {
		t.Fatalf("write bypass fixture: %v", err)
	}
	violations := dpCellBypassViolations(t, dir)
	if len(violations) != 1 || !strings.Contains(violations[0], "sneaky") {
		t.Fatalf("bypass fixture violations = %v, want exactly one naming sneaky", violations)
	}
}
