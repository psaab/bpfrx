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
//
// Codex PR #6743 r4-F5: a direct d.dpCell.Load()/Store() outside the
// accessors is NOT "unsynchronized" — atomic operations are synchronized
// by definition, and that was the wrong reason to forbid them. The real
// reasons are that a raw Store bypasses setDataplane's kind-gated
// typed-nil normalization (publishing a non-nil interface wrapping a nil
// value), and a raw Load bypasses the §5.3 snapshot-boundary discipline
// that keeps one publication view per tick/callback/block. Either failure
// is silent at runtime, so it fails the build here the same way the
// retirement-boundary canary fails a legacy eBPF reference
// (pkg/dataplane/retirement_boundary_canary_test.go).
//
// This canary is a SYNTACTIC fence over the accessor boundary, and it
// matches on the `.dpCell` SELECTOR — so it is deliberately blind to a
// re-added plain `dp dataplane.RuntimeDataPlane` field, which has no such
// selector at all. That case is covered by checkDaemonDPFieldShape
// (pkg/dataplane/retirement_boundary_canary_test.go), which parses the
// real pkg/daemon/daemon.go and rejects both a missing
// `dpCell atomic.Pointer[dpSlot]` and any raw RuntimeDataPlane field.
//
// It also says nothing about what happens to a handle once dataplane()
// has returned it — that is the escape question, guarded behaviourally in
// daemon_dp_escape_test.go / daemon_dp_escape_rest_test.go and
// syntactically in daemon_dp_escape_canary_test.go.

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
		// selector can be attributed to its enclosing function. The match
		// must be a *Daemon method — a same-named function or a method on
		// another type is NOT the accessor (Codex PR #6743 r2-2: a
		// compile-valid `func (bypass) setDataplane(...)` on an unrelated
		// type otherwise bypasses the typed-nil normalization and the
		// single-writer contract).
		type fnSpan struct {
			name      string
			body      *ast.BlockStmt
			isDaemonM bool
		}
		var fns []fnSpan
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				span := fnSpan{name: fn.Name.Name, body: fn.Body}
				if fn.Recv != nil && len(fn.Recv.List) == 1 {
					if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
						if id, ok := star.X.(*ast.Ident); ok && id.Name == "Daemon" {
							span.isDaemonM = true
						}
					}
				}
				fns = append(fns, span)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "dpCell" {
				return true
			}
			enclosing := "<file scope>"
			isAccessor := false
			for _, fn := range fns {
				if fn.body.Pos() <= sel.Pos() && sel.Pos() < fn.body.End() {
					enclosing = fn.name
					isAccessor = fn.isDaemonM && dpCellAccessorFuncs[fn.name]
					break
				}
			}
			if !isAccessor {
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
	typeCollision := clean + `
type bypass struct{}

func (b bypass) setDataplane(d *Daemon, v int) {
	d.dpCell.Store(&dpSlot{v: v})
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

	// The cross-type name-collision fixture must also fail: a setDataplane
	// method on an unrelated type is not the accessor.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "clean.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("write clean fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "collision.go"), []byte(typeCollision), 0o644); err != nil {
		t.Fatalf("write collision fixture: %v", err)
	}
	violations2 := dpCellBypassViolations(t, dir2)
	if len(violations2) != 1 || !strings.Contains(violations2[0], "collision.go") {
		t.Fatalf("type-collision fixture violations = %v, want exactly one in collision.go", violations2)
	}
}
