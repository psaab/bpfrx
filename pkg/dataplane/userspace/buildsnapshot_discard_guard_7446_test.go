package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #7446: the discarding form must not come back.
//
// The population was 44 call sites across 16 files, all of the shape
// `snap, _ := buildSnapshot(...)` followed by a dereference. Re-introducing one
// is a two-character edit, and nothing about the result looks wrong until a
// build failure turns it into a SIGSEGV that aborts the whole test binary. A
// population that large is not policed by review attention.
//
// The scan is over the AST rather than the text, so a comment showing the bad
// form — including the ones in this file and in the helper file — can neither
// satisfy nor trip it.
//
// Scoped to the three POINTER-returning builders. The sibling builders return
// slices and maps, where a nil result reads back safely, so a discarded error
// there is a vacuity smell and not this crash; sweeping them here would flag
// call sites that cannot exhibit the defect.
var pointerSnapshotBuilders7446 = map[string]struct{}{
	"buildSnapshot":                                 {},
	"buildSnapshotWithSchedulerState":               {},
	"buildSnapshotWithSchedulerStateAndNATCounters": {},
}

func TestNoDiscardedSnapshotBuildErrors_7446(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}

	fset := token.NewFileSet()
	var offenders []string
	filesScanned, callsSeen := 0, 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		filesScanned++

		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if _, tracked := pointerSnapshotBuilders7446[fn.Name]; !tracked {
				return true
			}
			callsSeen++
			// The error is the LAST result. Discarding it means the final
			// left-hand side is the blank identifier.
			last, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
			if ok && last.Name == "_" {
				offenders = append(offenders,
					filepath.Base(fset.Position(assign.Pos()).String())+": "+fn.Name)
			}
			return true
		})
	}

	// Vacuity, both halves. A scan that read no files, or that read them and
	// recognised no builder call, would report "no offenders" for the wrong
	// reason — and this guard's whole value is the absence it asserts.
	if filesScanned < 50 {
		t.Fatalf("scanned only %d test files; the guard is not reading the package", filesScanned)
	}
	if callsSeen == 0 {
		t.Fatal("scanned the package and recognised no pointer-returning snapshot " +
			"builder call at all — the guard would report clean no matter what")
	}

	if len(offenders) > 0 {
		t.Errorf("%d call site(s) discard the error from a pointer-returning snapshot "+
			"builder and can dereference nil, which SIGSEGVs the whole test binary "+
			"(#7446). Use mustBuildSnapshot / mustBuildSnapshotWithSchedulerState:\n\t%s",
			len(offenders), strings.Join(offenders, "\n\t"))
	}
}
