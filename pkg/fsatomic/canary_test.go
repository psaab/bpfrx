package fsatomic

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// migratedPackages are the persistence-bearing packages whose direct
// os.WriteFile calls were classified and migrated to fsatomic in #1894.
// A new direct call in one of them is either a misclassified writer or
// an unreviewed durability decision — extend the allowlist ONLY for the
// BestEffortKernelKnob class (procfs/sysfs, where rename is impossible)
// or a writer explicitly adjudicated in review.
var migratedPackages = []string{
	"../configstore",
	"../frr",
	"../ipsec",
	"../dhcpserver",
	"../networkd",
	"../dhcp",
}

// allowedFunctions may keep direct os.WriteFile calls, keyed by
// enclosing function name.
var allowedFunctions = map[string]string{
	// procfs knob: rename(2) does not exist on procfs, the fsatomic
	// writers are impossible by construction (BestEffortKernelKnob).
	"restoreSlowPathRPFilter": "procfs rp_filter knob",
}

// TestNoDirectOsWriteFileInMigratedPackages is the #1894 canary. It
// parses production (non-test) sources with go/ast — not grep — so
// comments can mention os.WriteFile freely and import aliases of the
// os package are still caught.
func TestNoDirectOsWriteFileInMigratedPackages(t *testing.T) {
	var violations []string

	for _, dir := range migratedPackages {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, file, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", file, err)
			}

			// Resolve the local identifier of the "os" import,
			// including aliases. Dot-imports of os would defeat the
			// selector match — reject them outright.
			osName := ""
			for _, imp := range f.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if path != "os" {
					continue
				}
				osName = "os"
				if imp.Name != nil {
					osName = imp.Name.Name
					if osName == "." {
						violations = append(violations,
							fmt.Sprintf("%s: dot-import of os defeats the WriteFile canary", file))
					}
				}
			}
			if osName == "" || osName == "_" || osName == "." {
				continue
			}

			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if _, allowed := allowedFunctions[fn.Name.Name]; allowed {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "WriteFile" {
						return true
					}
					ident, ok := sel.X.(*ast.Ident)
					if !ok || ident.Name != osName {
						return true
					}
					violations = append(violations, fmt.Sprintf(
						"%s: direct %s.WriteFile in %s — classify it (DurableState -> fsatomic.WriteFileDurable, AtomicGeneratedConfig -> fsatomic.WriteFileAtomic, BestEffortKernelKnob -> allowlist here with justification); see docs/engineering-style.md 'Persistence classes' (#1894)",
						fset.Position(call.Pos()), osName, fn.Name.Name))
					return true
				})
			}
		}
	}

	for _, v := range violations {
		t.Error(v)
	}
}
