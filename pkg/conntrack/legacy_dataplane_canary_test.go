package conntrack

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConntrackHasNoLegacyDataPlaneDependency is the #1451 retirement
// canary for pkg/conntrack. The garbage collector has already migrated
// to runtime-domain providers (SessionStore, Telemetry,
// sessionCountPublisher, persistentNATProvider); this canary prevents
// a future refactor from quietly re-introducing a parameter, result,
// field, or embedded type of dataplane.DataPlane in production code.
//
// Test files are intentionally excluded — they may legitimately
// reference dataplane.DataPlane to assert non-implementation, the
// same pattern as pkg/dataplane/userspace/manager_coupling_test.go.
func TestConntrackHasNoLegacyDataPlaneDependency(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	var offenders []string

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// Skip *_test.go — see godoc above.
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				if node.Type.Params != nil {
					for _, field := range node.Type.Params.List {
						if isLegacyDataPlaneType(field.Type) {
							offenders = append(offenders, name+": func "+funcDeclName(node)+" parameter is dataplane.DataPlane")
						}
					}
				}
				if node.Type.Results != nil {
					for _, field := range node.Type.Results.List {
						if isLegacyDataPlaneType(field.Type) {
							offenders = append(offenders, name+": func "+funcDeclName(node)+" result is dataplane.DataPlane")
						}
					}
				}
			case *ast.StructType:
				if node.Fields == nil {
					return true
				}
				for _, field := range node.Fields.List {
					if !isLegacyDataPlaneType(field.Type) {
						continue
					}
					if len(field.Names) == 0 {
						offenders = append(offenders, name+": struct embeds dataplane.DataPlane")
					} else {
						for _, ident := range field.Names {
							offenders = append(offenders, name+": struct field "+ident.Name+" is dataplane.DataPlane")
						}
					}
				}
			case *ast.InterfaceType:
				if node.Methods == nil {
					return true
				}
				for _, method := range node.Methods.List {
					if isLegacyDataPlaneType(method.Type) {
						methodName := "<anonymous>"
						if len(method.Names) > 0 {
							methodName = method.Names[0].Name
						}
						offenders = append(offenders, name+": interface method "+methodName+" mentions dataplane.DataPlane")
					}
				}
			}
			return true
		})
	}

	if len(offenders) > 0 {
		t.Fatalf("pkg/conntrack production code must not depend on dataplane.DataPlane; #1451 retirement canary; offenders:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// isLegacyDataPlaneType returns true when expr names dataplane.DataPlane
// or *dataplane.DataPlane. Star-prefixed shapes are checked because
// future migrations may introduce a pointer form before someone notices.
func isLegacyDataPlaneType(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := e.X.(*ast.Ident)
		if !ok {
			return false
		}
		return pkg.Name == "dataplane" && e.Sel.Name == "DataPlane"
	case *ast.StarExpr:
		return isLegacyDataPlaneType(e.X)
	default:
		return false
	}
}

func funcDeclName(fn *ast.FuncDecl) string {
	if fn == nil || fn.Name == nil {
		return "<anonymous>"
	}
	return fn.Name.Name
}
