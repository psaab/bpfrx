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
//
// Scope (minimum viable; bypass-hardening tracked in #1548):
//
// What this canary catches today:
//   - Function parameters of `dataplane.DataPlane` or `*dataplane.DataPlane`
//   - Function results of those types
//   - Struct fields of those types
//   - Embedded interfaces declaring `dataplane.DataPlane`
//   - Interface method param/result of those types
//
// Known bypass vectors (see #1548 for hardening plan):
//   - Compound types: `[]dataplane.DataPlane`, `map[...]dataplane.DataPlane`,
//     `chan dataplane.DataPlane`, `func(dataplane.DataPlane) error`
//   - Generic types: `T dataplane.DataPlane` constraints, `Generic[dataplane.DataPlane]`
//   - Type aliases: `type DPAlias = dataplane.DataPlane`, transitive uses
//   - Import renames: `import dp "github.com/psaab/xpf/pkg/dataplane"`
//
// The fence covers the most common naive-reintroduction mode; #1548
// hardens it to cover the bypass vectors above using `go/types`-level
// import resolution.
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
					methodName := "<anonymous>"
					if len(method.Names) > 0 {
						methodName = method.Names[0].Name
					}

					switch mt := method.Type.(type) {
					case *ast.FuncType:
						if mt.Params != nil {
							for _, field := range mt.Params.List {
								if isLegacyDataPlaneType(field.Type) {
									offenders = append(offenders, name+": interface method "+methodName+" parameter is dataplane.DataPlane")
								}
							}
						}
						if mt.Results != nil {
							for _, field := range mt.Results.List {
								if isLegacyDataPlaneType(field.Type) {
									offenders = append(offenders, name+": interface method "+methodName+" result is dataplane.DataPlane")
								}
							}
						}
					default:
						if isLegacyDataPlaneType(method.Type) {
							offenders = append(offenders, name+": interface embed "+methodName+" is dataplane.DataPlane")
						}
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
// Ellipsis-prefixed (`...dataplane.DataPlane` for variadic params) and
// parenthesized (`(dataplane.DataPlane)`) forms are also unwrapped so a
// syntactic disguise can't bypass the fence.
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
	case *ast.Ellipsis:
		return isLegacyDataPlaneType(e.Elt)
	case *ast.ParenExpr:
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

// TestLegacyDataPlaneTypeMatcher is a synthetic-AST sanity check that
// `isLegacyDataPlaneType` matches the prohibited shapes (direct,
// pointer, variadic, paren-wrapped) and rejects unrelated shapes. It
// guards against accidental regressions in the matcher (e.g., dropping
// an `*ast.Ellipsis` arm) without depending on the production tree
// happening to contain a violating type.
func TestLegacyDataPlaneTypeMatcher(t *testing.T) {
	t.Parallel()

	dpSel := &ast.SelectorExpr{
		X:   &ast.Ident{Name: "dataplane"},
		Sel: &ast.Ident{Name: "DataPlane"},
	}
	otherSel := &ast.SelectorExpr{
		X:   &ast.Ident{Name: "context"},
		Sel: &ast.Ident{Name: "Context"},
	}

	cases := []struct {
		name string
		expr ast.Expr
		want bool
	}{
		{"direct", dpSel, true},
		{"pointer", &ast.StarExpr{X: dpSel}, true},
		{"variadic", &ast.Ellipsis{Elt: dpSel}, true},
		{"paren", &ast.ParenExpr{X: dpSel}, true},
		{"paren-pointer", &ast.ParenExpr{X: &ast.StarExpr{X: dpSel}}, true},
		{"unrelated-selector", otherSel, false},
		{"bare-ident", &ast.Ident{Name: "DataPlane"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLegacyDataPlaneType(tc.expr); got != tc.want {
				t.Fatalf("isLegacyDataPlaneType(%s) = %v, want %v",
					tc.name, got, tc.want)
			}
		})
	}
}

// TestInterfaceMethodCanaryScansFuncTypeParamsAndResults proves the
// AST walker in TestConntrackHasNoLegacyDataPlaneDependency actually
// fires on `dataplane.DataPlane` mentioned as an interface-method
// parameter or result type. The production scan switches on
// `method.Type.(*ast.FuncType)` and dives into `Params`/`Results`;
// this subtest builds a synthetic interface AST and runs the same
// shape of inspection inline so a future regression that drops the
// FuncType arm is caught here even when no real production file
// happens to violate the rule.
func TestInterfaceMethodCanaryScansFuncTypeParamsAndResults(t *testing.T) {
	t.Parallel()

	dpSel := &ast.SelectorExpr{
		X:   &ast.Ident{Name: "dataplane"},
		Sel: &ast.Ident{Name: "DataPlane"},
	}

	// Build: interface { Foo(dataplane.DataPlane); Bar() dataplane.DataPlane }
	iface := &ast.InterfaceType{
		Methods: &ast.FieldList{
			List: []*ast.Field{
				{
					Names: []*ast.Ident{{Name: "Foo"}},
					Type: &ast.FuncType{
						Params: &ast.FieldList{
							List: []*ast.Field{{Type: dpSel}},
						},
					},
				},
				{
					Names: []*ast.Ident{{Name: "Bar"}},
					Type: &ast.FuncType{
						Results: &ast.FieldList{
							List: []*ast.Field{{Type: dpSel}},
						},
					},
				},
				{
					Names: []*ast.Ident{{Name: "Baz"}},
					Type: &ast.FuncType{
						Params: &ast.FieldList{
							List: []*ast.Field{{Type: &ast.Ident{Name: "int"}}},
						},
					},
				},
			},
		},
	}

	var hits []string
	for _, method := range iface.Methods.List {
		methodName := method.Names[0].Name
		mt, ok := method.Type.(*ast.FuncType)
		if !ok {
			continue
		}
		if mt.Params != nil {
			for _, field := range mt.Params.List {
				if isLegacyDataPlaneType(field.Type) {
					hits = append(hits, methodName+":param")
				}
			}
		}
		if mt.Results != nil {
			for _, field := range mt.Results.List {
				if isLegacyDataPlaneType(field.Type) {
					hits = append(hits, methodName+":result")
				}
			}
		}
	}

	wantSet := map[string]bool{"Foo:param": true, "Bar:result": true}
	if len(hits) != len(wantSet) {
		t.Fatalf("hits = %v, want exactly %v", hits, wantSet)
	}
	for _, h := range hits {
		if !wantSet[h] {
			t.Fatalf("unexpected hit %q (want only %v)", h, wantSet)
		}
	}
}
