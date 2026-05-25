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
// Scope:
//
// The canary has two passes (see findLegacyDataPlaneOffenders):
//
//  1. STRUCTURAL pass — produces precise diagnostics for FuncDecl
//     params/results, StructType fields/embeds, and InterfaceType
//     method params/results/embeds. Handles direct, pointer (*T),
//     variadic (...T), parenthesized ((T)), and fixed-array ([N]T)
//     disguises via isLegacyDataPlaneType.
//
//  2. CATCH-ALL selector sweep — walks every *ast.SelectorExpr in
//     the file and flags any `dataplane.DataPlane` reference the
//     structural pass did not already attribute. This closes every
//     bypass that introduces a textual `dataplane.DataPlane`
//     selector anywhere in production code: package-level / local
//     `var x dataplane.DataPlane`, `&dataplane.DataPlane{}` composite
//     literals, `func(dp dataplane.DataPlane){}` closures, `type X
//     dataplane.DataPlane` type definitions, and any future syntactic
//     context this canary's structural switch hasn't enumerated.
//
// Known #1548-deferred bypasses (require go/types-level resolution):
//   - Generic types: `T dataplane.DataPlane` constraints,
//     `Generic[dataplane.DataPlane]` instantiations
//   - Type aliases: `type DPAlias = dataplane.DataPlane`, transitive
//     uses where the alias is then referenced as a bare Ident
//   - Import renames: `import dp "github.com/psaab/xpf/pkg/dataplane"`
//     causing the selector to read `dp.DataPlane` not
//     `dataplane.DataPlane`
//
// Compound shapes (`[]T`, `map[K]T`, `chan T`, `func(T)`) are now
// caught by the catch-all sweep because they still contain a literal
// `dataplane.DataPlane` selector in their AST.
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

		offenders = append(offenders, findLegacyDataPlaneOffenders(file, name)...)
	}

	if len(offenders) > 0 {
		t.Fatalf("pkg/conntrack production code must not depend on dataplane.DataPlane; #1451 retirement canary; offenders:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// findLegacyDataPlaneOffenders walks file's AST and returns a list of
// offender strings tagged with origin. It implements the production
// canary's matching logic in one place so the main canary
// (TestConntrackHasNoLegacyDataPlaneDependency) AND the synthetic
// regression test (TestProductionWalker*) drive the SAME walker — a
// future refactor that drops an arm here is caught by both.
//
// The walker has two passes:
//
//  1. Structural pass — inspects FuncDecl param/result, StructType
//     fields/embeds, and InterfaceType method param/result/embed.
//     This produces precise diagnostics that name the function /
//     field / method holding the prohibited type.
//
//  2. Catch-all selector sweep — walks EVERY *ast.SelectorExpr in
//     the file and flags any `dataplane.DataPlane` reference that
//     the structural pass did not already attribute. This closes the
//     bypass vectors AGY adversarial-review (#1532 round-N) flagged:
//     package-level / function-local `var x dataplane.DataPlane`,
//     `&dataplane.DataPlane{}` composite literals, `func(dp
//     dataplane.DataPlane){}` closures, and `type X
//     dataplane.DataPlane` type definitions. Any direct selector
//     `dataplane.DataPlane` anywhere in the file produces an
//     offender, even if the structural pass missed it.
//
// Documented #1548-deferred bypasses (compound `[]T`, `map[K]T`,
// `chan T`, `func(T)`, generics, type aliases, import renames)
// remain out of scope because they require go/types-level import
// resolution.
func findLegacyDataPlaneOffenders(file *ast.File, name string) []string {
	var offenders []string

	// Pass 1: structural walker (detailed diagnostics).
	structuralHits := make(map[token.Pos]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Type.Params != nil {
				for _, field := range node.Type.Params.List {
					if isLegacyDataPlaneType(field.Type) {
						offenders = append(offenders, name+": func "+funcDeclName(node)+" parameter is dataplane.DataPlane")
						markSelectorPositions(field.Type, structuralHits)
					}
				}
			}
			if node.Type.Results != nil {
				for _, field := range node.Type.Results.List {
					if isLegacyDataPlaneType(field.Type) {
						offenders = append(offenders, name+": func "+funcDeclName(node)+" result is dataplane.DataPlane")
						markSelectorPositions(field.Type, structuralHits)
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
				markSelectorPositions(field.Type, structuralHits)
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
								markSelectorPositions(field.Type, structuralHits)
							}
						}
					}
					if mt.Results != nil {
						for _, field := range mt.Results.List {
							if isLegacyDataPlaneType(field.Type) {
								offenders = append(offenders, name+": interface method "+methodName+" result is dataplane.DataPlane")
								markSelectorPositions(field.Type, structuralHits)
							}
						}
					}
				default:
					if isLegacyDataPlaneType(method.Type) {
						offenders = append(offenders, name+": interface embed "+methodName+" is dataplane.DataPlane")
						markSelectorPositions(method.Type, structuralHits)
					}
				}
			}
		}
		return true
	})

	// Pass 2: catch-all selector sweep — flag any dataplane.DataPlane
	// selector the structural pass did not already attribute. Closes
	// the bypass vectors AGY adversarial-review #1532 round-N flagged
	// (package-level / local `var x dataplane.DataPlane`,
	// `&dataplane.DataPlane{}` composite literals, `func(dp
	// dataplane.DataPlane){}` closures, `type X dataplane.DataPlane`
	// type definitions).
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkg.Name != "dataplane" || sel.Sel.Name != "DataPlane" {
			return true
		}
		if structuralHits[sel.Pos()] {
			return true
		}
		offenders = append(offenders, name+": dataplane.DataPlane referenced (catch-all sweep — declaration/closure/composite/type-def bypass)")
		return true
	})

	return offenders
}

// markSelectorPositions records the token positions of every
// `dataplane.DataPlane` *ast.SelectorExpr underneath expr, so the
// pass-2 catch-all sweep can skip selectors the structural pass
// already attributed.
func markSelectorPositions(expr ast.Expr, hits map[token.Pos]bool) {
	ast.Inspect(expr, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkg.Name == "dataplane" && sel.Sel.Name == "DataPlane" {
			hits[sel.Pos()] = true
		}
		return true
	})
}

// isLegacyDataPlaneType returns true when expr names dataplane.DataPlane
// or *dataplane.DataPlane. Star-prefixed shapes are checked because
// future migrations may introduce a pointer form before someone notices.
// Ellipsis-prefixed (`...dataplane.DataPlane` for variadic params),
// parenthesized (`(dataplane.DataPlane)`), and fixed-array
// (`[N]dataplane.DataPlane`) forms are also unwrapped so a syntactic
// disguise can't bypass the fence. Slice (`[]T`), map, chan, and
// generic instantiations remain documented #1548-deferred bypasses
// because matching them naively would also flag external compound
// shapes that are out of scope for this canary.
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
	case *ast.ArrayType:
		// Fixed-size arrays (`[1]dataplane.DataPlane`) are unwrapped.
		// Slices (`[]dataplane.DataPlane`, Len==nil) remain a
		// documented #1548-deferred bypass — recognising slices here
		// would entangle this canary with broader compound-type
		// resolution that needs go/types.
		if e.Len == nil {
			return false
		}
		return isLegacyDataPlaneType(e.Elt)
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
		{"fixed-array",
			&ast.ArrayType{Len: &ast.BasicLit{Kind: token.INT, Value: "3"}, Elt: dpSel},
			true},
		// Slice (Len == nil) is a documented #1548-deferred bypass —
		// must NOT match here.
		{"slice-deferred", &ast.ArrayType{Len: nil, Elt: dpSel}, false},
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

// TestProductionWalkerCatchesCanaryShapes drives the SAME production
// walker (findLegacyDataPlaneOffenders) that the main canary uses
// against synthetic Go source text parsed via parser.ParseFile.
// Each subcase asserts a specific shape produces the expected
// offender entry. A future regression that drops any arm of the
// walker (e.g. the `*ast.FuncType` case in the `*ast.InterfaceType`
// switch) will cause the relevant subcase to fail.
func TestProductionWalkerCatchesCanaryShapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		source     string
		wantSubstr string // expected substring in at least one offender
	}{
		{
			name: "func-param-direct",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func Foo(dp dataplane.DataPlane) {}
`,
			wantSubstr: "func Foo parameter is dataplane.DataPlane",
		},
		{
			name: "func-param-pointer",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func Foo(dp *dataplane.DataPlane) {}
`,
			wantSubstr: "func Foo parameter is dataplane.DataPlane",
		},
		{
			name: "func-param-variadic",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func Foo(dps ...dataplane.DataPlane) {}
`,
			wantSubstr: "func Foo parameter is dataplane.DataPlane",
		},
		{
			name: "func-result-paren",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func Foo() (dataplane.DataPlane) { var x dataplane.DataPlane; return x }
`,
			wantSubstr: "func Foo result is dataplane.DataPlane",
		},
		{
			name: "struct-field",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
type S struct { Dp dataplane.DataPlane }
`,
			wantSubstr: "struct field Dp is dataplane.DataPlane",
		},
		{
			name: "struct-embed",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
type S struct { dataplane.DataPlane }
`,
			wantSubstr: "struct embeds dataplane.DataPlane",
		},
		{
			name: "interface-method-param",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
type I interface { Foo(dp dataplane.DataPlane) }
`,
			wantSubstr: "interface method Foo parameter is dataplane.DataPlane",
		},
		{
			name: "interface-method-result",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
type I interface { Bar() dataplane.DataPlane }
`,
			wantSubstr: "interface method Bar result is dataplane.DataPlane",
		},
		{
			name: "interface-method-variadic",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
type I interface { Baz(dps ...dataplane.DataPlane) }
`,
			wantSubstr: "interface method Baz parameter is dataplane.DataPlane",
		},
		{
			name: "interface-embed",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
type I interface { dataplane.DataPlane }
`,
			// Embedded types have no method name; production walker
			// labels them <anonymous>. This is intentional — embedding
			// is still caught and reported, just without a name.
			wantSubstr: "interface embed <anonymous> is dataplane.DataPlane",
		},
		{
			name: "func-param-fixed-array",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func Foo(dps [1]dataplane.DataPlane) {}
`,
			wantSubstr: "func Foo parameter is dataplane.DataPlane",
		},
		{
			name: "struct-field-fixed-array",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
type S struct { Dps [2]dataplane.DataPlane }
`,
			wantSubstr: "struct field Dps is dataplane.DataPlane",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", tc.source, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			got := findLegacyDataPlaneOffenders(file, "fixture.go")
			if len(got) == 0 {
				t.Fatalf("findLegacyDataPlaneOffenders returned no offenders; want one containing %q", tc.wantSubstr)
			}
			match := false
			for _, off := range got {
				if strings.Contains(off, tc.wantSubstr) {
					match = true
					break
				}
			}
			if !match {
				t.Fatalf("no offender contains %q; got %v", tc.wantSubstr, got)
			}
		})
	}
}

// TestProductionWalkerIgnoresUnrelatedTypes asserts the production
// walker has no false positives on the same selectors that appear in
// pkg/conntrack/ today (dataplane.SessionStore, dataplane.Telemetry,
// dataplane.Sessions, etc.), bare local identifiers named DataPlane,
// or non-dataplane package selectors.
func TestProductionWalkerIgnoresUnrelatedTypes(t *testing.T) {
	t.Parallel()

	source := `package fixture
import (
	"context"
	"github.com/psaab/xpf/pkg/dataplane"
)
func A(s dataplane.SessionStore) {}
func B(t dataplane.Telemetry) dataplane.Sessions { return nil }
func C(ctx context.Context) {}
type T struct {
	store dataplane.SessionStore
	tel   dataplane.Telemetry
}
type I interface {
	Sessions() dataplane.Sessions
	Telemetry() dataplane.Telemetry
}
type DataPlane = int
var d DataPlane
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", source, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	got := findLegacyDataPlaneOffenders(file, "fixture.go")
	if len(got) != 0 {
		t.Fatalf("findLegacyDataPlaneOffenders returned unexpected offenders on clean code: %v", got)
	}
}

// TestProductionWalkerCatchAllSweepClosesAGYBypasses asserts the
// catch-all selector sweep (pass 2 of findLegacyDataPlaneOffenders)
// catches the bypass categories AGY adversarial-review flagged on PR
// #1532: package-level var, function-local var, closure, composite
// literal, type definition, and the compound types ([]T, map, chan,
// func) that were previously documented as #1548-deferred.
func TestProductionWalkerCatchAllSweepClosesAGYBypasses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		source string
	}{
		{
			name: "package-level-var",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
var GlobalDP *dataplane.DataPlane
`,
		},
		{
			name: "local-var-decl",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func Touch() { var dp *dataplane.DataPlane; _ = dp }
`,
		},
		{
			name: "closure-param",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
var Handler = func(dp dataplane.DataPlane) {}
`,
		},
		{
			name: "composite-literal",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func Make() { _ = &dataplane.DataPlane{} }
`,
		},
		{
			name: "type-definition",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
type LocalDP dataplane.DataPlane
`,
		},
		{
			name: "slice-compound",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func Slice(dps []dataplane.DataPlane) {}
`,
		},
		{
			name: "map-compound",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func MapV(m map[string]dataplane.DataPlane) {}
`,
		},
		{
			name: "chan-compound",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func ChanV(c chan dataplane.DataPlane) {}
`,
		},
		{
			name: "func-type-arg",
			source: `package fixture
import "github.com/psaab/xpf/pkg/dataplane"
func FnArg(f func(dataplane.DataPlane)) {}
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", tc.source, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			got := findLegacyDataPlaneOffenders(file, "fixture.go")
			if len(got) == 0 {
				t.Fatalf("expected catch-all sweep to flag %s but got zero offenders", tc.name)
			}
		})
	}
}
