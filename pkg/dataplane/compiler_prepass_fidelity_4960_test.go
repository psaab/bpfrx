package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// #6894 r5 F1: the pre-pass fake must not be MORE PERMISSIVE than the dataplane
// production actually compiles against.
//
// The concern is real in the abstract: `discardingDataPlane` answers every
// write with nil, so if the production dataplane validated its arguments and
// returned an error, a config could clear the pre-pass, let compileZones mutate
// the host, and then fail in a later phase — the exact half-applied state
// #4960 exists to prevent, produced by the guard meant to close it.
//
// It is NOT true today, and the reason is worth pinning rather than
// re-deriving. A review round raised it against
// `(*Manager).SetAddressBookEntry` (maps_policy.go), which does call
// net.ParseCIDR and does return an error. That method belongs to the RETIRED
// eBPF backend: `NewDataPlane` and `NewRuntimeDataPlane` both refuse TypeEBPF
// with ErrEBPFBackendRetired (dataplane.go), so no production apply reaches it.
// What production compiles against is `userspaceShimCompileDataplane`
// (loader.go), passed by CompileUserspaceShim, reached via
// userspace.Manager.ApplyConfig -> .Compile. Every one of its methods is a bare
// `return nil`, so it cannot reject anything the fake accepts, and the pre-pass
// is exactly as permissive as the real compile — no more, no less.
//
// That equivalence is a PROPERTY OF THE SHIM, not a law, which is why this test
// exists instead of a comment. Someone adding a validating method to
// `userspaceShimCompileDataplane` would make the concern live, silently: the
// pre-pass would start accepting configs the real compile rejects. This fails
// the moment that happens.
//
// It deliberately does NOT require the fake to validate. Teaching the fake to
// ParseCIDR would make the PRE-PASS STRICTER than production and reject at
// commit configs the runtime accepts — an empty address-book `value` is a
// deliberate WARNING, not a reject (compiler_validate_warn.go, #2229), and this
// gate has already swung through over-rejection twice. The invariant is
// "the fake is no more permissive than the shim", and while every shim method
// is a no-op that reduces to "every shim method is a no-op".
func TestPrePassFakeIsNoMorePermissiveThanProduction_4960(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "loader.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse loader.go: %v", err)
	}

	var validating []string
	seen := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if !strings.Contains(typeName(fn.Recv.List[0].Type), "userspaceShimCompileDataplane") {
			continue
		}
		seen++
		if fn.Body == nil {
			continue
		}
		// A no-op body is empty, or a single `return nil` / bare `return`.
		if len(fn.Body.List) == 0 {
			continue
		}
		if len(fn.Body.List) == 1 {
			ret, isRet := fn.Body.List[0].(*ast.ReturnStmt)
			if isRet && isNilOnlyReturn(ret) {
				continue
			}
		}
		validating = append(validating, fn.Name.Name)
	}

	// FLOOR: if the receiver were renamed or the file moved, `seen` would drop to
	// zero and the scan below would pass over nothing at all.
	if seen < 40 {
		t.Fatalf("only %d userspaceShimCompileDataplane methods found in loader.go — "+
			"the scan is not reaching the production compile shim, so a validating "+
			"method could be added without this test noticing", seen)
	}

	if len(validating) > 0 {
		sort.Strings(validating)
		t.Errorf("userspaceShimCompileDataplane now has method(s) with a non-no-op "+
			"body: %v\n\nThe #4960 pre-pass compiles against discardingDataPlane, "+
			"whose every method returns nil. While the production shim was also a "+
			"pure no-op the two were equivalent and the pre-pass could not be more "+
			"permissive than the real compile. A method that can now REJECT breaks "+
			"that: a config can pass the pre-pass, let compileZones mutate the host, "+
			"and then fail in the real phase — the half-applied apply #4960 exists "+
			"to prevent.\n\nEither give discardingDataPlane the same check (and "+
			"accept that the pre-pass now rejects at commit what the runtime would "+
			"have rejected at apply), or establish that the new method cannot fail "+
			"for any config that reaches it. Do NOT simply update this list.",
			validating)
	}
}

func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

func isNilOnlyReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return true
	}
	for _, r := range ret.Results {
		id, ok := r.(*ast.Ident)
		if !ok || id.Name != "nil" {
			return false
		}
	}
	return true
}
