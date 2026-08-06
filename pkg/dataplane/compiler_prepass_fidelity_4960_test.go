package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// prePassShimDivergence records a method the #4960 pre-pass's
// discardingDataPlane answers DIFFERENTLY from the dataplane production
// compiles against, with the reason the divergence is acceptable.
//
// An entry here is a hole in "the pre-pass sees what the real compile sees",
// so each one needs an argument for why it cannot produce a config that clears
// the pre-pass and then fails after compileZones has mutated the host.
var prePassShimDivergence = map[string]string{
	"IsLoaded": "the fake returns true unconditionally; the shim promotes to " +
		"(*Manager).IsLoaded. CompileConfig checks it at the very top " +
		"(compiler.go), BEFORE newValidationResult and long before compileZones, " +
		"so a production false aborts with 'dataplane not loaded' having mutated " +
		"nothing. The fake being more permissive here cannot produce a " +
		"half-applied host.",
	"GetPersistentNAT": "the fake returns a typed-nil *PersistentNATTable; the " +
		"shim promotes to (*Manager).GetPersistentNAT, which returns the live " +
		"m.PersistentNAT. Both compile-path call sites nil-guard " +
		"(compiler_nat.go, in compileNAT), so the pre-pass SKIPS " +
		"ClearPoolConfigs and SetPoolConfig while production runs them. Neither " +
		"returns an error, so no failure can escape the pre-pass into the " +
		"post-mutation window -- but the branch is genuinely unexercised by the " +
		"pre-pass, and if either ever gains an error return this entry must go " +
		"and the fake must model the table.",
	"xpfValidationPass": "not a DataPlane method at all -- the marker " +
		"isValidationPass keys on, defined only on the fake by construction.",
}

// #6894 r5 F1: the pre-pass fake must not be MORE PERMISSIVE than the dataplane
// production actually compiles against.
//
// The concern is real in the abstract: discardingDataPlane answers every write
// with nil, so if the production dataplane validated its arguments and returned
// an error, a config could clear the pre-pass, let compileZones mutate the
// host, and then fail in a later phase -- the exact half-applied state #4960
// exists to prevent, produced by the guard meant to close it.
//
// A review round raised it against (*Manager).SetAddressBookEntry
// (maps_policy.go), which does call net.ParseCIDR and does return an error.
// That method belongs to the RETIRED eBPF backend: NewDataPlane and
// NewRuntimeDataPlane both refuse TypeEBPF with ErrEBPFBackendRetired
// (dataplane.go), so no production apply reaches it. What production compiles
// against is userspaceShimCompileDataplane (loader.go), passed by
// CompileUserspaceShim and reached via userspace.Manager.ApplyConfig ->
// .Compile. Its SetAddressBookEntry is a bare `return nil`, so for THAT method
// the fake and production agree exactly and the reported chain does not exist.
//
// This test deliberately does NOT require the fake to validate. Teaching it to
// ParseCIDR would make the PRE-PASS STRICTER than production and reject at
// commit configs the runtime accepts -- an empty address-book `value` is a
// deliberate WARNING, not a reject (compiler_validate_warn.go, #2229), and this
// gate has already swung through over-rejection twice.
//
// WHAT IT DOES CHECK, and why the shape matters. The equivalence is a PROPERTY
// OF THE SHIM, not a law, so:
//
//   - The DataPlane method set is enumerated by REFLECTION, not hardcoded. A
//     hardcoded list silently stops covering methods added later, which is the
//     precise failure this test exists to prevent.
//   - Method bodies are classified by AST, because reflection cannot see them:
//     for an embedded *Manager, Go synthesizes a wrapper on the outer type, so
//     a PROMOTED method is indistinguishable from an overridden one at runtime.
//     That distinction is the whole point -- an un-overridden compile-surface
//     method falls through to the eBPF Manager, which is exactly where the
//     validating implementations live.
//   - Every divergence is allowlisted WITH a reason, and the allowlist is
//     asserted MINIMAL, so it cannot rot into a dumping ground.
func TestPrePassFakeIsNoMorePermissiveThanProduction_4960(t *testing.T) {
	shimDecl, shimNonNoop := declaredMethods(t, "loader.go", "userspaceShimCompileDataplane")
	fakeDecl, _ := declaredMethods(t, "compiler_validate_4960.go", "discardingDataPlane")

	// FLOOR: a rename or file move would empty either scan and pass vacuously.
	if len(shimDecl) < 40 || len(fakeDecl) < 30 {
		t.Fatalf("scan found %d shim and %d fake methods — it is not reaching the "+
			"real types, so a divergence could be introduced without this test "+
			"noticing", len(shimDecl), len(fakeDecl))
	}

	// (1) Every method the production shim DECLARES must be a no-op. A
	//     validating body here is the live version of the reported concern.
	if len(shimNonNoop) > 0 {
		sort.Strings(shimNonNoop)
		t.Errorf("userspaceShimCompileDataplane now has method(s) with a non-no-op "+
			"body: %v\n\nThe #4960 pre-pass compiles against discardingDataPlane, "+
			"whose every method returns nil. While the production shim is also a "+
			"pure no-op the two are equivalent and the pre-pass cannot be more "+
			"permissive than the real compile. A method that can REJECT breaks "+
			"that: a config can pass the pre-pass, let compileZones mutate the "+
			"host, then fail in the real phase — the half-applied apply #4960 "+
			"exists to prevent.\n\nEither give discardingDataPlane the same check "+
			"(accepting that the pre-pass now rejects at commit what the runtime "+
			"would have rejected at apply), or establish the method cannot fail "+
			"for any config that reaches it and add it to prePassShimDivergence "+
			"with that argument.", shimNonNoop)
	}

	// (2) Every method the PRE-PASS CALL SURFACE covers must also be overridden
	//     by the shim — otherwise it promotes to the embedded *Manager, i.e. to
	//     the retired-eBPF implementation, and the fake and production diverge.
	var undocumented []string
	for name := range fakeDecl {
		if shimDecl[name] {
			continue
		}
		if _, ok := prePassShimDivergence[name]; !ok {
			undocumented = append(undocumented, name)
		}
	}
	if len(undocumented) > 0 {
		sort.Strings(undocumented)
		t.Errorf("discardingDataPlane overrides %v, but userspaceShimCompileDataplane "+
			"does NOT — so in production those calls PROMOTE to the embedded "+
			"*Manager, the retired eBPF implementation, while the pre-pass answers "+
			"with the fake's stub. The two are no longer looking at the same "+
			"dataplane on a path the pre-pass claims to model.\n\nEither override "+
			"it on the shim as a no-op, or add it to prePassShimDivergence with an "+
			"argument for why the divergence cannot produce a config that clears "+
			"the pre-pass and fails after compileZones has mutated the host.",
			undocumented)
	}

	// (3) The allowlist must stay MINIMAL: an entry that is in fact overridden
	//     is stale, and a stale entry is how a future real divergence gets
	//     waved through by a reason written for a different situation.
	var stale []string
	for name := range prePassShimDivergence {
		if shimDecl[name] && fakeDecl[name] {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("prePassShimDivergence lists %v, but the shim DOES override them "+
			"now, so there is no divergence to excuse. Remove the entries — a "+
			"stale exemption is a hole waiting for the next method to fall into "+
			"it.", stale)
	}

	// (4) The reflection half: every DataPlane method must be satisfied, and the
	//     interface is the source of truth for what "the call surface" can grow
	//     into. This is what keeps the scans above from going stale silently.
	iface := reflect.TypeOf((*DataPlane)(nil)).Elem()
	if iface.NumMethod() < 100 {
		t.Fatalf("DataPlane exposes %d methods — the reflection enumeration is not "+
			"seeing the real interface", iface.NumMethod())
	}
	shimType := reflect.TypeOf(userspaceShimCompileDataplane{})
	for i := 0; i < iface.NumMethod(); i++ {
		if _, ok := shimType.MethodByName(iface.Method(i).Name); !ok {
			t.Errorf("userspaceShimCompileDataplane does not satisfy DataPlane.%s",
				iface.Method(i).Name)
		}
	}
}

// declaredMethods returns the set of methods DECLARED on recv in file (promoted
// ones are absent by construction, which is the distinction this test needs),
// plus the names of those whose body is not a bare no-op.
func declaredMethods(t *testing.T, file, recv string) (map[string]bool, []string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	decl := map[string]bool{}
	var nonNoop []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if !strings.Contains(exprTypeName(fn.Recv.List[0].Type), recv) {
			continue
		}
		decl[fn.Name.Name] = true
		if fn.Body == nil || len(fn.Body.List) == 0 {
			continue
		}
		if len(fn.Body.List) == 1 {
			if ret, isRet := fn.Body.List[0].(*ast.ReturnStmt); isRet && returnsOnlyNilOrNothing(ret) {
				continue
			}
		}
		// The fake's stubs may spell a typed nil over two statements; that is
		// still a no-op for this purpose. Only the SHIM's bodies are policed.
		if recv == "userspaceShimCompileDataplane" {
			nonNoop = append(nonNoop, fn.Name.Name)
		}
	}
	return decl, nonNoop
}

func exprTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprTypeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

func returnsOnlyNilOrNothing(ret *ast.ReturnStmt) bool {
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
