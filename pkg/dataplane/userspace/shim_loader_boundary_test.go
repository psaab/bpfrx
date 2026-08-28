package userspace

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserspaceStartupUsesShimLoaderBoundary(t *testing.T) {
	t.Parallel()

	// #7004: every check below keys on the AST, not on rendered call text.
	//
	// A text match on `.Load()` cannot see a method value — `f := x.Load; f()`
	// invokes it while the literal never appears — and a text match on
	// `m.Compile(cfg)` additionally breaks on any respelling of the receiver or
	// the argument, so ordinary refactoring silently retires the guard. Both
	// failure modes leave the guard GREEN, which is the shape this project keeps
	// paying for.
	//
	// The prohibitions are therefore POSITION-FREE: any reference to the banned
	// method, in any position, is a violation. That is deliberately stronger than
	// "is called here" — a method value taken and stored is exactly the escape,
	// so refusing the reference outright is the property, not an approximation
	// of it. The requirements bind the RECEIVER and ARGUMENT by what they are
	// bound to rather than by how they are spelled.

	loadFn, loadFset := funcDeclOf7004(t, "manager.go", "Load")
	if selectorRefs7004(loadFn)["LoadUserspaceShim"] == 0 {
		t.Errorf("userspace Load must use LoadUserspaceShim:\n%s", renderDecl7004(t, loadFset, loadFn))
	}
	if n := selectorRefs7004(loadFn)["Load"]; n != 0 {
		t.Errorf("userspace Load references the legacy .Load method %d time(s); it must not, in any "+
			"position — taking it as a method value calls it just as effectively as invoking it "+
			"directly (#7004):\n%s", n, renderDecl7004(t, loadFset, loadFn))
	}

	compileFn, compileFset := funcDeclOf7004(t, "manager_compile.go", "Compile")
	if selectorRefs7004(compileFn)["CompileUserspaceShim"] == 0 {
		t.Errorf("userspace Compile must use CompileUserspaceShim:\n%s", renderDecl7004(t, compileFset, compileFn))
	}
	if n := selectorRefs7004(compileFn)["Compile"]; n != 0 {
		t.Errorf("userspace Compile references the legacy .Compile method %d time(s); it must not, in "+
			"any position (#7004):\n%s", n, renderDecl7004(t, compileFset, compileFn))
	}
	if n := allRefs7004(compileFn)["AttachTC"]; n != 0 {
		t.Errorf("userspace Compile references AttachTC %d time(s); the userspace runtime must not "+
			"attach TC programs (#7004):\n%s", n, renderDecl7004(t, compileFset, compileFn))
	}

	// The adapter must route through the userspace Manager it obtained from
	// managerOrErr. Binding "the receiver is whatever managerOrErr returned"
	// instead of the literal `m` is what makes this survive a rename, and it is
	// also the property that actually matters: routing through SOME `.Load` is
	// not the claim, routing through THAT manager's is.
	for _, tc := range []struct{ fn, method string }{{"Load", "Load"}, {"Compile", "Compile"}} {
		adapterFn, adapterFset := funcDeclOf7004(t, "legacy_dataplane.go", tc.fn)
		recv := managerOrErrBinding7004(adapterFn)
		if recv == "" {
			t.Errorf("legacy adapter %s does not bind the result of a.managerOrErr(); it cannot be "+
				"routing through the userspace Manager:\n%s", tc.fn, renderDecl7004(t, adapterFset, adapterFn))
			continue
		}
		if !callsMethodOn7004(adapterFn, recv, tc.method) {
			t.Errorf("legacy adapter %s must call %s.%s() on the manager returned by managerOrErr "+
				"(#7004 binds the receiver, not the spelling):\n%s",
				tc.fn, recv, tc.method, renderDecl7004(t, adapterFset, adapterFn))
		}
		if n := qualifiedRefs7004(adapterFn)["DataPlane."+tc.method]; n != 0 {
			t.Errorf("legacy adapter %s references DataPlane.%s %d time(s); it must route through the "+
				"userspace Manager, not the legacy DataPlane (#7004):\n%s",
				tc.fn, tc.method, n, renderDecl7004(t, adapterFset, adapterFn))
		}
	}
}

func TestUserspaceShimLoaderDoesNotReferenceLegacyObjects(t *testing.T) {
	t.Parallel()

	// Post-#1476 the retained shim loader graph lives in
	// loader_userspace_shim.go. The pre-#1476 location at
	// `../loader_ebpf.go` is deleted along with the legacy
	// XDP/TC bpf2go batch it used to coexist with.
	loaderFn, loaderFset := funcDeclOf7004(t, filepath.Join("..", "loader_userspace_shim.go"), "loadUserspaceShimObjectsOnce")
	loaderRefs := allRefs7004(loaderFn)
	if loaderRefs["loadRustUserspaceXDP"] == 0 {
		t.Errorf("userspace shim loader must load the retained Rust shim:\n%s", renderDecl7004(t, loaderFset, loaderFn))
	}
	if loaderRefs["userspaceShimEntryProg"] == 0 {
		t.Errorf("userspace shim loader must register the explicit shim entry program:\n%s", renderDecl7004(t, loaderFset, loaderFn))
	}
	assertNoLegacyLoaderRefs7004(t, "loadUserspaceShimObjectsOnce", loaderRefs)

	compileFn, _ := funcDeclOf7004(t, filepath.Join("..", "loader.go"), "CompileUserspaceShim")
	compileRefs := allRefs7004(compileFn)
	assertNoLegacyLoaderRefs7004(t, "CompileUserspaceShim", compileRefs)
	if n := compileRefs["AttachTC"]; n != 0 {
		t.Errorf("CompileUserspaceShim references AttachTC %d time(s); it must not attach TC programs (#7004)", n)
	}
}

func assertNoLegacyLoaderRefs7004(t *testing.T, name string, refs map[string]int) {
	t.Helper()
	for _, tok := range []string{
		"loadAllObjects",
		"loadXpfXdp",
		"loadXpfTc",
		"xpfXdp",
		"xpfTc",
		"xdp_main_prog",
		"tc_main_prog",
	} {
		if n := refs[tok]; n != 0 {
			t.Errorf("%s references legacy loader symbol %q %d time(s) (#7004: any position, not just "+
				"as a direct callee)", name, tok, n)
		}
	}
}

// funcDeclOf7004 parses path and returns the named top-level declaration.
//
// Returning the DECLARATION rather than its rendered text is the #7004 change.
// Comments were already excluded by #6647's printer round-trip; what a rendered
// string still cannot express is the difference between a call and a method
// value, or between an argument and its name.
func funcDeclOf7004(t *testing.T, path, name string) (*ast.FuncDecl, *token.FileSet) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		return fn, fset
	}
	t.Fatalf("function %s not found in %s", name, path)
	return nil, nil
}

func renderDecl7004(t *testing.T, fset *token.FileSet, fn *ast.FuncDecl) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, fn); err != nil {
		t.Fatalf("print %s: %v", fn.Name.Name, err)
	}
	return buf.String()
}

// selectorRefs7004 counts every X.Sel selector by its Sel name, in ANY position
// — callee, method value, argument, assignment RHS. Position-free is the point:
// a name-and-position matcher is defeated by `f := x.Load`.
func selectorRefs7004(n ast.Node) map[string]int {
	out := map[string]int{}
	ast.Inspect(n, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok {
			out[sel.Sel.Name]++
		}
		return true
	})
	return out
}

// qualifiedRefs7004 counts selectors as "X.Sel" when the receiver is itself an
// identifier or a selector, so a chain like a.legacy.DataPlane.Load registers as
// "DataPlane.Load".
func qualifiedRefs7004(n ast.Node) map[string]int {
	out := map[string]int{}
	ast.Inspect(n, func(node ast.Node) bool {
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch x := sel.X.(type) {
		case *ast.Ident:
			out[x.Name+"."+sel.Sel.Name]++
		case *ast.SelectorExpr:
			out[x.Sel.Name+"."+sel.Sel.Name]++
		}
		return true
	})
	return out
}

// allRefs7004 counts every identifier occurrence, bare or as a selector's Sel,
// so a banned symbol cannot hide behind either spelling.
func allRefs7004(n ast.Node) map[string]int {
	out := map[string]int{}
	ast.Inspect(n, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok {
			out[id.Name]++
		}
		return true
	})
	return out
}

// managerOrErrBinding7004 returns the name the function binds the result of
// a.managerOrErr() to, or "" if it never calls it.
func managerOrErrBinding7004(fn *ast.FuncDecl) string {
	name := ""
	ast.Inspect(fn, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "managerOrErr" {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && name == "" {
			name = id.Name
		}
		return true
	})
	return name
}

// callsMethodOn7004 reports whether fn CALLS recv.method(...) — callee position
// specifically, because here the claim is that the routing happens, and a method
// value taken and never invoked would not route anything.
//
// For a method taking arguments it also requires every argument to be one of
// fn's own parameters, so the check does not depend on what the argument is
// NAMED — the respelling fragility #7004 is about.
func callsMethodOn7004(fn *ast.FuncDecl, recv, method string) bool {
	params := map[string]bool{}
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			for _, id := range field.Names {
				params[id.Name] = true
			}
		}
	}
	found := false
	ast.Inspect(fn, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != method {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != recv {
			return true
		}
		for _, arg := range call.Args {
			id, ok := arg.(*ast.Ident)
			if !ok || !params[id.Name] {
				return true
			}
		}
		found = true
		return false
	})
	return found
}

func goFunctionSource(t *testing.T, path, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		candidate, ok := decl.(*ast.FuncDecl)
		if !ok || candidate.Name.Name != name {
			continue
		}
		fn = candidate
		break
	}
	if fn == nil {
		t.Fatalf("function %s not found in %s", name, path)
	}
	// RETURN CODE, NOT TEXT (#6647). This used to slice the raw file bytes
	// from fn.Pos() to fn.End(), which includes every comment INSIDE the
	// function body — so a source-scanning guard built on it could be
	// satisfied by a comment that merely quotes the call it demands.
	//
	// MEASURED on this file's own subject before the fix: deleting the real
	// `m.disarmSnapshotProtocolFailClosedLocked(snap, err, samePlanRefresh)`
	// from applyCompiledSnapshot, substituting the weaker plain-disarm call,
	// and leaving the demanded string behind in a `//` comment left
	// TestProtocolGateSitesRouteThroughFailClosedHelper5488 GREEN — and the
	// whole pkg/dataplane/userspace suite green with it, at `go vet` rc 0. The
	// #5488 F7 fail-closed compensation was unpinned in exactly the way the
	// guard existed to prevent.
	//
	// ParseFile ran with mode 0 above, so comments were never attached to the
	// AST; printing the node back out therefore yields the declaration's CODE
	// with every interior comment dropped. Formatting is gofmt-normalised,
	// which is what the tree is already in, so asserted call-expression
	// substrings are unaffected.
	//
	// The direction is right for both assertion shapes every caller uses: a
	// presence check can no longer be faked by a comment, and a banned-token
	// check can no longer FALSE-POSITIVE on prose that names the token it
	// forbids.
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, fn); err != nil {
		t.Fatalf("print %s from %s: %v", name, path, err)
	}
	return buf.String()
}

// #6647: goFunctionSource must return CODE, not raw file text.
//
// Every source-scanning guard in this package is built on it, including the one
// that pins the #5488 F7 fail-closed compensation in applyCompiledSnapshot —
// the compensator that closes #6647's "abort strands an armed helper behind new
// classifier state". While the helper sliced raw bytes from fn.Pos() to
// fn.End(), interior comments came back with the code, so a guard demanding a
// call could be satisfied by a comment that merely quotes it.
//
// MEASURED at origin/master before this fix, on that exact subject: deleting
// `m.disarmSnapshotProtocolFailClosedLocked(snap, err, samePlanRefresh)` from
// applyCompiledSnapshot, substituting the weaker plain-disarm call, and leaving
// the demanded string behind in a `//` comment left
// TestProtocolGateSitesRouteThroughFailClosedHelper5488 GREEN — and the whole
// pkg/dataplane/userspace suite green with it, at `go vet` rc 0.
//
// This cell is the paired proof: the SAME text is present in a comment and
// absent from the code, so a helper that leaks comments returns it and a helper
// that returns code does not. Reverting to the byte-slice form reds it.
func TestGoFunctionSourceReturnsCodeNotComments6647(t *testing.T) {
	t.Parallel()

	// A subject whose body carries a comment naming a call it does NOT make.
	// commentDecoySubject6647 is defined below purely for this cell.
	src := goFunctionSource(t, "shim_loader_boundary_test.go", "commentDecoySubject6647")

	if strings.Contains(src, "decoyCallThatIsOnlyEverMentionedInAComment") {
		t.Fatalf("goFunctionSource leaked an interior comment: the returned text "+
			"contains a call the function never makes, so every presence guard "+
			"built on this helper can be satisfied by a comment quoting the line "+
			"it demands (#6647). Got:\n%s", src)
	}
	// Positive control: the real call in the body must still be visible, or the
	// helper would be "safe" by returning nothing useful and every guard above
	// would pass vacuously.
	if !strings.Contains(src, "realCallTheSubjectActuallyMakes") {
		t.Fatalf("goFunctionSource dropped real code; guards built on it would "+
			"pass vacuously. Got:\n%s", src)
	}
}

func realCallTheSubjectActuallyMakes() int { return 0 }

// commentDecoySubject6647 exists only as the subject of
// TestGoFunctionSourceReturnsCodeNotComments6647.
func commentDecoySubject6647() int {
	// decoyCallThatIsOnlyEverMentionedInAComment() is named here and nowhere
	// else in this function's code. A comment-leaking reader returns it.
	return realCallTheSubjectActuallyMakes()
}
