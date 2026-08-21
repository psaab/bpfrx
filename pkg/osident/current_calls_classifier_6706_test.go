package osident

// #6706 review r11 F5: bind the CALL, not the value.
//
// TestCurrentUsesClassifyLookup_6706 (passwd_6706_test.go) checks
// `Current() == classifyLookup(uid, name, err)` for the running process. That
// is a VALUE comparison, so it is satisfied by any production code computing
// the same answer — including an inlined copy of the switch with
// `classifyLookup` left dead. Measured: inlining the equivalent switch into
// Current and never calling classifyLookup leaves `./pkg/osident ./pkg/cli
// ./pkg/daemon ./cmd/cli` all `ok`. The guard could not fire.
//
// That matters because the seam is not decorative. classifyLookup exists so
// the `err == nil && name != ""` term — unreachable through Current's own
// lookup paths — stays drivable, and TestClassifyLookupUnnamedSuccessIsNotIdentified_6706
// binds it. If Current stops routing through the classifier, that test proves
// something about dead code while the live identity path is unguarded, which
// is the precise failure the sibling's comment claims to prevent.
//
// WHY A SOURCE ASSERTION. The claim being guarded is syntactic — "Current
// routes through classifyLookup" — so a syntactic instrument is the honest
// one. The behavioural alternatives were both rejected in production comments
// already: a package-level `var classify = classifyLookup` hook would put a
// repointable function pointer on the identity path of a package whose whole
// purpose is failing closed (osident.go's own reasoning, #6706 r10 F3), and a
// value comparison is what already failed to bind.
//
// It is scoped to Current's OWN body via go/ast rather than grepping the file,
// because a file-level match would stay green if the call moved to any other
// function — the file mentions classifyLookup in several places, including the
// tests' own use of it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// bodyCalls reports whether the named top-level func in file calls callee.
// found=false with exists=false means the function itself is absent, which is a
// different failure from "present but does not call" and must not be reported
// as the latter.
func bodyCalls(t *testing.T, file, fn, callee string) (found, exists bool) {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var body *ast.BlockStmt
	for _, decl := range parsed.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name == nil || fd.Name.Name != fn {
			continue
		}
		body = fd.Body
		break
	}
	if body == nil {
		return false, false
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == callee {
			found = true
			return false
		}
		return true
	})
	return found, true
}

// TestCurrentBodyCallsClassifyLookup_6706 pins the whole live identity path to
// the classifier, one link at a time.
//
// #6645 split the path in two: Current now delegates to ForUID (which resolves
// an ARBITRARY uid, because the REST surface learns its caller's uid from
// SO_PEERCRED rather than os.Getuid), and ForUID does the classifying. That
// extraction MOVED the boundary this guard was watching — asserting only on
// Current's body would now pass while proving nothing, since Current no longer
// touches the classifier itself.
//
// So both links are asserted, and the chain must be complete: Current -> ForUID
// -> classifyLookup. Breaking either link fails, and inlining the switch into
// EITHER function fails, which is strictly more than the single link this
// guarded before.
func TestCurrentBodyCallsClassifyLookup_6706(t *testing.T) {
	const file = "osident.go"

	for _, link := range []struct {
		fn, callee, why string
	}{
		{
			fn: "ForUID", callee: "classifyLookup",
			why: "the unnamed-success term is only reachable through the classifier, so " +
				"TestClassifyLookupUnnamedSuccessIsNotIdentified_6706 would be proving " +
				"something about dead code while the live identity path — the one every " +
				"RBAC decision reads — goes unguarded. Inlining an equivalent switch " +
				"satisfies the value comparison in TestCurrentUsesClassifyLookup_6706; " +
				"that is exactly the substitution this test exists to catch",
		},
		{
			fn: "Current", callee: "ForUID",
			why: "Current is the entry point every CLI decision uses. If it stops routing " +
				"through ForUID it no longer shares a resolver with the REST surface, " +
				"which is the divergence #6645 closed: two implementations of one rule " +
				"disagreed on duplicate UIDs and admitted a caller the CLI denied",
		},
	} {
		found, exists := bodyCalls(t, file, link.fn, link.callee)
		if !exists {
			t.Fatalf("no top-level func %s in %s — this guard names a production "+
				"function that no longer exists, so it is guarding nothing", link.fn, file)
		}
		if !found {
			t.Fatalf("%s.%s does not call %s. %s", file, link.fn, link.callee, link.why)
		}
	}
}

// TestCurrentBodyCallsClassifyLookupCanaryCanFail_6706 is the checker's own
// control: it proves the AST walk above rejects a body that does NOT contain
// the call, rather than passing for any input. Without it, a walk that silently
// matched everything (a broken Inspect predicate, a mistyped callee) would look
// identical to a passing guard.
func TestCurrentBodyCallsClassifyLookupCanaryCanFail_6706(t *testing.T) {
	const src = `package p
func Current() Identity {
	uid := os.Getuid()
	name, err := lookupID(uid)
	switch {
	case err == nil && name != "":
		return Identity{UID: uid, Name: name}
	default:
		return Identity{UID: uid, Reason: ReasonLookupFailed}
	}
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range parsed.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "Current" {
			body = fd.Body
		}
	}
	if body == nil {
		t.Fatal("synthetic fixture has no Current")
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "classifyLookup" {
			found = true
			return false
		}
		return true
	})
	if found {
		t.Fatal("the checker reported a classifyLookup call in a body that inlines the " +
			"switch instead — it would pass for the very mutation it is meant to catch")
	}
}
