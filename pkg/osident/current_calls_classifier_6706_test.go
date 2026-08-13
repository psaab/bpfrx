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

func TestCurrentBodyCallsClassifyLookup_6706(t *testing.T) {
	const (
		file   = "osident.go"
		fn     = "Current"
		callee = "classifyLookup"
	)

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
		t.Fatalf("no top-level func %s in %s — this guard names a production "+
			"function that no longer exists, so it is guarding nothing", fn, file)
	}

	found := false
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

	if !found {
		t.Fatalf("%s.%s does not call %s. The unnamed-success term is only reachable "+
			"through the classifier, so TestClassifyLookupUnnamedSuccessIsNotIdentified_6706 "+
			"would now be proving something about dead code while the live identity path "+
			"— the one every RBAC decision reads — goes unguarded. Inlining an equivalent "+
			"switch satisfies the value comparison in TestCurrentUsesClassifyLookup_6706; "+
			"that is exactly the substitution this test exists to catch", file, fn, callee)
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
