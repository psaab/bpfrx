package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// #7079: the bpffs cleanups must run AFTER CompileConfig, not before it.
//
// CompileConfig carries the #4960 validate-before-mutate pre-pass. Three host
// mutations used to run ahead of it — the XDP link pins (from
// userspace.Manager.Compile) plus the legacy TC link and legacy-only map pin
// cleanups (from the top of CompileUserspaceShim) — so a config the pre-pass
// REJECTED still left the host with those pins removed, for an apply that never
// happened.
//
// WHY THIS IS A SOURCE-ORDER ASSERTION RATHER THAN A BEHAVIOURAL ONE. The
// property is "statement A precedes statement B in this function". Driving it
// behaviourally means a real bpffs, a loaded shim and a config that reaches the
// pre-pass and is rejected by it — none of which a unit test has. The repo
// already binds this class of property this way:
// TestArmProofIsInvokedFromCompileUserspaceShim walks this very function for a
// CallExpr and asserts the arm proof runs after the attach, and
// TestCompileRoutesPublishThroughFailClosedHelper4959 asserts a publish goes
// through a particular helper.
//
// It parses the AST rather than matching strings, so a comment mentioning
// cleanupUserspaceShimLegacyTCLinks cannot satisfy it — the failure mode a
// grep-based version of this guard would have.
func TestPinCleanupsRunAfterCompileConfig_7079(t *testing.T) {
	const file = "loader.go"
	fset := token.NewFileSet()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	parsed, err := parser.ParseFile(fset, file, src, 0) // comments dropped
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	var fn *ast.FuncDecl
	ast.Inspect(parsed, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == "CompileUserspaceShim" {
			fn = d
		}
		return fn == nil
	})
	if fn == nil {
		t.Fatalf("CompileUserspaceShim not found in %s — this guard is anchored on a "+
			"name that no longer exists, which is not evidence of correct ordering", file)
	}

	// Positions of the calls that matter, by NAME, in source order.
	pos := map[string]int{}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch f := call.Fun.(type) {
		case *ast.Ident:
			name = f.Name
		case *ast.SelectorExpr:
			name = f.Sel.Name
		}
		if _, seen := pos[name]; !seen && name != "" {
			pos[name] = fset.Position(call.Pos()).Line
		}
		return true
	})

	compile, ok := pos["CompileConfig"]
	if !ok {
		t.Fatal("CompileUserspaceShim no longer calls CompileConfig, so the #4960 " +
			"pre-pass does not run on this path at all")
	}

	// Non-vacuity FIRST: absent calls would make every ordering check below pass
	// for free, which is exactly how this guard would rot if one were renamed.
	for _, name := range []string{
		"cleanupUserspaceShimLegacyTCLinks",
		"cleanupUserspaceShimLegacyOnlyMapPins",
		"removeUserspaceShimXDPLinkPins",
		"runPostMutationSteps",
	} {
		if _, found := pos[name]; !found {
			t.Fatalf("%s is not called from CompileUserspaceShim. Either it was renamed "+
				"— in which case this guard is checking an ordering it can no longer see "+
				"— or the cleanup was dropped. Calls found: %v", name, keysOf(pos))
		}
	}

	attach := pos["runPostMutationSteps"]
	for _, name := range []string{
		"cleanupUserspaceShimLegacyTCLinks",
		"cleanupUserspaceShimLegacyOnlyMapPins",
		"removeUserspaceShimXDPLinkPins",
	} {
		if pos[name] < compile {
			t.Errorf("%s (line %d) runs BEFORE CompileConfig (line %d). It mutates host "+
				"bpffs state, so a config the #4960 pre-pass rejects loses those pins for "+
				"an apply that never happened (#7079)", name, pos[name], compile)
		}
		if pos[name] > attach {
			t.Errorf("%s (line %d) runs AFTER runPostMutationSteps (line %d), which "+
				"contains the attach. The XDP pin removal exists to force a FRESH attach: "+
				"pinned reuse (existing.Update) swaps the program without reinitializing "+
				"the mlx5 XSK RQs, leaving the fill ring unconsumed (#7079)",
				name, pos[name], attach)
		}
	}
}

func keysOf(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// #7079: the XDP link-pin removal must NOT have crept back into
// userspace.Manager.Compile, where it ran ahead of the pre-pass.
//
// The sibling above pins where it now IS. This pins where it must not be, and
// the pair matters because a re-added removal at the old site would leave the
// new one in place — the ordering test would still pass while the host was
// mutated ahead of validation again.
func TestUserspaceCompileDoesNotRemovePinsBeforeValidation_7079(t *testing.T) {
	path := filepath.Join("userspace", "manager_compile.go")
	fset := token.NewFileSet()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	parsed, err := parser.ParseFile(fset, path, src, 0) // comments dropped
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var fn *ast.FuncDecl
	ast.Inspect(parsed, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == "Compile" && d.Recv != nil {
			fn = d
		}
		return fn == nil
	})
	if fn == nil {
		t.Fatalf("(*Manager).Compile not found in %s", path)
	}

	var offenders []string
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, isIdent := sel.X.(*ast.Ident)
		if !isIdent {
			return true
		}
		if pkg.Name == "os" && (sel.Sel.Name == "Remove" || sel.Sel.Name == "RemoveAll") {
			offenders = append(offenders,
				sel.Sel.Name+" at line "+strconv.Itoa(fset.Position(call.Pos()).Line))
		}
		return true
	})
	if len(offenders) > 0 {
		t.Errorf("(*Manager).Compile removes host filesystem state before "+
			"CompileUserspaceShim runs the #4960 pre-pass: %v.\nThat is the #7079 "+
			"defect — the removal belongs in CompileUserspaceShim after CompileConfig "+
			"and before the attach, where removeUserspaceShimXDPLinkPins now lives",
			offenders)
	}
}
