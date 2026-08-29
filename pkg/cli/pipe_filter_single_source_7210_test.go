package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/psaab/xpf/pkg/cliterm"
)

// #7210: pkg/cli must DELEGATE its pipe filtering to pkg/cliterm rather than
// keeping a second copy, because the local and remote CLI surfaces must not be
// able to drift apart (#4968 is what drifting looks like).
//
// WHY A VALUE COMPARISON CANNOT TEST THE CAP. `maxTailLines == cliterm.MaxTailLines`
// is true whether maxTailLines is an alias for it or a second literal 100_000.
// The two states are indistinguishable by value TODAY, and only become
// distinguishable on the day someone changes one of them — which is exactly the
// day the test is needed and the day it would not fire. So the assertion has to
// be about how the constant is DECLARED, which is a fact about the source.
//
// A mutation matrix found this gap: restoring `const maxTailLines = 100_000`
// left the entire suite green. The delegation comment claimed "an ALIAS, not a
// second copy of the number" and nothing enforced it.
//
// go/parser rather than grep: the surrounding doc comments name the literal and
// the shared constant, so a textual scan matches whichever one it looks for.

func constValueExpr(t *testing.T, file, name string) ast.Expr {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, id := range vs.Names {
				if id.Name == name && i < len(vs.Values) {
					return vs.Values[i]
				}
			}
		}
	}
	t.Fatalf("const %s not found in %s — if it moved, move this test with it; a missing "+
		"declaration must not read as a passing delegation check", name, file)
	return nil
}

func TestLocalMaxTailLinesIsAnAliasNotACopy7210(t *testing.T) {
	expr := constValueExpr(t, "cli_dispatch.go", "maxTailLines")

	referencesShared := false
	ast.Inspect(expr, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "cliterm" && sel.Sel.Name == "MaxTailLines" {
			referencesShared = true
		}
		return true
	})

	if !referencesShared {
		t.Error("maxTailLines is not declared as cliterm.MaxTailLines, so the local and remote " +
			"CLI now hold two independent copies of the tail cap. They are equal today, which is " +
			"why no value assertion can catch this — the copies only diverge on the day someone " +
			"changes one, and that is the day a value assertion still passes (#7210)")
	}

	// Positive control: the walker must actually detect a shared reference,
	// otherwise "no reference found" would be reported for a delegating
	// declaration too and the assertion above would be vacuous.
	ctl, err := parser.ParseExpr("cliterm.MaxTailLines")
	if err != nil {
		t.Fatalf("parsing the control expression: %v", err)
	}
	found := false
	ast.Inspect(ctl, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "cliterm" && sel.Sel.Name == "MaxTailLines" {
				found = true
			}
		}
		return true
	})
	if !found {
		t.Fatal("the walker failed to find cliterm.MaxTailLines in a literal reference to it; " +
			"until it does, a clean result above means nothing")
	}
}

// The behavioural half: whatever the declaration says, the two must agree.
// Kept alongside the structural check because they fail for different reasons —
// this one catches a wrong value, the one above catches a re-forked declaration
// that happens to still hold the right value.
func TestLocalAndSharedTailCapsAgree7210(t *testing.T) {
	if maxTailLines != cliterm.MaxTailLines {
		t.Errorf("local cap %d != shared cap %d", maxTailLines, cliterm.MaxTailLines)
	}
	if got := parseLastCount("2000000000"); got != cliterm.MaxTailLines {
		t.Errorf("local parseLastCount did not clamp to the shared cap: got %d, want %d",
			got, cliterm.MaxTailLines)
	}
}
