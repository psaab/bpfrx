package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCLIResolvesThroughTheSharedEvaluator_5561 binds the SHARING that #5561
// relies on, which its namesake in pkg/authz does not.
//
// TestResolveClassPermissionsIsSharedWithTheCLI_5561 calls
// config.ResolveClassPermissions directly and never enters pkg/cli at all, so
// it pins the shared helper's BEHAVIOUR while proving nothing about the CLI
// using it. Swap CLI.resolveClassPerms back to a duplicated evaluator and that
// test stays green — the name claims a factoring the assertions never touch.
//
// This one drives the CLI's own store-bound adapter and requires it to agree
// with the shared function for the same class and config. The #5561 gate's
// whole premise is that `curl` and the CLI cannot answer differently; if the
// CLI stops going through the shared evaluator, that premise fails silently.
//
// Custom classes carry the assertion, deliberately. A duplicated evaluator that
// only knew the four BUILT-IN classes would agree on every built-in and diverge
// exactly on the config-defined ones — which is the shape the #4304 fallback
// exists for, and the shape a built-ins-only fixture cannot see.
func TestCLIResolvesThroughTheSharedEvaluator_5561(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	sets := []string{
		"set system login class noc-admin permissions all",
		"set system login class viewer-plus permissions [ view clear ]",
		"set system login class nothing-at-all permissions view",
		// A custom class SHADOWING a built-in name, which the config path
		// genuinely admits: schema_system.go validates `user ... class` against
		// built-ins UNION custom classes, and compiler_system.go appends every
		// parsed class with no collision check. It is the fixture that gives this
		// test teeth against the ORDER a duplicated evaluator would get wrong.
		//
		// config.ResolveClassPermissions checks BUILT-INS FIRST, so the shared
		// answer for "super-user" is PermAll and this line changes nothing while
		// the CLI routes through it. A plausible CLI-only special case — resolve
		// config-defined classes inline, fall through to the shared evaluator
		// otherwise — keeps ONE syntactic shared call and so passes the
		// structural guard below, and passed the whole pkg/cli suite before this
		// line existed. With it, the CLI answers [view] where the shared
		// evaluator answers [all] and this test REDs. Without it, the two guards
		// between them bind "the body calls the shared evaluator" but not "the
		// answer comes from it".
		"set system login class super-user permissions view",
	}
	if _, err := store.LoadSet(strings.Join(sets, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config after commit")
	}

	// Built-ins AND config-defined classes AND an unknown one: the CLI's adapter
	// must return exactly what the shared evaluator returns for each.
	for _, class := range []string{
		"super-user", "operator", "read-only", "config-viewer", "unauthorized",
		"noc-admin", "viewer-plus", "nothing-at-all", "no-such-class",
	} {
		c := &CLI{store: store, userClass: class}
		gotPerms, gotKnown := c.resolveClassPerms(class)
		wantPerms, wantKnown := config.ResolveClassPermissions(cfg, class)

		if gotKnown != wantKnown {
			t.Errorf("class %q: CLI known=%v, shared evaluator known=%v — the CLI is not "+
				"resolving through config.ResolveClassPermissions, so `curl` and the CLI "+
				"can disagree about what a class may do", class, gotKnown, wantKnown)
			continue
		}
		if !samePerms(gotPerms, wantPerms) {
			t.Errorf("class %q: CLI resolved %v, shared evaluator resolved %v — same class, "+
				"same config, two answers", class, gotPerms, wantPerms)
		}
	}
}

// samePerms compares two permission sets as sets, since neither side promises
// an order.
func samePerms(a, b []config.LoginClassPermission) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[config.LoginClassPermission]int, len(a))
	for _, p := range a {
		seen[p]++
	}
	for _, p := range b {
		seen[p]--
		if seen[p] < 0 {
			return false
		}
	}
	return true
}

// TestCLIResolveClassPermsCallsSharedEvaluator_5561 is the STRUCTURAL half, and
// it exists because the behavioural half above cannot do this job.
//
// A behavioural test compares OUTPUTS. It therefore cannot distinguish "these
// share an implementation" from "these have equivalent implementations" — swap
// config.ResolveClassPermissions for a FAITHFUL inline copy and every output
// comparison still agrees, for built-in and custom classes alike. My earlier
// reasoning ("custom classes carry the assertion") held only against a
// built-ins-only duplicate, which is the weaker mutant. Against a faithful one
// the behavioural guard is green and the factoring is gone.
//
// Sharing is a STRUCTURAL property, so it needs a structural check: the CLI's
// adapter must actually CALL config.ResolveClassPermissions. This reads the AST
// of the real source file rather than exercising behaviour, which is the only
// thing a faithful copy cannot satisfy.
func TestCLIResolveClassPermsCallsSharedEvaluator_5561(t *testing.T) {
	const (
		file    = "permissions.go"
		fn      = "resolveClassPerms"
		wantPkg = "config"
		wantSel = "ResolveClassPermissions"
	)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	var body *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if ok && fd.Name.Name == fn && fd.Recv != nil {
			body = fd
		}
		return body == nil
	})
	if body == nil {
		t.Fatalf("no method %s found in %s — the guard is looking at the wrong symbol and "+
			"would pass vacuously", fn, file)
	}

	var calls int
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == wantPkg && sel.Sel.Name == wantSel {
			calls++
		}
		return true
	})
	if calls != 1 {
		t.Fatalf("%s.%s contains %d call(s) to %s.%s, want exactly 1 — the CLI is not "+
			"resolving through the shared evaluator, so `curl` and the CLI can drift into "+
			"disagreeing about what a class may do. A behaviourally identical inline copy "+
			"passes every output comparison and is exactly what this check exists to catch.",
			file, fn, calls, wantPkg, wantSel)
	}
}
