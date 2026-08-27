package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #7713: Run() must actually START cluster comms at boot.
//
// Measured before this canary: deleting `d.startClusterComms(ctx)` from Run()
// left pkg/daemon FULLY GREEN — 0 named failures. A daemon that never starts
// cluster heartbeat or session sync at all passed the whole suite.
//
// # Why this is a call-shape canary and not a behavioural test
//
// Stated plainly rather than implied, because the choice is the interesting
// part. Run() is ~790 lines and NOTHING drives it: no test in this package
// calls Daemon.Run. Binding the boot start behaviourally needs a real config
// file, an initialised dataplane, the server phase and the shutdown sequence —
// a harness that does not exist and that #7713 explicitly declined to build by
// reshaping production code.
//
// The tempting alternative is worse and was rejected: extracting the three-line
// block into a `startBootClusterComms` method and unit-testing THAT. It would
// pass, and it would bind nothing new — the unbound call simply moves up one
// level, from `Run() -> startClusterComms` to `Run() -> startBootClusterComms`.
// That is the same "bind the wiring, not the function it calls" failure this
// issue exists to close, dressed as a refactor. So Run() is left exactly as it
// is and its call site is bound where it lives.
//
// Mirrors the #5103 canary (reth_hook_wired_5103_test.go), including its
// discipline of staying SMALL: that one over-reached in an early revision,
// matching an inline statement and its guard, and a hostile reviewer escaped it
// three ways that each only bought another AST clause.
//
// # What this binds
//
//  1. Run() contains EXACTLY ONE call to d.startClusterComms, taking one
//     argument. Deleting it, or duplicating it, REDs.
//  2. That call is not nested inside a constant-false `if` — the cheapest way
//     to disable it while leaving the syntax in place.
//
// # What this does NOT bind, and cannot
//
// It cannot reject a RUNTIME-false guard, an earlier `return` under a
// runtime-false condition, or a `goto` over the call. Nothing structural can;
// those need Run() to be executable in a test. It also says nothing about
// whether startClusterComms then works — pkg/daemon has separate coverage for
// what happens inside it, and #6878 binds the step-20 restart pair.
//
// What it does buy: a silent drop of the boot start has to be a deliberate
// control-flow edit rather than a plausible refactor or a bad merge.
func TestRunStartsClusterCommsAtBoot_7713(t *testing.T) {
	const file = "daemon_run.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	var runFn *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Name.Name != "Run" || fd.Recv == nil {
			return true
		}
		runFn = fd
		return false
	})
	if runFn == nil {
		t.Fatalf("no method Run found in %s — this canary would count zero call "+
			"sites and pass for the wrong reason", file)
	}

	// Collect calls to d.startClusterComms(...) inside Run, recording whether
	// each sits under a constant-false `if`.
	type site struct {
		pos       token.Position
		args      int
		deadBlock bool
	}
	var sites []site

	// Track constant-false `if` bodies so a disabled-but-present call is caught.
	dead := map[ast.Node]bool{}
	ast.Inspect(runFn, func(n ast.Node) bool {
		if ifs, ok := n.(*ast.IfStmt); ok {
			if lit, ok := ifs.Cond.(*ast.Ident); ok && lit.Name == "false" {
				dead[ifs.Body] = true
			}
		}
		return true
	})

	var stack []ast.Node
	ast.Inspect(runFn, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "startClusterComms" {
			return true
		}
		inDead := false
		for _, anc := range stack {
			if dead[anc] {
				inDead = true
				break
			}
		}
		sites = append(sites, site{
			pos:       fset.Position(call.Pos()),
			args:      len(call.Args),
			deadBlock: inDead,
		})
		return true
	})

	if len(sites) != 1 {
		t.Fatalf("found %d call(s) to startClusterComms in Run(), want exactly 1 "+
			"(%v) — deleting it leaves a daemon that never starts cluster heartbeat "+
			"or session sync, and before this canary that passed the whole package",
			len(sites), sites)
	}
	if got := sites[0].args; got != 1 {
		t.Errorf("Run() calls startClusterComms with %d args at %s, want 1 (the "+
			"context)", got, sites[0].pos)
	}
	if sites[0].deadBlock {
		t.Errorf("Run()'s startClusterComms call at %s is nested inside a "+
			"constant-false `if` — present in the source but never reached",
			sites[0].pos)
	}
}
