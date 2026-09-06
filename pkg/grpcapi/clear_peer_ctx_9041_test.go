package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #9041: clearPeerSessions must derive its peer-RPC deadline from the CALLER's
// context, not from context.Background().
//
// WHY STRUCTURALLY. Binding this behaviourally needs a live cluster.Manager
// with PeerAlive() plus a real authenticated peer dial, which a unit test
// cannot reach -- the same limit peer_fanout_attach_6851_test.go states for its
// sibling. So the WIRING is bound instead, at the call site, which is the half
// a behavioural test could not cover anyway.
//
// THE CANCEL IS REACHABLE, which is what makes this worth a guard rather than a
// tidy-up. Two independent routes cancel the handler context:
//
//   - `pkg/api/sessions.go` passes `r.Context()`, which net/http cancels when
//     the HTTP client disconnects;
//   - `cmd/cli/shared.go` passes `cmdCtx`, whose own field comment reads
//     "per-command context, cancelled by Ctrl-C".
//
// On context.Background() an operator's cancel returned immediately while the
// PEER clear ran to completion -- a ghost clear. That is the one outcome the
// #5882/#2468 partial-success apparatus cannot represent: it reports what was
// attempted, and a ghost clear is neither reported nor stopped.
//
// RED means someone reverted the derivation or added a second Background()
// timeout on this path.
func TestClearPeerSessionsDerivesCallerContext_9041(t *testing.T) {
	const (
		file   = "server_sessions.go"
		target = "clearPeerSessions"
	)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == target {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatalf("%s not found in %s — this guard is keyed to that function by name, so a "+
			"rename must bring it along rather than silently disarm it", target, file)
	}

	// 1. It must TAKE a context. Before #9041 it did not, so it structurally
	//    could not honour one however carefully the call site was written.
	takesCtx := false
	for _, p := range fn.Type.Params.List {
		if sel, ok := p.Type.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "context" && sel.Sel.Name == "Context" {
				takesCtx = true
			}
		}
	}
	if !takesCtx {
		t.Errorf("#9041: %s takes no context.Context parameter, so it cannot honour a "+
			"caller's cancel no matter what the call site passes. Its five siblings in this "+
			"fan-out all derive from the caller.", target)
	}

	// 2. Its timeout must not be rooted at Background().
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithTimeout" || len(call.Args) == 0 {
			return true
		}
		inner, ok := call.Args[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		isel, ok := inner.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := isel.X.(*ast.Ident); ok && x.Name == "context" && isel.Sel.Name == "Background" {
			t.Errorf("#9041: %s roots its peer-RPC timeout at context.Background(), so an "+
				"operator's cancel (HTTP disconnect, or Ctrl-C via cmdCtx) returns "+
				"immediately while the PEER clear runs to completion — a ghost clear the "+
				"partial-success apparatus cannot report.", target)
		}
		return true
	})

	// 3. THE CALL SITES must pass a context through. A correct function reached
	//    by a call that still drops the ctx is the failure this guard exists for,
	//    and it is invisible from inside the function.
	var bareCalls int
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != target {
			return true
		}
		if len(call.Args) < 2 {
			bareCalls++
			return true
		}
		// Passing SOMETHING is not passing the caller's context. A call site
		// handing over context.Background() satisfies the arity check and
		// defeats the whole fix, so the first argument must be an identifier
		// (the ctx the handler was given), not a fresh root context.
		if inner, ok := call.Args[0].(*ast.CallExpr); ok {
			if isel, ok := inner.Fun.(*ast.SelectorExpr); ok {
				if x, ok := isel.X.(*ast.Ident); ok && x.Name == "context" {
					t.Errorf("#9041: a call site passes context.%s() to %s instead of the "+
						"context the handler was given — the arity is right and the cancel "+
						"is still dropped.", isel.Sel.Name, target)
				}
			}
		}
		return true
	})
	if bareCalls != 0 {
		t.Errorf("#9041: %d call site(s) invoke %s without passing a context. The function "+
			"accepting one is not enough — the caller must hand over the one it was given.",
			bareCalls, target)
	}
}
