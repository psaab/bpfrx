package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #5103: the daemon must hand programRethMAC a REAL beforeCycle hook.
//
// The ordering tests in reth_worker_join_order_5103_test.go drive
// programRethMAC directly, so they bind the sequencing inside it. They do not
// bind the daemon's call TO it — and passing `nil` there compiles, keeps every
// one of those tests green, and silently restores the original defect: no
// worker join happens at all, on any driver, ever.
//
// Binding it behaviourally would need a *Daemon with a live cluster manager, a
// wired dataplane and real netlink RETH members, none of which a unit test
// reaches. So it is bound structurally instead.
//
// SCOPE, stated rather than implied. This asserts that the single
// programRethMAC call site in pkg/daemon passes a third argument that is not
// the literal `nil`, and that the apply loop reaches it through
// programRethMACWithWorkerJoin — the wrapper the behavioural tests in
// reth_prepare_abort_recovery_5103_test.go drive, which is where the hook is
// built and where an aborted cycle is rolled back. It cannot see a hook that is
// non-nil but returns nil unconditionally, and it does not see the
// `networkdErr = errors.Join(...)` line that carries the wrapper's commit error
// into the tail. It binds the specific regression shape: quietly dropping the
// hook, or the wrapper, at the consumer while the producer's tests stay green.
func TestDaemonPassesRethBeforeCycleHook_5103(t *testing.T) {
	const file = "daemon_apply_dataplane.go"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	calls := 0
	wrapperCalls := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "programRethMACWithWorkerJoin" {
				wrapperCalls++
			}
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "programRethMAC" {
			return true
		}
		calls++
		if len(call.Args) != 3 {
			t.Errorf("%s:%d: programRethMAC called with %d args, want 3 — the third is the "+
				"beforeCycle worker-join hook (#5103)",
				file, fset.Position(call.Pos()).Line, len(call.Args))
			return true
		}
		if arg, ok := call.Args[2].(*ast.Ident); ok && arg.Name == "nil" {
			t.Errorf("%s:%d: the daemon passes a nil beforeCycle hook, so the AF_XDP workers "+
				"are never joined before a RETH MAC link cycle — the #5103 defect, restored "+
				"with every producer-side test still green",
				file, fset.Position(call.Pos()).Line)
		}
		return true
	})

	// Guard the guard: a rename or a move would otherwise make this pass by
	// finding nothing to check.
	if calls != 1 {
		t.Fatalf("expected exactly 1 programRethMAC call site in %s, found %d — this canary "+
			"is keyed to that call site and is not checking anything otherwise", file, calls)
	}
	// The apply loop must go through the wrapper, not around it: calling
	// programRethMAC directly from the loop would keep the hook and lose the
	// rollback of an aborted cycle (#5103 F4), with every behavioural test in
	// reth_prepare_abort_recovery_5103_test.go still green because they drive
	// the wrapper.
	if wrapperCalls != 1 {
		t.Fatalf("expected exactly 1 programRethMACWithWorkerJoin call site in %s, found %d",
			file, wrapperCalls)
	}
}
