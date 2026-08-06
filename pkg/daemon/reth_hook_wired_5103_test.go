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
// built and where an aborted cycle is rolled back. Since #5103 r4 it ALSO
// asserts the `networkdErr = errors.Join(..., prepareErr)` line that carries
// the wrapper's commit error into the tail — previously unbound, and deleting
// it removed the entire fail-the-commit payload with every behavioural test
// still green. It cannot see a hook that is non-nil but returns nil
// unconditionally. It binds the specific regression shape: quietly dropping the
// hook, the wrapper, or the error join at the consumer while the producer's
// tests stay green.
func TestDaemonPassesRethBeforeCycleHook_5103(t *testing.T) {
	const file = "daemon_apply_dataplane.go"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	calls := 0
	wrapperCalls := 0
	// #5103 r4: the third structural claim. The wrapper's classified error is
	// bound (reth_prepare_abort_recovery_5103_test.go asserts errors.Is on the
	// sentinel) and the tail is bound (#5309 proves networkdErr reaches the
	// commit error), but the ONE line joining them was not: mutating
	// `if prepareErr != nil` to `if false && prepareErr != nil` left
	// ./pkg/daemon/... and ./pkg/dataplane/... entirely green. That deletes the
	// whole payload of the fail-the-commit behaviour — a member left
	// administratively DOWN, which no later apply repairs because the MAC write
	// SUCCEEDED and step 2.6 then early-returns on bytes.Equal — while every
	// behavioural test stays silent.
	// Assert the GUARDING CONDITION too, not merely that the statement exists.
	// A presence-only walk is satisfied by `if false && prepareErr != nil { ...
	// }` — the AssignStmt node is still there, unreachable. That is precisely
	// the mutation this guard is for, so it must see the `if` as well: the
	// condition has to be exactly the binary expression `prepareErr != nil`,
	// which a `false &&` wrapper (Op == token.LAND) is not.
	joinsIntoNetworkdErr := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if ifs, ok := n.(*ast.IfStmt); ok {
			cond, ok := ifs.Cond.(*ast.BinaryExpr)
			if !ok || cond.Op != token.NEQ {
				return true
			}
			lhsID, lok := cond.X.(*ast.Ident)
			rhsID, rok := cond.Y.(*ast.Ident)
			if !lok || !rok || lhsID.Name != "prepareErr" || rhsID.Name != "nil" {
				return true
			}
			for _, st := range ifs.Body.List {
				assign, ok := st.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
					continue
				}
				if id, ok := assign.Lhs[0].(*ast.Ident); !ok || id.Name != "networkdErr" {
					continue
				}
				call, ok := assign.Rhs[0].(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Join" {
					continue
				}
				for _, a := range call.Args {
					if id, ok := a.(*ast.Ident); ok && id.Name == "prepareErr" {
						joinsIntoNetworkdErr++
					}
				}
			}
			return true
		}
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
	// The wrapper's error must reach the commit. Without this the wrapper can
	// keep classifying correctly, the tail can keep surfacing networkdErr, and
	// the apply loop can silently drop the error between them — leaving a RETH
	// member administratively DOWN behind a green commit until the daemon
	// restarts.
	if joinsIntoNetworkdErr != 1 {
		t.Fatalf("%s: expected exactly 1 `networkdErr = errors.Join(..., prepareErr)` in the "+
			"RETH loop, found %d. The wrapper's classified error is what makes an aborted "+
			"link cycle fail the commit; dropping this join restores a SUCCESS report over a "+
			"member left administratively DOWN, and no behavioural test notices",
			file, joinsIntoNetworkdErr)
	}
}
