package userspace

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// TestWorkerCountHasOneRepresentation_5718 is the #5718 fold F3
// fail-on-revert.
//
// programBootstrapMapsLocked describes the worker count three times — the ctrl
// map's Workers field, its QueueCount field, and the heartbeat zero-init loop
// bound — and before the fold they were derived from cfg.Workers under two
// different rules: `maxInt(cfg.Workers, 1)` cast to uint32 for the ctrl
// fields, and the RAW cfg.Workers passed to heartbeatZeroSlots for the loop.
//
// Fixing the A6-b01-C1 narrowing in heartbeatZeroSlots alone did not make them
// agree, it made them DISAGREE for exactly the inputs that fix was written
// for. `workers 4294967296` clamps to the full heartbeat map on the loop side
// while `uint32(maxInt(1<<32, 1))` narrows to 0 on the ctrl side, so the shim
// is told the dataplane has ZERO workers and ZERO queues while userspace
// zero-initialises 128 workers' worth of heartbeat slots. `1<<32+5` tells the
// shim there are 5.
//
// planUserspaceWorkers now returns both numbers from one clamp, so this test
// asserts the property on the plan: whatever the configured value, the count
// the ctrl fields carry survives their uint32 cast, is never zero, and is
// exactly the count the heartbeat bound was sized from.
func TestWorkerCountHasOneRepresentation_5718(t *testing.T) {
	// The real userspace_heartbeat Array capacity (lib.rs: 4096 entries), so
	// maxW is the production 128 workers.
	const mapCap = uint32(4096)
	const perWorker = uint32(heartbeatSlotsPerWorker)
	const maxW = int(mapCap / perWorker)

	cases := []struct {
		name    string
		workers int
		want    int
	}{
		// The narrowing boundary. A cast-first derivation reads 0 here.
		{"one past the uint32 range", 1 << 32, maxW},
		// Narrows to a legal-looking 5 under a cast-first derivation.
		{"uint32 range plus five", 1<<32 + 5, maxW},
		{"two full uint32 wraps", 2 << 32, maxW},
		{"max int", int(^uint(0) >> 1), maxW},
		// Ordinary and boundary values.
		{"six", 6, 6},
		{"one", 1, 1},
		{"at the cap", maxW, maxW},
		{"above the cap", maxW + 1, maxW},
		{"huge but under the uint32 range", 999_999_999, maxW},
		{"zero coerces to one", 0, 1},
		{"negative coerces to one", -1, 1},
		{"large negative coerces to one", -5_000_000_000, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := planUserspaceWorkers(tc.workers, mapCap)

			// 1) The count the ctrl fields carry to the shim. A cast-first
			//    derivation fails here: for 1<<32 it reports 0 workers and 0
			//    queues, for 1<<32+5 it reports 5.
			if int(plan.Workers) != tc.want {
				t.Fatalf("planUserspaceWorkers(%d, %d).Workers = %d, want %d — this is the "+
					"number ctrl.Workers and ctrl.QueueCount carry to the shim",
					tc.workers, mapCap, plan.Workers, tc.want)
			}
			if plan.Workers == 0 {
				t.Fatalf("configured workers=%d: ctrl.Workers/ctrl.QueueCount would be 0 — "+
					"the shim is told the dataplane has no workers and no queues", tc.workers)
			}

			// 2) The heartbeat zero-init bound describes the SAME count.
			wantSlots := plan.Workers * perWorker
			if plan.HeartbeatSlots != wantSlots {
				t.Fatalf("configured workers=%d: the heartbeat loop is sized for %d slots "+
					"but the ctrl fields report %d workers (%d slots) — the same quantity "+
					"has two representations and they have drifted",
					tc.workers, plan.HeartbeatSlots, plan.Workers, wantSlots)
			}

			// 3) The invariants each side owes independently.
			if plan.HeartbeatSlots == 0 || plan.HeartbeatSlots > mapCap {
				t.Fatalf("planUserspaceWorkers(%d, %d).HeartbeatSlots = %d: must be in (0, %d]",
					tc.workers, mapCap, plan.HeartbeatSlots, mapCap)
			}

			// 4) The standalone helpers agree with the plan, so a caller that
			//    reaches for either directly cannot land on a different number.
			if got := effectiveWorkers(tc.workers, mapCap); got != tc.want {
				t.Fatalf("effectiveWorkers(%d, %d) = %d, want %d", tc.workers, mapCap, got, tc.want)
			}
			if got := heartbeatZeroSlots(tc.workers, mapCap); got != plan.HeartbeatSlots {
				t.Fatalf("heartbeatZeroSlots(%d, %d) = %d but the plan says %d",
					tc.workers, mapCap, got, plan.HeartbeatSlots)
			}
		})
	}
}

// exprText renders a node's source text for assertion messages.
func exprText(fset *token.FileSet, n ast.Node) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, n); err != nil {
		return "<unprintable>"
	}
	return sb.String()
}

// TestProgramBootstrapWorkerCountDataFlow_5718 binds the CALL SITE's DATA
// FLOW, not just an occurrence count.
//
// planUserspaceWorkers can only guarantee one representation if
// programBootstrapMapsLocked actually routes every use through it. Counting
// `cfg.Workers` occurrences and requiring one is too weak for that claim:
// `w := cfg.Workers` reads the raw value ONCE and then lets `w` feed a second,
// independent derivation downstream — the pre-fold defect exactly, with a
// single occurrence. So the guard asserts the flow instead:
//
//  1. the one `cfg.Workers` read is an ARGUMENT to planUserspaceWorkers, so
//     the raw value cannot be aliased into a local first;
//  2. planUserspaceWorkers is called exactly once and bound to a name;
//  3. ctrl.Workers and ctrl.QueueCount are both `<plan>.Workers`;
//  4. the zero-init loop bound is `<plan>.HeartbeatSlots`;
//  5. neither clamp helper is called directly here — reaching around the plan
//     to effectiveWorkers or heartbeatZeroSlots is how a second representation
//     re-appears without ever touching cfg.Workers again.
func TestProgramBootstrapWorkerCountDataFlow_5718(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "maps_sync.go", nil, 0)
	if err != nil {
		t.Fatalf("parse maps_sync.go: %v", err)
	}

	var fn *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		d, ok := n.(*ast.FuncDecl)
		if ok && d.Name.Name == "programBootstrapMapsLocked" {
			fn = d
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("programBootstrapMapsLocked not found in maps_sync.go — if it was renamed, " +
			"re-point this guard at the new name rather than deleting it")
	}
	body := fn.Body

	isSel := func(n ast.Node, x, sel string) bool {
		s, ok := n.(*ast.SelectorExpr)
		if !ok || s.Sel.Name != sel {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && id.Name == x
	}

	// (2) exactly one planUserspaceWorkers call, bound to a name.
	var planVar string
	planCalls := 0
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "planUserspaceWorkers" {
			return true
		}
		planCalls++
		if lhs, ok := as.Lhs[0].(*ast.Ident); ok {
			planVar = lhs.Name
		}
		// (1) the raw configured value must be an ARGUMENT to this call.
		rawIsArg := false
		for _, arg := range call.Args {
			if isSel(arg, "cfg", "Workers") {
				rawIsArg = true
			}
		}
		if !rawIsArg {
			t.Fatalf("planUserspaceWorkers(%s) is not passed cfg.Workers directly. The raw "+
				"configured value must flow straight into the single clamp — aliasing it "+
				"into a local first (`w := cfg.Workers`) lets a second derivation feed off "+
				"the raw value while cfg.Workers still appears only once (#5718 fold F3)",
				exprText(fset, call))
		}
		return true
	})
	if planCalls != 1 || planVar == "" {
		t.Fatalf("programBootstrapMapsLocked must call planUserspaceWorkers exactly once and "+
			"bind the result to a name; found %d call(s), var %q", planCalls, planVar)
	}

	// (1, cont.) every cfg.Workers read must be that argument — one read, and
	// it is the one already checked above.
	rawReads := 0
	var rawPos []string
	ast.Inspect(body, func(n ast.Node) bool {
		if isSel(n, "cfg", "Workers") {
			rawReads++
			rawPos = append(rawPos, fset.Position(n.Pos()).String())
		}
		return true
	})
	if rawReads != 1 {
		t.Fatalf("programBootstrapMapsLocked reads cfg.Workers %d time(s) at %v; want exactly 1 "+
			"(the planUserspaceWorkers argument). A second read is how the ctrl fields and the "+
			"heartbeat loop came to describe the same quantity differently", rawReads, rawPos)
	}

	// (5) no direct clamp-helper call — every representation goes via the plan.
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "heartbeatZeroSlots" || id.Name == "effectiveWorkers" {
			t.Fatalf("programBootstrapMapsLocked calls %s directly at %s. Reaching around the "+
				"plan re-creates an independent derivation of the worker count — the exact "+
				"drift planUserspaceWorkers exists to prevent — without reading cfg.Workers "+
				"a second time", id.Name, fset.Position(call.Pos()))
		}
		return true
	})

	// (3) ctrl.Workers and ctrl.QueueCount both read <plan>.Workers.
	ctrlFields := map[string]bool{"Workers": false, "QueueCount": false}
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "userspaceCtrlValue" {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			if _, want := ctrlFields[key.Name]; !want {
				continue
			}
			if !isSel(kv.Value, planVar, "Workers") {
				t.Fatalf("userspaceCtrlValue.%s is %q; want %s.Workers. Every representation of "+
					"the worker count must be read from the single plan, or the ctrl fields and "+
					"the heartbeat bound can describe the same quantity differently (#5718 fold F3)",
					key.Name, exprText(fset, kv.Value), planVar)
			}
			ctrlFields[key.Name] = true
		}
		return true
	})
	for name, seen := range ctrlFields {
		if !seen {
			t.Fatalf("userspaceCtrlValue.%s was not found in programBootstrapMapsLocked — if the "+
				"field moved, re-point this guard rather than dropping the check", name)
		}
	}

	// (4) The heartbeat zero-init loop counts against <plan>.HeartbeatSlots.
	//
	// This asserts the LOOP CONDITION, not an assignment. Checking `slots :=
	// plan.HeartbeatSlots` binds nothing on its own: keeping that statement as
	// a decoy and writing `for slot := 0; slot < plan.Workers; slot++` passes
	// an assignment-shaped guard while production zeroes one Array entry per
	// WORKER instead of per SLOT — 1 of 32 at the default worker count
	// (capabilities.go seeds Workers: 1) and 6 of 192 on the six-worker loss
	// cluster. Every un-zeroed slot keeps a stale value, and the shim refuses
	// to redirect for a worker whose slot never got initialised. The loop's own
	// bound is the thing with the runtime consequence, so it is the thing
	// checked.
	//
	// The loop is located by what it DOES (it writes heartbeatMap), so
	// renaming variables cannot silently detach the guard from its subject.
	loopChecked := false
	ast.Inspect(body, func(n ast.Node) bool {
		fl, ok := n.(*ast.ForStmt)
		if !ok {
			return true
		}
		writesHeartbeat := false
		ast.Inspect(fl.Body, func(bn ast.Node) bool {
			call, ok := bn.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Update" {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "heartbeatMap" {
					writesHeartbeat = true
				}
			}
			return true
		})
		if !writesHeartbeat {
			return true
		}
		loopChecked = true
		cond, ok := fl.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.LSS {
			t.Fatalf("the heartbeat zero-init loop condition is %q; want `slot < %s.HeartbeatSlots`",
				exprText(fset, fl.Cond), planVar)
		}
		if !isSel(cond.Y, planVar, "HeartbeatSlots") {
			t.Fatalf("the heartbeat zero-init loop counts against %q, not %s.HeartbeatSlots. "+
				"That is the bound with the runtime consequence: counting against "+
				"%s.Workers zeroes one Array entry per WORKER instead of per SLOT — 6 of "+
				"192 on the six-worker loss cluster, 1 of 32 at the default of one "+
				"worker — and every un-zeroed slot reads as a "+
				"stale heartbeat, so the shim refuses to redirect for that worker "+
				"(#5718 fold r3)", exprText(fset, cond.Y), planVar, planVar)
		}
		return true
	})
	if !loopChecked {
		t.Fatal("no loop writing heartbeatMap.Update was found in programBootstrapMapsLocked — " +
			"if the zero-init moved, re-point this guard rather than dropping the check")
	}
}

// TestHeartbeatZeroSlotsNeverLeavesTheArray_5718 keeps the degenerate
// map-capacity boundary pinned across the fold F3 refactor: effectiveWorkers
// floors the worker count at 1 so the ctrl fields never report zero workers,
// which means heartbeatZeroSlots must cap the SLOT count itself when the Array
// is too small to hold one worker's slots. An uncapped multiply would index
// past the map.
func TestHeartbeatZeroSlotsNeverLeavesTheArray_5718(t *testing.T) {
	const perWorker = uint32(heartbeatSlotsPerWorker)
	for _, mapCap := range []uint32{0, 1, perWorker - 1, perWorker, perWorker + 1, 4096} {
		for _, workers := range []int{-1, 0, 1, 6, 1 << 32, int(^uint(0) >> 1)} {
			got := heartbeatZeroSlots(workers, mapCap)
			if got > mapCap {
				t.Fatalf("heartbeatZeroSlots(%d, %d) = %d exceeds the Array capacity",
					workers, mapCap, got)
			}
			if plan := planUserspaceWorkers(workers, mapCap); plan.HeartbeatSlots > mapCap {
				t.Fatalf("planUserspaceWorkers(%d, %d).HeartbeatSlots = %d exceeds the Array capacity",
					workers, mapCap, plan.HeartbeatSlots)
			}
			if mapCap >= perWorker && got == 0 {
				t.Fatalf("heartbeatZeroSlots(%d, %d) = 0: the Array can hold at least one "+
					"worker's slots, so nothing being zero-initialised leaves every "+
					"worker starting on stale heartbeat data", workers, mapCap)
			}
		}
	}
}
