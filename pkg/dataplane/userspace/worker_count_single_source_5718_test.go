package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
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

// TestProgramBootstrapReadsConfiguredWorkersOnce_5718 binds the CALL SITE, not
// just the helper.
//
// planUserspaceWorkers can only guarantee one representation if
// programBootstrapMapsLocked actually routes every use through it. The
// pre-fold shape read cfg.Workers TWICE — once into the local `workers` the
// ctrl fields were cast from, once straight into heartbeatZeroSlots — and that
// second read is the whole defect. So the structural invariant is exactly
// "the raw configured value is consumed once", and this test asserts it on the
// function's AST: a re-introduced second read fails here even if every helper
// unit test still passes.
func TestProgramBootstrapReadsConfiguredWorkersOnce_5718(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "maps_sync.go", nil, 0)
	if err != nil {
		t.Fatalf("parse maps_sync.go: %v", err)
	}

	var body *ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "programBootstrapMapsLocked" {
			body = fn.Body
			return false
		}
		return true
	})
	if body == nil {
		t.Fatal("programBootstrapMapsLocked not found in maps_sync.go — if it was renamed, " +
			"re-point this guard at the new name rather than deleting it")
	}

	reads := 0
	var positions []string
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Workers" {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "cfg" {
			return true
		}
		reads++
		positions = append(positions, fset.Position(sel.Pos()).String())
		return true
	})

	if reads != 1 {
		t.Fatalf("programBootstrapMapsLocked reads cfg.Workers %d time(s) at %v; want exactly 1. "+
			"Every representation of the worker count — ctrl.Workers, ctrl.QueueCount and the "+
			"heartbeat zero-init bound — must come from the single planUserspaceWorkers call. "+
			"A second read of the raw configured value is how the ctrl fields and the heartbeat "+
			"loop came to describe the same quantity differently (#5718 fold F3)", reads, positions)
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
