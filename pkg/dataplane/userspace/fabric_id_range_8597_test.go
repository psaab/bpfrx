package userspace

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #8597 K78: `SetFabricForwarding` dispatched with `if id == 1 { fabric1 } else
// { fabric0 }`, so every FabricID other than 1 — 2, 3, 255 — silently programmed
// FABRIC 0 and reported success. `FabricID` is a uint8: the type admits 256
// values while the dispatch distinguished two, and the mismatch resolved by
// writing the caller's data into the wrong fabric.
//
// NOT A LIVE DEFECT, and the cells say so rather than implying otherwise. Every
// call site in the tree passes a literal 0 or 1 (daemon_ha_fabric.go), and the
// only two loops over this axis — controllers_binding_table_6871_test.go and
// cluster/heartbeat_ack_incarnation_5718_test.go — both iterate {0, 1}. The
// change refuses nothing that exists.
//
// What it removes is the SILENCE on the day a third fabric is added, which is
// exactly the moment an `else` arm stops being a two-valued dispatch and starts
// being a wrong answer that reports success.

func TestFabricIDOutOfRangeIsRefusedNotAliasedToFabric0_8597K78(t *testing.T) {
	for _, id := range []dataplane.FabricID{2, 3, 255} {
		ops := &recordingHAOps6871{}
		c := userspaceHAController{manager: ops}
		err := c.SetFabricForwarding(context.Background(), id, dataplane.FabricFwdInfo{})
		if err == nil {
			t.Errorf("#8597 K78: SetFabricForwarding(fabric %d) returned nil. An id "+
				"outside {0,1} must be refused, not accepted", id)
		}
		// The assertion that actually names the harm: the refusal must happen
		// INSTEAD of a write, not alongside one. An error return with the write
		// already performed still puts the caller's fabric data into fabric 0.
		if ops.fwdCalls != 0 {
			t.Errorf("#8597 K78: fabric %d was ALIASED onto fabric 0 (UpdateFabricFwd "+
				"called %d times). The caller's fabric data went into the wrong "+
				"fabric and the call reported success", id, ops.fwdCalls)
		}
		if ops.fwd1Calls != 0 {
			t.Errorf("fabric %d reached UpdateFabricFwd1 (%d calls)", id, ops.fwd1Calls)
		}
		if ops.syncCalls != 0 {
			t.Errorf("fabric %d pushed helper fabric state (%d SyncFabricState calls) "+
				"for a write that must not have happened", id, ops.syncCalls)
		}
	}
}

// THE CONTROL, and it is the one that matters for a change of this shape: a
// range check is exactly the kind of remedy that refuses the configuration the
// product actually ships. Both real fabrics must still program, and must still
// reach their OWN map — a gate that rejected everything would pass the cell
// above completely.
func TestBothRealFabricsStillProgram_8597K78(t *testing.T) {
	for _, tc := range []struct {
		id       dataplane.FabricID
		wantFwd  int
		wantFwd1 int
	}{
		{id: 0, wantFwd: 1, wantFwd1: 0},
		{id: 1, wantFwd: 0, wantFwd1: 1},
	} {
		ops := &recordingHAOps6871{}
		c := userspaceHAController{manager: ops}
		if err := c.SetFabricForwarding(context.Background(), tc.id, dataplane.FabricFwdInfo{}); err != nil {
			t.Fatalf("CONTROL: fabric %d is a REAL fabric and must still program: %v", tc.id, err)
		}
		if ops.fwdCalls != tc.wantFwd || ops.fwd1Calls != tc.wantFwd1 {
			t.Errorf("CONTROL: fabric %d wrote fwd=%d fwd1=%d, want fwd=%d fwd1=%d — the "+
				"two fabrics must reach their OWN map, which is the property the "+
				"original `else` arm lost", tc.id, ops.fwdCalls, ops.fwd1Calls,
				tc.wantFwd, tc.wantFwd1)
		}
		if ops.syncCalls != 1 {
			t.Errorf("CONTROL: fabric %d SyncFabricState calls = %d, want 1", tc.id, ops.syncCalls)
		}
	}
}
