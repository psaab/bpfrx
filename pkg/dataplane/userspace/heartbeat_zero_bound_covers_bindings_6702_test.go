package userspace

import "testing"

// TestHeartbeatZeroBoundCoversEveryBindingSlot_6702 is the #6702 blocker-2
// fail-on-revert, written against the DEFECT rather than against the constant.
//
// THE DEFECT. programBootstrapMapsLocked zero-initialises the leading
// userspace_heartbeat slots on every non-same-plan apply. The bound used to be
// `effectiveWorkers(cfg.Workers) * heartbeatSlotsPerWorker` — derived from the
// configured WORKER count. But a heartbeat slot is indexed by the BINDING
// SLOT: the XDP shim reads `USERSPACE_HEARTBEAT.get(binding.slot)`
// (userspace-xdp/src/lib.rs) and the helper writes
// `update_heartbeat_slot(fd, slot, ..)` (userspace-dp/src/afxdp/bpf_map/ha.rs).
// The binding count is `min(rx_queues) * interfaces`, which has never been a
// function of cfg.Workers — so the two quantities were never the same thing,
// and the loop zeroed a prefix that could be far shorter than the binding set.
//
// WHY THAT MATTERS, in the direction that makes it worth fixing. A zeroed slot
// reads as stale (`bpf_ktime_get_ns() >> 0`) and the shim correctly refuses to
// redirect until userspace starts updating it. A slot left holding the
// PREVIOUS load's timestamp reads as FRESH for as long as that timestamp is
// inside the heartbeat timeout — so it masks a helper that has stopped,
// defeating the exact liveness mechanism the heartbeat exists for, on
// precisely the slots nobody zeroed.
//
// The cases below are ordinary appliance shapes, not contrivances: the default
// is `Workers: 1` (capabilities.go), so the old bound was 32 slots on a box
// that can easily plan more bindings than that.
//
// FAIL-ON-REVERT: restoring a worker-derived bound makes `covered` false for
// every row whose binding count exceeds the old prefix.
func TestHeartbeatZeroBoundCoversEveryBindingSlot_6702(t *testing.T) {
	const mapCap = uint32(4096) // userspace_heartbeat Array max_entries (lib.rs)
	const perWorker = uint32(heartbeatSlotsPerWorker)

	cases := []struct {
		name       string
		workers    int
		ifaces     uint32
		minQueues  uint32
		wantOldGap bool // did the pre-#6702 worker-derived bound leave slots un-zeroed?
	}{
		{
			// The reported shape: three interfaces at the 16-queue maximum.
			name: "default workers, 3 ifaces x 16 queues", workers: 1,
			ifaces: 3, minQueues: 16, wantOldGap: true,
		},
		{
			// The loss cluster's queue count on a six-interface box.
			name: "default workers, 6 ifaces x 6 queues", workers: 1,
			ifaces: 6, minQueues: 6, wantOldGap: true,
		},
		{
			// Exactly at the old prefix — the boundary, which must be
			// covered by both bounds. Present so the table cannot pass by
			// every row being a gap.
			name: "default workers, 2 ifaces x 16 queues", workers: 1,
			ifaces: 2, minQueues: 16, wantOldGap: false,
		},
		{
			// A worker count large enough that the old bound happened to
			// cover the binding set. The fix must not regress these.
			name: "six workers, 3 ifaces x 6 queues", workers: 6,
			ifaces: 3, minQueues: 6, wantOldGap: false,
		},
	}

	sawGap, sawNoGap := false, false
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bindings := tc.ifaces * tc.minQueues
			// The highest slot the shim can be asked to read for this plan.
			// Slots are assigned densely from 0, so the count IS the bound.
			plan := planUserspaceWorkers(tc.workers, mapCap)

			// The pre-#6702 bound, recomputed here rather than called, so this
			// test keeps its subject after the production helper is gone.
			oldBound := uint32(effectiveWorkers(tc.workers, mapCap)) * perWorker
			gap := bindings > oldBound
			if gap != tc.wantOldGap {
				t.Fatalf("%d bindings vs the old worker-derived bound %d: gap=%v, want %v — "+
					"the fixture no longer demonstrates what it was chosen for",
					bindings, oldBound, gap, tc.wantOldGap)
			}
			if gap {
				sawGap = true
			} else {
				sawNoGap = true
			}

			// The property: the bound covers every binding slot this plan can
			// produce, whatever the worker count is.
			if plan.HeartbeatSlots < bindings {
				t.Fatalf("%d bindings (%d ifaces x %d queues) with workers=%d, but only %d "+
					"heartbeat slots are zero-initialised — slots %d..%d keep the previous "+
					"load's timestamps and read as a FRESH heartbeat for a helper that may "+
					"have stopped (#6702)",
					bindings, tc.ifaces, tc.minQueues, tc.workers, plan.HeartbeatSlots,
					plan.HeartbeatSlots, bindings-1)
			}
		})
	}

	// The table must contain BOTH kinds of row. Without a gap row the test
	// cannot observe the defect; without a no-gap row it cannot observe that
	// the fix is not simply "always true because every fixture is extreme".
	if !sawGap {
		t.Fatal("no fixture exercised a binding count above the old worker-derived bound: " +
			"this table cannot see the #6702 defect at all")
	}
	if !sawNoGap {
		t.Fatal("every fixture was a gap: the table has no control row where the old bound " +
			"was already sufficient")
	}
}
