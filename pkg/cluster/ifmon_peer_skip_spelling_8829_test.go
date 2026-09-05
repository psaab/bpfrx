package cluster

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestPeerInterfaceSkippedInBothSpellings8829 covers the THIRD defect in the
// #8829 family, and the one with the worst blast radius.
//
// Both monitor sites in monitor.go decide whether a missing interface belongs
// to the PEER before treating its absence as a local failure:
//
//	slot := config.InterfaceSlot(im.Interface)
//	if slot >= 0 && config.SlotToNodeID(slot) != mon.mgr.NodeID() {
//	        continue // peer's interface
//	}
//
// Before #8829 that guard was UNREACHABLE for the operational dash spelling by
// arithmetic: InterfaceSlot returned -1, so `slot >= 0` is unconditionally
// false and the peer-skip could never fire. Control fell through to "local
// interface missing, treating as down", which feeds the redundancy-group
// weight dampener.
//
// One config text describes BOTH nodes and is synced verbatim, and each RG
// monitors both nodes' interfaces at weight 255
// (docs/ha-cluster-userspace.conf). So with dash-spelled monitors node 0
// demotes ITSELF for node 1's link while node 1 does the same for node 0's —
// both members demoted over interfaces neither ever owned.
//
// The slash arm is the CONTROL: it passed before this fix and must keep
// passing, so a green here cannot come from the peer-skip being disabled
// outright.
func TestPeerInterfaceSkippedInBothSpellings8829(t *testing.T) {
	for _, sp := range []struct {
		name        string
		local, peer string
	}{
		{"slash (control)", "ge-0/0/0", "ge-7/0/0"},
		{"dash  (subject)", "ge-0-0-0", "ge-7-0-0"},
	} {
		t.Run(sp.name, func(t *testing.T) {
			m := NewManager(0, 1) // node 0
			nlh := newMockNlHandle()
			nlh.setLink("ge-0-0-0", true)
			nlh.setLink("ge-7-0-0", true)

			mon := NewMonitor(m, []*config.RedundancyGroup{{
				ID: 0,
				InterfaceMonitors: []*config.InterfaceMonitor{
					{Interface: sp.local, Weight: 255},
					{Interface: sp.peer, Weight: 255},
				},
			}})
			mon.nlHandle = nlh

			if ready, reasons := mon.RGInterfaceReady(0); !ready {
				t.Fatalf("baseline: both links up must be ready, got %v", reasons)
			}

			// The PEER's link disappears. On this node that is normal — the
			// peer owns it and publishes its state over the heartbeat.
			delete(nlh.links, "ge-7-0-0")
			ready, reasons := mon.RGInterfaceReady(0)
			if !ready {
				t.Errorf("node 0 reported NOT ready because the PEER's interface %q is absent "+
					"(reasons: %v). The peer-skip is `InterfaceSlot(...) >= 0 && "+
					"SlotToNodeID(slot) != NodeID`, so a spelling that does not parse makes it "+
					"unreachable and the node demotes itself for a link it never owned (#8829)",
					sp.peer, reasons)
			}

			// POSITIVE CONTROL: the LOCAL link must still fail readiness, or
			// "ready" above could just mean nothing is ever checked.
			delete(nlh.links, "ge-0-0-0")
			ready, reasons = mon.RGInterfaceReady(0)
			if ready {
				t.Errorf("missing LOCAL interface %q must fail readiness", sp.local)
			}
			if len(reasons) != 1 || !strings.Contains(reasons[0], sp.local) {
				t.Errorf("expected exactly one reason naming %q, got %v", sp.local, reasons)
			}
		})
	}
}
