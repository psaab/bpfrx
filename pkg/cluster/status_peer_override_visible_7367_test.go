package cluster

import (
	"strings"
	"testing"
)

// #7367: `show chassis cluster status` renders the POST-override peerGroups
// map, so a peer state THIS node substituted was indistinguishable from one the
// peer actually reported.
//
// That is what let the #6656 incident present as a healthy cluster on both
// nodes at once: node0 printed node1 as secondary-hold (because node0's own
// transfer-out override forced it) while node1 printed itself primary, and
// neither render carried anything anomalous.
//
// The pair below is the whole test. A single case cannot show a DIFFERENCE —
// asserting only the override case passes equally well against a render that
// appends the suffix unconditionally, and asserting only the reported case
// passes against one that never appends it.

func peerStatusLine7367(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "node1") {
			return strings.TrimSpace(l)
		}
	}
	t.Fatalf("no node1 row in status output:\n%s", out)
	return ""
}

func TestPeerReportedAndLocallyOverriddenStatesRenderDifferently7367(t *testing.T) {
	// --- Case A: the peer itself reports secondary-hold. No override. ---
	reported := NewManager(0, 1)
	reported.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	drainEvents(reported, 4)
	reported.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)}},
	})
	if got := reported.PeerGroupStates()[0].StateOverriddenLocally; got {
		t.Fatalf("case A must have NO local override, got StateOverriddenLocally=%v — "+
			"the fixture is not testing a peer-reported state", got)
	}
	reportedLine := peerStatusLine7367(t, reported.FormatStatus())

	// --- Case B: the peer reports PRIMARY; this node substitutes it. ---
	overridden := NewManager(0, 1)
	overridden.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	drainEvents(overridden, 4)
	overridden.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)}},
	})
	armTransferOutOverride(t, overridden, 0, 4242)
	overridden.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)}},
	})

	// Anti-vacuity: both cases must land on the SAME NodeState, or the render
	// difference below would just be the difference between two states and
	// would say nothing about the substitution being visible.
	pg := overridden.PeerGroupStates()[0]
	if pg.State != StateSecondaryHold {
		t.Fatalf("case B: expected the override to force secondary-hold, got %v — "+
			"the override is not being applied, so this test compares two "+
			"different states rather than a reported one against a substituted one",
			pg.State)
	}
	if !pg.StateOverriddenLocally {
		t.Fatal("case B: the peer state was substituted but StateOverriddenLocally is false, " +
			"so the render has no way to tell the operator")
	}
	overriddenLine := peerStatusLine7367(t, overridden.FormatStatus())

	// The property. Both peers are in secondary-hold; only one of them said so.
	if reportedLine == overriddenLine {
		t.Errorf("a peer state this node SUBSTITUTED renders identically to one the peer "+
			"REPORTED:\n  reported:   %s\n  overridden: %s\n\n"+
			"Both rows say secondary-hold and nothing distinguishes them, which is how an "+
			"RG-ownership divergence shows as a healthy cluster on both nodes at once "+
			"(#6656).", reportedLine, overriddenLine)
	}
	if strings.Contains(reportedLine, "local:") {
		t.Errorf("a peer-REPORTED state was annotated as a local override: %s\n"+
			"Marking every row makes the annotation meaningless.", reportedLine)
	}
	if !strings.Contains(overriddenLine, "local:") {
		t.Errorf("a SUBSTITUTED peer state was not annotated: %s", overriddenLine)
	}
}

// The reason must name WHICH mechanism substituted the state: a transfer-out
// override stays armed until cleared, a commit-grace window expires on its own,
// and the operator's response differs.
func TestOverrideReasonNamesTheMechanism7367(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	drainEvents(m, 4)
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)}},
	})
	armTransferOutOverride(t, m, 0, 4242)
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)}},
	})

	got := m.PeerGroupStates()[0].OverrideReason
	if got != "transfer-out override" {
		t.Errorf("OverrideReason = %q, want %q — an unnamed override tells the operator "+
			"the state is not the peer's without telling them which mechanism to look at, "+
			"and the two have different remedies", got, "transfer-out override")
	}
}
