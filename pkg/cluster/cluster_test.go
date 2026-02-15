package cluster

import (
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func makeConfig(groups ...*config.RedundancyGroup) *config.ClusterConfig {
	return &config.ClusterConfig{
		RethCount:        len(groups),
		RedundancyGroups: groups,
	}
}

func makeRG(id int, preempt bool, priorities map[int]int, monitors ...*config.InterfaceMonitor) *config.RedundancyGroup {
	return &config.RedundancyGroup{
		ID:                id,
		NodePriorities:    priorities,
		Preempt:           preempt,
		InterfaceMonitors: monitors,
	}
}

func TestNewManager(t *testing.T) {
	m := NewManager(0, 1)
	if m.NodeID() != 0 {
		t.Fatalf("NodeID = %d, want 0", m.NodeID())
	}
	if m.ClusterID() != 1 {
		t.Fatalf("ClusterID = %d, want 1", m.ClusterID())
	}
	if states := m.GroupStates(); len(states) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(states))
	}
}

func TestUpdateConfig_CreatesRGs(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
		makeRG(1, true, map[int]int{0: 150, 1: 250}),
	)
	m.UpdateConfig(cfg)

	states := m.GroupStates()
	if len(states) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(states))
	}

	// RG 0: node0 priority=200
	if states[0].GroupID != 0 {
		t.Errorf("group 0 ID = %d", states[0].GroupID)
	}
	if states[0].LocalPriority != 200 {
		t.Errorf("group 0 priority = %d, want 200", states[0].LocalPriority)
	}
	if states[0].Preempt {
		t.Error("group 0 preempt should be false")
	}

	// RG 1: node0 priority=150
	if states[1].GroupID != 1 {
		t.Errorf("group 1 ID = %d", states[1].GroupID)
	}
	if states[1].LocalPriority != 150 {
		t.Errorf("group 1 priority = %d, want 150", states[1].LocalPriority)
	}
	if !states[1].Preempt {
		t.Error("group 1 preempt should be true")
	}
}

func TestUpdateConfig_SingleNodeElection(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)

	if !m.IsLocalPrimary(0) {
		t.Error("node should be primary after single-node election")
	}

	// Check event was emitted.
	select {
	case ev := <-m.Events():
		if ev.OldState != StateSecondary || ev.NewState != StatePrimary {
			t.Errorf("event = %v->%v, want secondary->primary", ev.OldState, ev.NewState)
		}
	default:
		t.Error("expected election event")
	}
}

func TestUpdateConfig_PreservesState(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)

	// Drain events from initial election.
	for i := 0; i < 2; i++ {
		<-m.Events()
	}

	// Manually failover RG 0.
	m.ManualFailover(0)

	// Re-apply config with updated priority but same groups.
	cfg2 := makeConfig(
		makeRG(0, true, map[int]int{0: 250}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg2)

	states := m.GroupStates()
	// RG 0: priority updated, but manual failover should be preserved.
	if states[0].LocalPriority != 250 {
		t.Errorf("RG 0 priority = %d, want 250", states[0].LocalPriority)
	}
	if !states[0].ManualFailover {
		t.Error("RG 0 manual failover should be preserved")
	}
	if states[0].State != StateSecondary {
		t.Errorf("RG 0 state = %s, want secondary (manual failover)", states[0].State)
	}
	if !states[0].Preempt {
		t.Error("RG 0 preempt should be updated to true")
	}
}

func TestUpdateConfig_RemovesDeletedGroups(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)

	// Remove RG 1 from config.
	cfg2 := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg2)

	states := m.GroupStates()
	if len(states) != 1 {
		t.Fatalf("expected 1 group after removal, got %d", len(states))
	}
	if states[0].GroupID != 0 {
		t.Errorf("remaining group ID = %d, want 0", states[0].GroupID)
	}
}

func TestUpdateConfig_NilConfig(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(nil) // should not panic
	if len(m.GroupStates()) != 0 {
		t.Error("nil config should not create groups")
	}
}

func TestSetMonitorWeight_Down(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)

	// Drain election event.
	<-m.Events()

	// Mark an interface down with weight 100.
	m.SetMonitorWeight(0, "trust0", true, 100)

	states := m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight = %d, want 155 (255-100)", states[0].Weight)
	}
	if len(states[0].MonitorFails) != 1 || states[0].MonitorFails[0] != "trust0" {
		t.Errorf("monitor fails = %v, want [trust0]", states[0].MonitorFails)
	}
	// Still primary since weight > 0.
	if !m.IsLocalPrimary(0) {
		t.Error("should still be primary with weight 155")
	}
}

func TestSetMonitorWeight_AllDown(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	<-m.Events() // drain initial election

	// Bring down two interfaces totaling 255+.
	m.SetMonitorWeight(0, "trust0", true, 200)
	m.SetMonitorWeight(0, "untrust0", true, 100)

	states := m.GroupStates()
	if states[0].Weight != 0 {
		t.Errorf("weight = %d, want 0 (clamped)", states[0].Weight)
	}
	if m.IsLocalPrimary(0) {
		t.Error("should not be primary with weight 0")
	}
}

func TestSetMonitorWeight_Recovery(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()

	m.SetMonitorWeight(0, "trust0", true, 255)
	// Weight = 0, secondary.

	// Recover.
	m.SetMonitorWeight(0, "trust0", false, 0)
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 after recovery", states[0].Weight)
	}
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary after recovery")
	}
	if len(states[0].MonitorFails) != 0 {
		t.Errorf("monitor fails = %v, want empty", states[0].MonitorFails)
	}
}

func TestSetMonitorWeight_UnknownRG(t *testing.T) {
	m := NewManager(0, 1)
	// Should not panic on unknown RG.
	m.SetMonitorWeight(99, "trust0", true, 100)
}

func TestSetMonitorWeight_DuplicateDown(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Same interface reported down twice — should not double-count.
	m.SetMonitorWeight(0, "trust0", true, 100)
	m.SetMonitorWeight(0, "trust0", true, 100)

	states := m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight = %d, want 155 (no double-count)", states[0].Weight)
	}
	if len(states[0].MonitorFails) != 1 {
		t.Errorf("monitor fails count = %d, want 1", len(states[0].MonitorFails))
	}
}

func TestManualFailover(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events() // election event

	if err := m.ManualFailover(0); err != nil {
		t.Fatal(err)
	}

	states := m.GroupStates()
	if states[0].State != StateSecondary {
		t.Errorf("state = %s, want secondary after failover", states[0].State)
	}
	if !states[0].ManualFailover {
		t.Error("ManualFailover should be true")
	}
	if states[0].FailoverCount != 1 {
		t.Errorf("failover count = %d, want 1", states[0].FailoverCount)
	}

	// Failover event should be emitted.
	select {
	case ev := <-m.Events():
		if ev.OldState != StatePrimary || ev.NewState != StateSecondary {
			t.Errorf("event = %v->%v, want primary->secondary", ev.OldState, ev.NewState)
		}
	default:
		t.Error("expected failover event")
	}
}

func TestManualFailover_UnknownRG(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.ManualFailover(99); err == nil {
		t.Error("expected error for unknown RG")
	}
}

func TestResetFailover(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.ManualFailover(0)
	<-m.Events() // drain failover event

	if err := m.ResetFailover(0); err != nil {
		t.Fatal(err)
	}

	states := m.GroupStates()
	if states[0].ManualFailover {
		t.Error("ManualFailover should be cleared")
	}
	if states[0].State != StatePrimary {
		t.Errorf("state = %s, want primary after reset", states[0].State)
	}
	// Failover count should be preserved.
	if states[0].FailoverCount != 1 {
		t.Errorf("failover count = %d, want 1 (preserved)", states[0].FailoverCount)
	}
}

func TestResetFailover_UnknownRG(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.ResetFailover(99); err == nil {
		t.Error("expected error for unknown RG")
	}
}

func TestIsLocalPrimary(t *testing.T) {
	m := NewManager(0, 1)
	// Non-existent RG should return false.
	if m.IsLocalPrimary(0) {
		t.Error("should return false for non-existent RG")
	}

	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary after election")
	}
}

func TestGroupStates_Sorted(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(2, false, map[int]int{0: 100}),
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)

	states := m.GroupStates()
	if len(states) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(states))
	}
	for i, expected := range []int{0, 1, 2} {
		if states[i].GroupID != expected {
			t.Errorf("states[%d].GroupID = %d, want %d", i, states[i].GroupID, expected)
		}
	}
}

func TestGroupStates_Snapshot(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	states := m.GroupStates()
	// Modify returned state — should not affect internal state.
	states[0].LocalPriority = 999
	states2 := m.GroupStates()
	if states2[0].LocalPriority != 200 {
		t.Error("GroupStates should return snapshot, not reference")
	}
}

func TestGroupState_Single(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	rg := m.GroupState(0)
	if rg == nil {
		t.Fatal("GroupState(0) returned nil")
	}
	if rg.LocalPriority != 200 {
		t.Errorf("priority = %d, want 200", rg.LocalPriority)
	}

	if m.GroupState(99) != nil {
		t.Error("GroupState(99) should return nil")
	}
}

func TestNodeStateString(t *testing.T) {
	tests := []struct {
		state NodeState
		want  string
	}{
		{StateSecondary, "secondary"},
		{StatePrimary, "primary"},
		{StateSecondaryHold, "secondary-hold"},
		{StateLost, "lost"},
		{StateDisabled, "disabled"},
		{NodeState(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", int(tt.state), got, tt.want)
		}
	}
}

func TestFormatStatus(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)

	out := m.FormatStatus()
	if !strings.Contains(out, "Cluster ID: 1") {
		t.Error("missing cluster ID")
	}
	if !strings.Contains(out, "Node name: node0") {
		t.Error("missing node name")
	}
	if !strings.Contains(out, "Redundancy group: 0") {
		t.Error("missing RG 0")
	}
	if !strings.Contains(out, "Redundancy group: 1") {
		t.Error("missing RG 1")
	}
	if !strings.Contains(out, "primary") {
		t.Error("missing primary status")
	}
	if !strings.Contains(out, "200") {
		t.Error("missing priority 200")
	}
	if !strings.Contains(out, "yes") {
		t.Error("missing preempt yes")
	}
}

func TestFormatStatus_WithMonitorFails(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	m.SetMonitorWeight(0, "trust0", true, 50)
	m.SetMonitorWeight(0, "untrust0", true, 50)

	out := m.FormatStatus()
	if !strings.Contains(out, "trust0") {
		t.Error("missing failed monitor trust0")
	}
	if !strings.Contains(out, "untrust0") {
		t.Error("missing failed monitor untrust0")
	}
}

func TestMultipleMonitorWeights(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Three interfaces down with different weights.
	m.SetMonitorWeight(0, "trust0", true, 50)
	m.SetMonitorWeight(0, "untrust0", true, 75)
	m.SetMonitorWeight(0, "dmz0", true, 30)

	states := m.GroupStates()
	expectedWeight := 255 - 50 - 75 - 30 // = 100
	if states[0].Weight != expectedWeight {
		t.Errorf("weight = %d, want %d", states[0].Weight, expectedWeight)
	}

	// Recover one.
	m.SetMonitorWeight(0, "untrust0", false, 0)
	states = m.GroupStates()
	expectedWeight = 255 - 50 - 30 // = 175
	if states[0].Weight != expectedWeight {
		t.Errorf("weight after recovery = %d, want %d", states[0].Weight, expectedWeight)
	}
}

func TestMonitorFailsSorted(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	m.SetMonitorWeight(0, "untrust0", true, 50)
	m.SetMonitorWeight(0, "dmz0", true, 50)
	m.SetMonitorWeight(0, "trust0", true, 50)

	states := m.GroupStates()
	want := []string{"dmz0", "trust0", "untrust0"}
	if len(states[0].MonitorFails) != 3 {
		t.Fatalf("monitor fails count = %d, want 3", len(states[0].MonitorFails))
	}
	for i, name := range want {
		if states[0].MonitorFails[i] != name {
			t.Errorf("monitor fails[%d] = %s, want %s", i, states[0].MonitorFails[i], name)
		}
	}
}

func TestElectionSkipsDisabled(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Force state to disabled directly (simulating admin action).
	m.mu.Lock()
	m.groups[0].State = StateDisabled
	m.mu.Unlock()

	// Re-apply config — disabled state should be preserved by electSingleNode.
	m.UpdateConfig(cfg)
	states := m.GroupStates()
	if states[0].State != StateDisabled {
		t.Errorf("state = %s, want disabled (should be preserved)", states[0].State)
	}
}

func TestActiveActive_DifferentPrimariesPerRG(t *testing.T) {
	// Active/Active: RG 0 primary on node0, RG 1 primary on node1.
	// This validates that different RGs can have different primaries,
	// which is the core requirement for active/active mode.
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200, 1: 100}), // node0 higher for RG0
		makeRG(1, true, map[int]int{0: 100, 1: 200}), // node1 higher for RG1
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Peer heartbeat: node1 has RG0=secondary, RG1=primary.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Verify active/active: RG 0 primary here, RG 1 secondary here.
	if !m.IsLocalPrimary(0) {
		t.Error("RG 0: should be primary on node0 (active/active)")
	}
	if m.IsLocalPrimary(1) {
		t.Error("RG 1: should be secondary on node0 (active/active)")
	}

	// Verify peer states reflect the complementary configuration.
	peerStates := m.PeerGroupStates()
	if pg, ok := peerStates[0]; !ok || pg.State != StateSecondary {
		t.Errorf("peer RG 0: expected secondary, got %v", peerStates[0])
	}
	if pg, ok := peerStates[1]; !ok || pg.State != StatePrimary {
		t.Errorf("peer RG 1: expected primary, got %v", peerStates[1])
	}
}

func TestForceSecondary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Simulate peer alive.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Both RGs should be primary.
	if !m.IsLocalPrimary(0) || !m.IsLocalPrimary(1) {
		t.Fatal("both RGs should be primary before ForceSecondary")
	}

	// ForceSecondary.
	if err := m.ForceSecondary(); err != nil {
		t.Fatal(err)
	}

	// Both should now be secondary.
	states := m.GroupStates()
	for _, rg := range states {
		if rg.State != StateSecondary {
			t.Errorf("RG %d: state = %s, want secondary after ForceSecondary", rg.GroupID, rg.State)
		}
		if rg.Weight != 0 {
			t.Errorf("RG %d: weight = %d, want 0 after ForceSecondary", rg.GroupID, rg.Weight)
		}
		if !rg.ManualFailover {
			t.Errorf("RG %d: ManualFailover should be true after ForceSecondary", rg.GroupID)
		}
	}

	// Drain the failover events.
	drainEvents(m, 2)
}

func TestForceSecondary_NoPeer(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	// No peer — should fail.
	if err := m.ForceSecondary(); err == nil {
		t.Error("ForceSecondary should fail without active peer")
	}
}

func TestForceSecondary_SkipsDisabled(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Simulate peer alive.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Disable RG 1.
	m.mu.Lock()
	m.groups[1].State = StateDisabled
	m.mu.Unlock()

	if err := m.ForceSecondary(); err != nil {
		t.Fatal(err)
	}

	states := m.GroupStates()
	// RG 0: should be secondary.
	if states[0].State != StateSecondary {
		t.Errorf("RG 0: state = %s, want secondary", states[0].State)
	}
	// RG 1: should remain disabled.
	if states[1].State != StateDisabled {
		t.Errorf("RG 1: state = %s, want disabled (should be preserved)", states[1].State)
	}
}

func TestEventsChannel(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)

	// Should have 2 events (both RGs elected to primary).
	for i := 0; i < 2; i++ {
		select {
		case ev := <-m.Events():
			if ev.NewState != StatePrimary {
				t.Errorf("event %d: new state = %s, want primary", i, ev.NewState)
			}
		default:
			t.Errorf("expected event %d", i)
		}
	}

	// No more events.
	select {
	case ev := <-m.Events():
		t.Errorf("unexpected extra event: %+v", ev)
	default:
	}
}
