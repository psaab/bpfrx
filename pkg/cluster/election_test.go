package cluster

import (
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestEffectivePriority(t *testing.T) {
	tests := []struct {
		base, weight, want int
	}{
		{200, 255, 200},   // full weight
		{200, 0, 0},       // zero weight
		{200, 128, 100},   // half weight (200*128/255 = 100)
		{100, 255, 100},   // full weight, lower priority
		{255, 255, 255},   // max everything
		{0, 255, 0},       // zero priority
		{200, -1, 0},      // negative weight → 0
	}
	for _, tt := range tests {
		got := EffectivePriority(tt.base, tt.weight)
		if got != tt.want {
			t.Errorf("EffectivePriority(%d, %d) = %d, want %d",
				tt.base, tt.weight, got, tt.want)
		}
	}
}

func TestElection_PeerLost_BecomesPrimary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events() // drain initial single-node election

	// Simulate peer arriving then disappearing.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 250, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	// Peer is primary with higher priority and preempt=false,
	// so we should be secondary if peer is primary.
	drainEvents(m, 1)

	// Now peer times out.
	m.handlePeerTimeout()

	// We should become primary (peer lost, weight > 0).
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary after peer timeout")
	}
}

func TestElection_PeerHigherPriority_Preempt(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100})) // preempt enabled
	m.UpdateConfig(cfg)
	<-m.Events() // primary from single-node election

	// Peer has higher priority.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// With preempt, peer's higher priority should make us secondary.
	if m.IsLocalPrimary(0) {
		t.Error("should be secondary when peer has higher effective priority with preempt")
	}
}

func TestElection_LocalHigherPriority_Preempt(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 250})) // preempt, high priority
	m.UpdateConfig(cfg)
	<-m.Events()

	// Peer has lower priority and is currently primary.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// With preempt, our higher priority means we should be primary.
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary when local has higher priority with preempt")
	}
}

func TestElection_NonPreempt_IncumbentStays(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 250})) // no preempt
	m.UpdateConfig(cfg)
	<-m.Events()

	// We are primary. Peer arrives with higher priority but preempt=false.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 255, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Non-preempt: incumbent (us) stays primary.
	if !m.IsLocalPrimary(0) {
		t.Error("should stay primary with non-preempt (incumbent)")
	}
}

func TestElection_SplitBrain_LowerNodeWins(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Both nodes think they are primary (split-brain).
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Node 0 < Node 1, so node 0 (us) should stay primary.
	if !m.IsLocalPrimary(0) {
		t.Error("lower node ID should win split-brain")
	}
}

func TestElection_SplitBrain_HigherNodeLoses(t *testing.T) {
	m := NewManager(1, 1) // We are node 1 (higher)
	cfg := makeConfig(makeRG(0, true, map[int]int{1: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Peer (node 0, lower ID) also primary.
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// We (node 1) should yield to node 0 (lower ID).
	if m.IsLocalPrimary(0) {
		t.Error("higher node ID should yield in split-brain")
	}
}

func TestElection_LocalWeightZero_BecomesSecondary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 250}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Peer is secondary.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// We're primary. Now our weight drops to 0.
	m.SetMonitorWeight(0, "trust0", true, 255)

	// Should become secondary regardless of priority.
	if m.IsLocalPrimary(0) {
		t.Error("should be secondary with weight 0")
	}
}

func TestElection_PeerWeightZero_BecomesPrimary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Peer has higher priority but weight 0.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 250, Weight: 0, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Peer weight=0 means we should be primary.
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary when peer has weight 0")
	}
}

func TestElection_ManualFailover_Preserved(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Manual failover.
	m.ManualFailover(0)
	drainEvents(m, 1)

	// Peer heartbeat arrives.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Manual failover should keep us secondary even with higher priority.
	if m.IsLocalPrimary(0) {
		t.Error("manual failover should keep us secondary")
	}
}

func TestElection_DisabledState_Preserved(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Force disabled.
	m.mu.Lock()
	m.groups[0].State = StateDisabled
	m.mu.Unlock()

	// Peer heartbeat arrives.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Disabled state should be preserved.
	states := m.GroupStates()
	if states[0].State != StateDisabled {
		t.Errorf("state = %s, want disabled", states[0].State)
	}
}

func TestElection_MultipleRGs(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200, 1: 100}),
		makeRG(1, true, map[int]int{0: 100, 1: 200}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Peer heartbeat with different priorities per RG.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// RG 0: we have higher priority (200 vs 100) → primary.
	if !m.IsLocalPrimary(0) {
		t.Error("RG 0: should be primary (higher priority)")
	}
	// RG 1: peer has higher priority (200 vs 100) with preempt → secondary.
	if m.IsLocalPrimary(1) {
		t.Error("RG 1: should be secondary (peer has higher priority)")
	}
}

func TestFormatInformation(t *testing.T) {
	m := NewManager(0, 1)
	cfg := &config.ClusterConfig{
		ClusterID:         1,
		NodeID:            0,
		HeartbeatInterval: 500,
		HeartbeatThreshold: 5,
		ControlInterface:  "fab0",
		RedundancyGroups: []*config.RedundancyGroup{
			makeRG(0, true, map[int]int{0: 200}),
		},
	}
	m.UpdateConfig(cfg)

	out := m.FormatInformation()
	if !strings.Contains(out, "Cluster ID: 1") {
		t.Error("missing cluster ID")
	}
	if !strings.Contains(out, "Node ID: 0") {
		t.Error("missing node ID")
	}
	if !strings.Contains(out, "Heartbeat interval: 500 ms") {
		t.Error("missing heartbeat interval")
	}
	if !strings.Contains(out, "Heartbeat threshold: 5") {
		t.Error("missing heartbeat threshold")
	}
	if !strings.Contains(out, "Control interface: fab0") {
		t.Error("missing control interface")
	}
	if !strings.Contains(out, "Peer status: lost") {
		t.Error("missing peer status")
	}
	if !strings.Contains(out, "Redundancy group 0:") {
		t.Error("missing RG 0 details")
	}
	if !strings.Contains(out, "Effective priority: 200") {
		t.Error("missing effective priority")
	}
}

func TestFormatInformation_WithPeer(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	// Add peer.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 150, Weight: 200, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	out := m.FormatInformation()
	if !strings.Contains(out, "alive (node1)") {
		t.Error("peer should show as alive")
	}
	if !strings.Contains(out, "Peer priority: 150") {
		t.Error("missing peer priority")
	}
}

func TestFormatStatus_WithPeer(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	// Add peer.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	out := m.FormatStatus()
	if !strings.Contains(out, "node0") {
		t.Error("missing local node")
	}
	if !strings.Contains(out, "node1") {
		t.Error("missing peer node")
	}
}

func TestElection_TiePriority_LowerNodeWins(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Both nodes have same effective priority, preempt enabled.
	// Both are secondary initially for election purposes.
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Node 0 (us) should win tie with lower ID.
	if !m.IsLocalPrimary(0) {
		t.Error("lower node ID should win tie")
	}
}

// drainEvents drains up to n events from the channel.
func drainEvents(m *Manager, n int) {
	for i := 0; i < n; i++ {
		select {
		case <-m.Events():
		default:
			return
		}
	}
}
