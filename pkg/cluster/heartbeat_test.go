package cluster

import (
	"testing"
)

func TestMarshalUnmarshalHeartbeat(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 42,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 1, Priority: 150, Weight: 100, State: uint8(StateSecondary)},
		},
	}

	data := MarshalHeartbeat(pkt)
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.NodeID != 1 {
		t.Errorf("NodeID = %d, want 1", got.NodeID)
	}
	if got.ClusterID != 42 {
		t.Errorf("ClusterID = %d, want 42", got.ClusterID)
	}
	if len(got.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(got.Groups))
	}
	if got.Groups[0].GroupID != 0 || got.Groups[0].Priority != 200 || got.Groups[0].Weight != 255 {
		t.Errorf("group 0 = %+v", got.Groups[0])
	}
	if got.Groups[0].State != uint8(StatePrimary) {
		t.Errorf("group 0 state = %d, want %d", got.Groups[0].State, StatePrimary)
	}
	if got.Groups[1].GroupID != 1 || got.Groups[1].Priority != 150 || got.Groups[1].Weight != 100 {
		t.Errorf("group 1 = %+v", got.Groups[1])
	}
	if got.Groups[1].State != uint8(StateSecondary) {
		t.Errorf("group 1 state = %d, want %d", got.Groups[1].State, StateSecondary)
	}
}

func TestMarshalUnmarshalHeartbeat_NoGroups(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
	}
	data := MarshalHeartbeat(pkt)
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Groups) != 0 {
		t.Errorf("groups = %d, want 0", len(got.Groups))
	}
}

func TestUnmarshalHeartbeat_TooShort(t *testing.T) {
	_, err := UnmarshalHeartbeat([]byte{0x42, 0x50})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestUnmarshalHeartbeat_BadMagic(t *testing.T) {
	data := make([]byte, heartbeatHeaderSize)
	copy(data[0:4], "DEAD")
	data[4] = heartbeatVersion
	_, err := UnmarshalHeartbeat(data)
	if err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestUnmarshalHeartbeat_BadVersion(t *testing.T) {
	data := make([]byte, heartbeatHeaderSize)
	copy(data[0:4], heartbeatMagic)
	data[4] = 99 // bad version
	_, err := UnmarshalHeartbeat(data)
	if err == nil {
		t.Error("expected error for bad version")
	}
}

func TestUnmarshalHeartbeat_Truncated(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: 1},
		},
	}
	data := MarshalHeartbeat(pkt)
	// Truncate the group data.
	_, err := UnmarshalHeartbeat(data[:heartbeatHeaderSize+2])
	if err == nil {
		t.Error("expected error for truncated group data")
	}
}

func TestMarshalHeartbeat_Size(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: 1},
			{GroupID: 1, Priority: 100, Weight: 200, State: 0},
		},
	}
	data := MarshalHeartbeat(pkt)
	expected := heartbeatHeaderSize + 2*heartbeatGroupSize + 1 // +1 for NumMonitors byte
	if len(data) != expected {
		t.Errorf("size = %d, want %d", len(data), expected)
	}
}

func TestHandlePeerHeartbeat(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)
	// Drain initial election event.
	<-m.Events()

	// Simulate peer heartbeat.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if !m.PeerAlive() {
		t.Error("peer should be alive after heartbeat")
	}
	if m.PeerNodeID() != 1 {
		t.Errorf("peer node ID = %d, want 1", m.PeerNodeID())
	}

	peerGroups := m.PeerGroupStates()
	if pg, ok := peerGroups[0]; !ok {
		t.Error("peer group 0 not found")
	} else if pg.Priority != 100 {
		t.Errorf("peer group 0 priority = %d, want 100", pg.Priority)
	}
}

func TestHandlePeerTimeout(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()

	// First set peer alive.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 250, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if !m.PeerAlive() {
		t.Fatal("peer should be alive")
	}

	// Simulate timeout.
	m.handlePeerTimeout()

	if m.PeerAlive() {
		t.Error("peer should not be alive after timeout")
	}
	peerGroups := m.PeerGroupStates()
	if len(peerGroups) != 0 {
		t.Errorf("peer groups should be cleared, got %d", len(peerGroups))
	}
}

func TestMarshalUnmarshalHeartbeat_WithMonitors(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
		Monitors: []HeartbeatMonitor{
			{RGID: 1, Weight: 255, Up: true, Interface: "ge-0/0/0"},
			{RGID: 1, Weight: 255, Up: false, Interface: "ge-0/0/1"},
			{RGID: 2, Weight: 128, Up: true, Interface: "ge-0/0/2"},
		},
	}

	data := MarshalHeartbeat(pkt)
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(got.Groups))
	}
	if len(got.Monitors) != 3 {
		t.Fatalf("monitors = %d, want 3", len(got.Monitors))
	}

	// Check first monitor.
	if got.Monitors[0].RGID != 1 || got.Monitors[0].Weight != 255 || !got.Monitors[0].Up || got.Monitors[0].Interface != "ge-0/0/0" {
		t.Errorf("monitor 0 = %+v", got.Monitors[0])
	}
	// Check second monitor (down).
	if got.Monitors[1].Up {
		t.Error("monitor 1 should be down")
	}
	if got.Monitors[1].Interface != "ge-0/0/1" {
		t.Errorf("monitor 1 interface = %q, want ge-0/0/1", got.Monitors[1].Interface)
	}
	// Check third monitor.
	if got.Monitors[2].RGID != 2 || got.Monitors[2].Weight != 128 {
		t.Errorf("monitor 2 = %+v", got.Monitors[2])
	}
}

func TestMarshalUnmarshalHeartbeat_NoMonitors_BackwardsCompat(t *testing.T) {
	// Simulate an old-format packet (no monitor section) — manually build.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 5,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 200, State: uint8(StateSecondary)},
		},
	}
	// Marshal will include empty monitor section (NumMonitors=0).
	data := MarshalHeartbeat(pkt)
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Monitors) != 0 {
		t.Errorf("monitors = %d, want 0", len(got.Monitors))
	}

	// Also test with truly old-format data (no monitor bytes at all).
	oldSize := heartbeatHeaderSize + 1*heartbeatGroupSize
	oldData := data[:oldSize]
	got2, err := UnmarshalHeartbeat(oldData)
	if err != nil {
		t.Fatalf("unmarshal old format: %v", err)
	}
	if len(got2.Monitors) != 0 {
		t.Errorf("monitors from old format = %d, want 0", len(got2.Monitors))
	}
	if len(got2.Groups) != 1 {
		t.Errorf("groups from old format = %d, want 1", len(got2.Groups))
	}
}

func TestUnmarshalHeartbeat_TruncatedMonitor(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Monitors: []HeartbeatMonitor{
			{RGID: 1, Weight: 255, Up: true, Interface: "ge-0/0/0"},
		},
	}
	data := MarshalHeartbeat(pkt)
	// Truncate in the middle of the monitor entry.
	_, err := UnmarshalHeartbeat(data[:len(data)-3])
	if err == nil {
		t.Error("expected error for truncated monitor data")
	}
}

func TestPeerMonitorStatuses(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200, 1: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// No peer monitors initially.
	if pm := m.PeerMonitorStatuses(); pm != nil {
		t.Errorf("expected nil peer monitors, got %d", len(pm))
	}

	// Simulate peer heartbeat with monitors.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
		Monitors: []HeartbeatMonitor{
			{RGID: 0, Weight: 255, Up: true, Interface: "ge-7/0/0"},
			{RGID: 0, Weight: 255, Up: false, Interface: "ge-7/0/1"},
		},
	}
	m.handlePeerHeartbeat(pkt)

	pm := m.PeerMonitorStatuses()
	if len(pm) != 2 {
		t.Fatalf("peer monitors = %d, want 2", len(pm))
	}
	if pm[0].Interface != "ge-7/0/0" || !pm[0].Up {
		t.Errorf("peer monitor 0 = %+v", pm[0])
	}
	if pm[1].Interface != "ge-7/0/1" || pm[1].Up {
		t.Errorf("peer monitor 1 = %+v", pm[1])
	}

	// After timeout, peer monitors should be cleared.
	m.handlePeerTimeout()
	if pm := m.PeerMonitorStatuses(); pm != nil {
		t.Errorf("expected nil after timeout, got %d", len(pm))
	}
}

func TestBuildHeartbeat(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, true, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)

	pkt := m.buildHeartbeat()
	if pkt.NodeID != 0 {
		t.Errorf("NodeID = %d, want 0", pkt.NodeID)
	}
	if pkt.ClusterID != 1 {
		t.Errorf("ClusterID = %d, want 1", pkt.ClusterID)
	}
	if len(pkt.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(pkt.Groups))
	}
}
