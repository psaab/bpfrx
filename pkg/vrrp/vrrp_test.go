package vrrp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

// --- Collection tests ---

func TestCollectInstances_Nil(t *testing.T) {
	instances := CollectInstances(nil)
	if instances != nil {
		t.Errorf("expected nil, got %v", instances)
	}
}

func TestCollectRethInstances(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24", "10.0.1.2/24"}},
						1: {Addresses: []string{"10.0.2.1/24"}},
					},
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"172.16.0.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
				// No RedundancyGroup — should be excluded.
				"trust0": {
					Name:            "trust0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"192.168.1.1/24"}},
					},
				},
			},
		},
	}
	pri := map[int]int{1: 200, 2: 100}
	instances := CollectRethInstances(cfg, pri)

	if len(instances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(instances))
	}

	// Sorted by name: reth0 before reth1 → resolved to ge-0-0-0 / ge-0-0-1.
	inst0 := instances[0]
	if inst0.Interface != "ge-0-0-0" {
		t.Errorf("inst0.Interface = %q, want ge-0-0-0", inst0.Interface)
	}
	if inst0.GroupID != 101 {
		t.Errorf("inst0.GroupID = %d, want 101", inst0.GroupID)
	}
	if inst0.Priority != 200 {
		t.Errorf("inst0.Priority = %d, want 200", inst0.Priority)
	}
	if inst0.Preempt {
		t.Error("inst0.Preempt should be false (no RG preempt config)")
	}
	if !inst0.AcceptData {
		t.Error("inst0.AcceptData should be true")
	}
	if inst0.AdvertiseInterval != 30 {
		t.Errorf("inst0.AdvertiseInterval = %d, want 30", inst0.AdvertiseInterval)
	}
	// Unit 0 addresses then unit 1 (sorted by unit number).
	wantVIPs := []string{"10.0.1.1/24", "10.0.1.2/24", "10.0.2.1/24"}
	if len(inst0.VirtualAddresses) != len(wantVIPs) {
		t.Fatalf("inst0.VirtualAddresses = %v, want %v", inst0.VirtualAddresses, wantVIPs)
	}
	for i, v := range wantVIPs {
		if inst0.VirtualAddresses[i] != v {
			t.Errorf("inst0.VirtualAddresses[%d] = %q, want %q", i, inst0.VirtualAddresses[i], v)
		}
	}

	inst1 := instances[1]
	if inst1.Interface != "ge-0-0-1" {
		t.Errorf("inst1.Interface = %q, want ge-0-0-1", inst1.Interface)
	}
	if inst1.GroupID != 102 {
		t.Errorf("inst1.GroupID = %d, want 102", inst1.GroupID)
	}
	if inst1.Priority != 100 {
		t.Errorf("inst1.Priority = %d, want 100", inst1.Priority)
	}
}

func TestCollectRethInstances_NoAddresses(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: nil},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
	}
	instances := CollectRethInstances(cfg, map[int]int{1: 200})
	if len(instances) != 0 {
		t.Errorf("expected 0 instances for interface with no addresses, got %d", len(instances))
	}
}

func TestCollectRethInstances_Nil(t *testing.T) {
	instances := CollectRethInstances(nil, nil)
	if instances != nil {
		t.Errorf("expected nil, got %v", instances)
	}
}

func TestCollectRethInstances_DefaultPriority(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 5,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.0.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
	}
	// Priority map doesn't include RG 5 — should default to 100.
	instances := CollectRethInstances(cfg, map[int]int{})
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	if instances[0].Priority != 100 {
		t.Errorf("priority = %d, want 100 (default)", instances[0].Priority)
	}
}

func TestCollectRethInstances_LinuxIfName(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0/1": {
					Name:            "reth0/1",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.0.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0/1"},
			},
		},
	}
	instances := CollectRethInstances(cfg, map[int]int{1: 200})
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	if instances[0].Interface != "ge-0-0-0" {
		t.Errorf("Interface = %q, want ge-0-0-0 (resolved to physical member)", instances[0].Interface)
	}
}

func TestCollectRethInstances_VlanTagging(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					VlanTagging:     true,
					Units: map[int]*config.InterfaceUnit{
						50: {VlanID: 50, Addresses: []string{"172.16.50.6/24"}},
					},
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.60.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
			},
		},
	}
	pri := map[int]int{1: 200, 2: 100}
	instances := CollectRethInstances(cfg, pri)

	if len(instances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(instances))
	}

	// reth0 is VLAN-tagged → VRRP on ge-0-0-0.50 (physical member)
	inst0 := instances[0]
	if inst0.Interface != "ge-0-0-0.50" {
		t.Errorf("inst0.Interface = %q, want ge-0-0-0.50", inst0.Interface)
	}
	if inst0.GroupID != 101 {
		t.Errorf("inst0.GroupID = %d, want 101", inst0.GroupID)
	}
	if inst0.Priority != 200 {
		t.Errorf("inst0.Priority = %d, want 200", inst0.Priority)
	}
	wantVIPs := []string{"172.16.50.6/24"}
	if len(inst0.VirtualAddresses) != 1 || inst0.VirtualAddresses[0] != wantVIPs[0] {
		t.Errorf("inst0.VirtualAddresses = %v, want %v", inst0.VirtualAddresses, wantVIPs)
	}

	// reth1 is non-VLAN → VRRP on ge-0-0-1 (physical member)
	inst1 := instances[1]
	if inst1.Interface != "ge-0-0-1" {
		t.Errorf("inst1.Interface = %q, want ge-0-0-1", inst1.Interface)
	}
	if inst1.GroupID != 102 {
		t.Errorf("inst1.GroupID = %d, want 102", inst1.GroupID)
	}
	if inst1.Priority != 100 {
		t.Errorf("inst1.Priority = %d, want 100", inst1.Priority)
	}
}

func TestCollectRethInstances_ConfigurableInterval(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RethAdvertiseInterval: 50,
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 1, GratuitousARPCount: 5},
				},
			},
		},
	}
	instances := CollectRethInstances(cfg, map[int]int{1: 200})
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	if instances[0].AdvertiseInterval != 50 {
		t.Errorf("AdvertiseInterval = %d, want 50", instances[0].AdvertiseInterval)
	}
	if instances[0].GARPCount != 5 {
		t.Errorf("GARPCount = %d, want 5", instances[0].GARPCount)
	}
}

func TestCollectRethInstances_DefaultInterval30ms(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
	}
	instances := CollectRethInstances(cfg, map[int]int{1: 200})
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	// Default should be 30ms for sub-100ms failover.
	if instances[0].AdvertiseInterval != 30 {
		t.Errorf("AdvertiseInterval = %d, want 30 (default)", instances[0].AdvertiseInterval)
	}
	// GARP count should be 0 (use default of 3 at runtime).
	if instances[0].GARPCount != 0 {
		t.Errorf("GARPCount = %d, want 0 (default)", instances[0].GARPCount)
	}
}

// --- Packet codec tests ---

func TestPacketMarshalParseRoundTrip_IPv4(t *testing.T) {
	pkt := &VRRPPacket{
		VRID:         42,
		Priority:     200,
		MaxAdvertInt: 100, // 1 second
		IPAddresses:  []net.IP{net.IPv4(10, 0, 1, 1), net.IPv4(10, 0, 1, 2)},
	}

	srcIP := net.IPv4(192, 168, 1, 1)
	dstIP := net.IPv4(224, 0, 0, 18)

	data, err := pkt.Marshal(false, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	// Header (8) + 2 IPv4 addrs (8) = 16 bytes
	if len(data) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(data))
	}

	// Parse back
	parsed, err := ParseVRRPPacket(data, false, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.VRID != 42 {
		t.Errorf("VRID = %d, want 42", parsed.VRID)
	}
	if parsed.Priority != 200 {
		t.Errorf("Priority = %d, want 200", parsed.Priority)
	}
	if parsed.MaxAdvertInt != 100 {
		t.Errorf("MaxAdvertInt = %d, want 100", parsed.MaxAdvertInt)
	}
	if len(parsed.IPAddresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(parsed.IPAddresses))
	}
	if !parsed.IPAddresses[0].Equal(net.IPv4(10, 0, 1, 1)) {
		t.Errorf("addr[0] = %s, want 10.0.1.1", parsed.IPAddresses[0])
	}
	if !parsed.IPAddresses[1].Equal(net.IPv4(10, 0, 1, 2)) {
		t.Errorf("addr[1] = %s, want 10.0.1.2", parsed.IPAddresses[1])
	}
}

func TestPacketMarshalParseRoundTrip_IPv6(t *testing.T) {
	ip1 := net.ParseIP("2001:db8::1")
	ip2 := net.ParseIP("2001:db8::2")
	pkt := &VRRPPacket{
		VRID:         10,
		Priority:     100,
		MaxAdvertInt: 200,
		IPAddresses:  []net.IP{ip1, ip2},
	}

	srcIP := net.ParseIP("fe80::1")
	dstIP := net.ParseIP("ff02::12")

	data, err := pkt.Marshal(true, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	// Header (8) + 2 IPv6 addrs (32) = 40 bytes
	if len(data) != 40 {
		t.Fatalf("expected 40 bytes, got %d", len(data))
	}

	parsed, err := ParseVRRPPacket(data, true, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.VRID != 10 {
		t.Errorf("VRID = %d, want 10", parsed.VRID)
	}
	if parsed.Priority != 100 {
		t.Errorf("Priority = %d, want 100", parsed.Priority)
	}
	if len(parsed.IPAddresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(parsed.IPAddresses))
	}
}

func TestPacketParse_BadVersion(t *testing.T) {
	data := make([]byte, 12)
	data[0] = (2 << 4) | 1 // version 2
	_, err := ParseVRRPPacket(data, false, nil, nil)
	if err == nil {
		t.Error("expected error for version 2")
	}
}

func TestPacketParse_TooShort(t *testing.T) {
	_, err := ParseVRRPPacket([]byte{1, 2, 3}, false, nil, nil)
	if err == nil {
		t.Error("expected error for short packet")
	}
}

func TestPacketParse_BadChecksum(t *testing.T) {
	pkt := &VRRPPacket{
		VRID:         1,
		Priority:     100,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.IPv4(10, 0, 0, 1)},
	}
	srcIP := net.IPv4(192, 168, 1, 1)
	dstIP := net.IPv4(224, 0, 0, 18)
	data, _ := pkt.Marshal(false, srcIP, dstIP)

	// Corrupt checksum
	data[6] ^= 0xFF

	_, err := ParseVRRPPacket(data, false, srcIP, dstIP)
	if err == nil {
		t.Error("expected checksum error")
	}
}

func TestPacketPriority0(t *testing.T) {
	pkt := &VRRPPacket{
		VRID:         1,
		Priority:     0,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.IPv4(10, 0, 0, 1)},
	}
	srcIP := net.IPv4(192, 168, 1, 1)
	dstIP := net.IPv4(224, 0, 0, 18)
	data, err := pkt.Marshal(false, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseVRRPPacket(data, false, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Priority != 0 {
		t.Errorf("Priority = %d, want 0", parsed.Priority)
	}
}

// --- State machine tests ---

func TestVRRPState_String(t *testing.T) {
	tests := []struct {
		state VRRPState
		want  string
	}{
		{StateInitialize, "INIT"},
		{StateBackup, "BACKUP"},
		{StateMaster, "MASTER"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("VRRPState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestVipsEqual(t *testing.T) {
	tests := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{"10.0.0.1/24"}, []string{"10.0.0.1/24"}, true},
		{[]string{"10.0.0.1/24"}, []string{"10.0.0.2/24"}, false},
		{[]string{"10.0.0.1/24"}, []string{"10.0.0.1/24", "10.0.0.2/24"}, false},
	}
	for _, tt := range tests {
		if got := vipsEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("vipsEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestManagerNewAndStates(t *testing.T) {
	m := NewManager()
	states := m.States()
	if len(states) != 0 {
		t.Errorf("expected empty states, got %v", states)
	}
	status := m.Status()
	if status == "" {
		t.Error("expected non-empty status string")
	}
}

func TestOnesComplementChecksum(t *testing.T) {
	// All zeros should checksum to 0xFFFF
	data := make([]byte, 8)
	csum := onesComplementChecksum(data)
	if csum != 0xFFFF {
		t.Errorf("checksum of zeros = 0x%04X, want 0xFFFF", csum)
	}
}

// --- Sync hold tests ---

func TestSyncHold_SuppressesPreempt(t *testing.T) {
	m := NewManager()
	m.SetSyncHold(5 * time.Second)

	// Create an instance — desiredPreempt should be true, but active preempt false.
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)

	// Simulate what UpdateInstances does during sync hold.
	if m.syncHold {
		vi.cfg.Preempt = false
	}
	vi.desiredPreempt = true

	if vi.cfg.Preempt {
		t.Error("expected preempt to be suppressed during sync hold")
	}
	if !vi.desiredPreempt {
		t.Error("desiredPreempt should remain true")
	}

	// Release — should restore preempt.
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	m.ReleaseSyncHold()

	if !vi.getPreempt() {
		t.Error("expected preempt to be restored after sync hold release")
	}
}

func TestSyncHold_AppliesToExistingInstances(t *testing.T) {
	m := NewManager()

	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	m.SetSyncHold(5 * time.Second)
	defer m.ReleaseSyncHold()

	if vi.getPreempt() {
		t.Error("expected existing instance preempt to be suppressed during sync hold")
	}
	vi.mu.RLock()
	dp := vi.desiredPreempt
	vi.mu.RUnlock()
	if !dp {
		t.Error("expected desiredPreempt to remain true while hold is active")
	}
}

func TestUpdateInstances_PreservesSyncHoldForExistingInstances(t *testing.T) {
	m := NewManager()

	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	m.SetSyncHold(5 * time.Second)
	defer m.ReleaseSyncHold()

	desired := []*Instance{
		{
			Interface: "eth0",
			GroupID:   101,
			Priority:  150,
			Preempt:   true,
		},
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances failed: %v", err)
	}

	if vi.getPreempt() {
		t.Error("expected sync hold to keep preempt disabled on updated instance")
	}
	if got := vi.getPriority(); got != 150 {
		t.Errorf("priority = %d, want 150", got)
	}
	vi.mu.RLock()
	dp := vi.desiredPreempt
	vi.mu.RUnlock()
	if !dp {
		t.Error("expected desiredPreempt to track configured preempt during hold")
	}
}

func TestSyncHold_RearmStopsPreviousTimer(t *testing.T) {
	m := NewManager()
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	m.SetSyncHold(30 * time.Millisecond)
	time.Sleep(15 * time.Millisecond)
	m.SetSyncHold(120 * time.Millisecond)
	defer m.ReleaseSyncHold()

	time.Sleep(60 * time.Millisecond)

	m.mu.RLock()
	held := m.syncHold
	m.mu.RUnlock()
	if !held {
		t.Fatal("expected sync hold to remain active after timer re-arm")
	}
	if reason := m.SyncHoldReason(); reason != "" {
		t.Fatalf("expected empty sync hold reason while hold active, got %q", reason)
	}

	time.Sleep(90 * time.Millisecond)

	m.mu.RLock()
	held = m.syncHold
	m.mu.RUnlock()
	if held {
		t.Fatal("expected sync hold to release after re-armed timeout")
	}
	if reason := m.SyncHoldReason(); reason != "timeout-degraded" {
		t.Fatalf("expected timeout-degraded reason after timeout, got %q", reason)
	}
	if !vi.getPreempt() {
		t.Fatal("expected preempt to be restored after timeout release")
	}
}

func TestSyncHold_ReleaseTwiceIsNoop(t *testing.T) {
	m := NewManager()
	m.SetSyncHold(5 * time.Second)
	m.ReleaseSyncHold()
	// Second call should be a no-op, not panic.
	m.ReleaseSyncHold()
}

func TestSyncHold_BulkSyncCompleteReason(t *testing.T) {
	m := NewManager()
	m.SetSyncHold(5 * time.Second)

	// Before release, reason is empty.
	if reason := m.SyncHoldReason(); reason != "" {
		t.Errorf("expected empty reason before release, got %q", reason)
	}

	m.ReleaseSyncHold()

	if reason := m.SyncHoldReason(); reason != "bulk-sync-complete" {
		t.Errorf("expected reason 'bulk-sync-complete', got %q", reason)
	}
}

func TestSyncHold_TimeoutReleasesAutomatically(t *testing.T) {
	m := NewManager()

	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	// Set a very short timeout.
	m.SetSyncHold(50 * time.Millisecond)

	// Force preempt off to simulate sync hold.
	vi.mu.Lock()
	vi.cfg.Preempt = false
	vi.mu.Unlock()

	// Wait for timeout.
	time.Sleep(200 * time.Millisecond)

	if !vi.getPreempt() {
		t.Error("expected preempt to be restored after sync hold timeout")
	}
	if reason := m.SyncHoldReason(); reason != "timeout-degraded" {
		t.Errorf("expected reason 'timeout-degraded', got %q", reason)
	}
}

func TestInstanceRestorePreempt(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)

	// Simulate sync hold: override preempt=false but keep desiredPreempt=true.
	vi.mu.Lock()
	vi.cfg.Preempt = false
	vi.mu.Unlock()

	if vi.getPreempt() {
		t.Error("preempt should be false during hold")
	}

	vi.restorePreempt()
	if !vi.getPreempt() {
		t.Error("preempt should be true after restore")
	}
}

func TestPreemptNowCh_Initialized(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)

	if vi.preemptNowCh == nil {
		t.Fatal("preemptNowCh should be initialized")
	}
	if cap(vi.preemptNowCh) != 1 {
		t.Errorf("preemptNowCh capacity = %d, want 1", cap(vi.preemptNowCh))
	}
}

func TestTriggerPreemptNow_NonBlocking(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)

	// First call should succeed (buffer of 1).
	vi.triggerPreemptNow()
	if len(vi.preemptNowCh) != 1 {
		t.Error("expected 1 pending signal after first trigger")
	}

	// Second call should NOT block (buffer full, silently dropped).
	done := make(chan struct{})
	go func() {
		vi.triggerPreemptNow()
		close(done)
	}()
	select {
	case <-done:
		// ok — did not block
	case <-time.After(1 * time.Second):
		t.Fatal("triggerPreemptNow blocked on full channel")
	}

	// Still exactly 1 pending signal.
	if len(vi.preemptNowCh) != 1 {
		t.Errorf("expected 1 pending signal, got %d", len(vi.preemptNowCh))
	}
}

func TestReleaseSyncHold_TriggersPreemptNow(t *testing.T) {
	m := NewManager()

	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)

	// Simulate sync hold: preempt suppressed.
	vi.mu.Lock()
	vi.cfg.Preempt = false
	vi.mu.Unlock()

	m.mu.Lock()
	m.syncHold = true
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	m.ReleaseSyncHold()

	// Preempt should be restored.
	if !vi.getPreempt() {
		t.Error("expected preempt restored after ReleaseSyncHold")
	}

	// preemptNowCh should have a pending signal.
	select {
	case <-vi.preemptNowCh:
		// ok — signal was sent
	default:
		t.Error("expected preemptNowCh signal after ReleaseSyncHold")
	}
}

func TestUpdateConfig_PreservesDesiredPreempt(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)

	// updateConfig should update both cfg.Preempt and desiredPreempt.
	vi.updateConfig(Instance{Priority: 150, Preempt: false})

	if vi.getPreempt() {
		t.Error("preempt should be false after updateConfig")
	}
	vi.mu.RLock()
	dp := vi.desiredPreempt
	vi.mu.RUnlock()
	if dp {
		t.Error("desiredPreempt should be false after updateConfig")
	}
}

// --- Preempt wiring tests ---

func TestCollectRethInstances_PreemptFromRGConfig(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.2.1/24"}},
					},
				},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
			},
		},
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 1, Preempt: true},
					{ID: 2, Preempt: false},
				},
			},
		},
	}
	instances := CollectRethInstances(cfg, map[int]int{1: 200, 2: 100})
	if len(instances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(instances))
	}
	// RG1 has preempt=true, RG2 has preempt=false.
	if !instances[0].Preempt {
		t.Error("inst0 (RG1) should have Preempt=true")
	}
	if instances[1].Preempt {
		t.Error("inst1 (RG2) should have Preempt=false")
	}
}

func TestCollectRethInstances_NoPreemptByDefault(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
		// No cluster config — preempt defaults to false.
	}
	instances := CollectRethInstances(cfg, map[int]int{1: 200})
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	if instances[0].Preempt {
		t.Error("Preempt should default to false when no RG config")
	}
}

// --- Resign channel tests ---

func TestResignCh_Initialized(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)

	if vi.resignCh == nil {
		t.Fatal("resignCh should be initialized")
	}
	if cap(vi.resignCh) != 1 {
		t.Errorf("resignCh capacity = %d, want 1", cap(vi.resignCh))
	}
}

func TestTriggerResign_NonBlocking(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)

	// First call should succeed (buffer of 1).
	vi.triggerResign()
	if len(vi.resignCh) != 1 {
		t.Error("expected 1 pending signal after first trigger")
	}

	// Second call should NOT block (buffer full, silently dropped).
	done := make(chan struct{})
	go func() {
		vi.triggerResign()
		close(done)
	}()
	select {
	case <-done:
		// ok — did not block
	case <-time.After(1 * time.Second):
		t.Fatal("triggerResign blocked on full channel")
	}

	// Still exactly 1 pending signal.
	if len(vi.resignCh) != 1 {
		t.Errorf("expected 1 pending signal, got %d", len(vi.resignCh))
	}
}

func TestResignRG_SignalsCorrectInstances(t *testing.T) {
	m := NewManager()

	// Create instances for two different RGs.
	vi1 := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101, // VRID 101 = RG 1
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)

	vi2 := newInstance(Instance{
		Interface: "eth1",
		GroupID:   102, // VRID 102 = RG 2
		Priority:  200,
	}, &net.Interface{Name: "eth1"}, m.eventCh, nil)

	vi3 := newInstance(Instance{
		Interface: "eth2",
		GroupID:   101, // VRID 101 = RG 1 (second instance, same RG)
		Priority:  200,
	}, &net.Interface{Name: "eth2"}, m.eventCh, nil)

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi1,
		{iface: "eth1", groupID: 102}: vi2,
		{iface: "eth2", groupID: 101}: vi3,
	}
	m.mu.Unlock()

	// Resign RG 1 — should signal vi1 and vi3, not vi2.
	m.ResignRG(1)

	if len(vi1.resignCh) != 1 {
		t.Error("vi1 (RG1) should have resign signal")
	}
	if len(vi2.resignCh) != 0 {
		t.Error("vi2 (RG2) should NOT have resign signal")
	}
	if len(vi3.resignCh) != 1 {
		t.Error("vi3 (RG1) should have resign signal")
	}
}

// --- handleMasterRx tie-breaking tests (RFC 5798 §6.4.3) ---

func TestHandleMasterRx_HigherPriority_StepsDown(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  100,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIP = net.IPv4(10, 0, 0, 1)
	vi.setState(StateMaster)

	masterDownTimer := time.NewTimer(time.Hour)
	defer masterDownTimer.Stop()
	advertTimer := time.NewTimer(time.Hour)
	defer advertTimer.Stop()

	pkt := &VRRPPacket{
		Priority: 200,
		SrcIP:    net.IPv4(10, 0, 0, 2),
	}
	vi.handleMasterRx(pkt, masterDownTimer, advertTimer)

	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (higher priority should step down)", vi.getState())
	}
}

func TestHandleMasterRx_LowerPriority_StaysMaster(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIP = net.IPv4(10, 0, 0, 1)
	vi.setState(StateMaster)

	masterDownTimer := time.NewTimer(time.Hour)
	defer masterDownTimer.Stop()
	advertTimer := time.NewTimer(time.Hour)
	defer advertTimer.Stop()

	pkt := &VRRPPacket{
		Priority: 100,
		SrcIP:    net.IPv4(10, 0, 0, 2),
	}
	vi.handleMasterRx(pkt, masterDownTimer, advertTimer)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (lower priority should be ignored)", vi.getState())
	}
}

func TestHandleMasterRx_EqualPriority_HigherPeerIP_StepsDown(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIP = net.IPv4(10, 0, 0, 1) // lower IP
	vi.setState(StateMaster)

	masterDownTimer := time.NewTimer(time.Hour)
	defer masterDownTimer.Stop()
	advertTimer := time.NewTimer(time.Hour)
	defer advertTimer.Stop()

	pkt := &VRRPPacket{
		Priority: 200,
		SrcIP:    net.IPv4(10, 0, 0, 2), // higher IP
	}
	vi.handleMasterRx(pkt, masterDownTimer, advertTimer)

	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (equal priority, peer has higher IP)", vi.getState())
	}
}

func TestHandleMasterRx_EqualPriority_LowerPeerIP_StaysMaster(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIP = net.IPv4(10, 0, 0, 2) // higher IP
	vi.setState(StateMaster)

	masterDownTimer := time.NewTimer(time.Hour)
	defer masterDownTimer.Stop()
	advertTimer := time.NewTimer(time.Hour)
	defer advertTimer.Stop()

	pkt := &VRRPPacket{
		Priority: 200,
		SrcIP:    net.IPv4(10, 0, 0, 1), // lower IP
	}
	vi.handleMasterRx(pkt, masterDownTimer, advertTimer)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (equal priority, we have higher IP)", vi.getState())
	}
}

func TestHandleMasterRx_EqualPriority_NilSrcIP_StaysMaster(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIP = net.IPv4(10, 0, 0, 1)
	vi.setState(StateMaster)

	masterDownTimer := time.NewTimer(time.Hour)
	defer masterDownTimer.Stop()
	advertTimer := time.NewTimer(time.Hour)
	defer advertTimer.Stop()

	// SrcIP nil — can't tie-break, stay Master (safe default).
	pkt := &VRRPPacket{
		Priority: 200,
		SrcIP:    nil,
	}
	vi.handleMasterRx(pkt, masterDownTimer, advertTimer)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (nil SrcIP, can't tie-break)", vi.getState())
	}
}

func TestHandleMasterRx_Priority0_StaysMaster(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIP = net.IPv4(10, 0, 0, 1)
	vi.setState(StateMaster)

	masterDownTimer := time.NewTimer(time.Hour)
	defer masterDownTimer.Stop()
	advertTimer := time.NewTimer(time.Hour)
	defer advertTimer.Stop()

	pkt := &VRRPPacket{
		Priority: 0, // resign
		SrcIP:    net.IPv4(10, 0, 0, 2),
	}
	vi.handleMasterRx(pkt, masterDownTimer, advertTimer)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (priority-0 = resign)", vi.getState())
	}
}

func TestHandleMasterRx_EqualPriority_HigherPeerIPv6_StepsDown(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIPv6 = net.ParseIP("fe80::1") // lower IPv6
	vi.setState(StateMaster)

	masterDownTimer := time.NewTimer(time.Hour)
	defer masterDownTimer.Stop()
	advertTimer := time.NewTimer(time.Hour)
	defer advertTimer.Stop()

	pkt := &VRRPPacket{
		Priority: 200,
		SrcIP:    net.ParseIP("fe80::2"), // higher IPv6
	}
	vi.handleMasterRx(pkt, masterDownTimer, advertTimer)

	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (equal priority, peer has higher IPv6)", vi.getState())
	}
}

func TestHandleMasterRx_EqualPriority_LowerPeerIPv6_StaysMaster(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIPv6 = net.ParseIP("fe80::2") // higher IPv6
	vi.setState(StateMaster)

	masterDownTimer := time.NewTimer(time.Hour)
	defer masterDownTimer.Stop()
	advertTimer := time.NewTimer(time.Hour)
	defer advertTimer.Stop()

	pkt := &VRRPPacket{
		Priority: 200,
		SrcIP:    net.ParseIP("fe80::1"), // lower IPv6
	}
	vi.handleMasterRx(pkt, masterDownTimer, advertTimer)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (equal priority, we have higher IPv6)", vi.getState())
	}
}

func TestParsedPacket_PreservesSrcIP(t *testing.T) {
	pkt := &VRRPPacket{
		VRID:         42,
		Priority:     200,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.IPv4(10, 0, 1, 1)},
	}
	srcIP := net.IPv4(192, 168, 1, 1)
	dstIP := net.IPv4(224, 0, 0, 18)

	data, err := pkt.Marshal(false, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseVRRPPacket(data, false, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	if !parsed.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", parsed.SrcIP, srcIP)
	}
}

// --- VLAN AF_PACKET receive tests ---

// buildEthFrame constructs a minimal Ethernet frame with an IPv4 VRRP packet.
// If vlanID > 0, inserts an 802.1Q tag. Returns the raw frame bytes.
func buildEthFrame(t *testing.T, vlanID int, srcIP, dstIP net.IP, vrrpPkt *VRRPPacket) []byte {
	t.Helper()
	vrrpData, err := vrrpPkt.Marshal(false, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	// Build IP header (20 bytes, no options).
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version 4, IHL 5
	totalLen := 20 + len(vrrpData)
	ipHdr[2] = byte(totalLen >> 8)
	ipHdr[3] = byte(totalLen)
	ipHdr[8] = 255      // TTL
	ipHdr[9] = 112      // protocol = VRRP
	copy(ipHdr[12:16], srcIP.To4())
	copy(ipHdr[16:20], dstIP.To4())

	var frame []byte
	// Ethernet dst + src (12 bytes)
	ethDstSrc := make([]byte, 12)
	ethDstSrc[0] = 0x01 // multicast dst
	ethDstSrc[1] = 0x00
	ethDstSrc[2] = 0x5E
	ethDstSrc[3] = 0x00
	ethDstSrc[4] = 0x00
	ethDstSrc[5] = 0x12
	frame = append(frame, ethDstSrc...)

	if vlanID > 0 {
		// 802.1Q: ethertype 0x8100 + VLAN tag (2 bytes) + real ethertype 0x0800
		frame = append(frame, 0x81, 0x00)                       // TPID
		frame = append(frame, byte(vlanID>>8), byte(vlanID))     // TCI (PCP=0, DEI=0, VID)
		frame = append(frame, 0x08, 0x00)                        // real ethertype
	} else {
		frame = append(frame, 0x08, 0x00) // ethertype IPv4
	}
	frame = append(frame, ipHdr...)
	frame = append(frame, vrrpData...)
	return frame
}

// parseAfPacketFrame extracts a VRRPPacket from a raw Ethernet frame
// the same way receiverAfPacket does. Returns the parsed packet or an error.
func parseAfPacketFrame(buf []byte, n int, localIP net.IP, groupID int) (*VRRPPacket, error) {
	if n < 14 {
		return nil, fmt.Errorf("frame too short")
	}

	ethHeaderLen := 14
	ethertype := binary.BigEndian.Uint16(buf[12:14])
	if ethertype == 0x8100 || ethertype == 0x88a8 {
		ethHeaderLen = 18
		if n < 18 {
			return nil, fmt.Errorf("frame too short for VLAN")
		}
		ethertype = binary.BigEndian.Uint16(buf[16:18])
	}

	if ethertype == 0x86DD {
		return parseAfPacketIPv6Frame(buf, n, ethHeaderLen, localIP, groupID)
	}

	if n < ethHeaderLen+20+vrrpHeaderLen {
		return nil, fmt.Errorf("frame too short for IP+VRRP")
	}

	ip := buf[ethHeaderLen:]
	ipLen := n - ethHeaderLen

	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || ipLen < ihl+vrrpHeaderLen {
		return nil, fmt.Errorf("bad IHL")
	}

	ttl := int(ip[8])
	if ttl != 255 {
		return nil, fmt.Errorf("TTL %d != 255", ttl)
	}

	srcIP := make(net.IP, 4)
	copy(srcIP, ip[12:16])

	if localIP != nil && srcIP.Equal(localIP) {
		return nil, fmt.Errorf("self-sent")
	}

	payload := ip[ihl:ipLen]
	if payload[1] != uint8(groupID) {
		return nil, fmt.Errorf("VRID mismatch")
	}

	dstIP := make(net.IP, 4)
	copy(dstIP, ip[16:20])

	return ParseVRRPPacket(payload, false, srcIP, dstIP)
}

// parseAfPacketIPv6Frame parses an IPv6 VRRP packet from a raw Ethernet frame.
func parseAfPacketIPv6Frame(buf []byte, n, ethHeaderLen int, localIP net.IP, groupID int) (*VRRPPacket, error) {
	const ipv6HeaderLen = 40
	if n < ethHeaderLen+ipv6HeaderLen+vrrpHeaderLen {
		return nil, fmt.Errorf("frame too short for IPv6+VRRP")
	}

	ip6 := buf[ethHeaderLen:]
	ip6Len := n - ethHeaderLen

	if ip6[7] != 255 {
		return nil, fmt.Errorf("hop limit %d != 255", ip6[7])
	}

	srcIP := make(net.IP, 16)
	copy(srcIP, ip6[8:24])

	if localIP != nil && srcIP.Equal(localIP) {
		return nil, fmt.Errorf("self-sent")
	}

	payload := ip6[ipv6HeaderLen:ip6Len]
	if len(payload) < vrrpHeaderLen {
		return nil, fmt.Errorf("payload too short")
	}
	if payload[1] != uint8(groupID) {
		return nil, fmt.Errorf("VRID mismatch")
	}

	dstIP := make(net.IP, 16)
	copy(dstIP, ip6[24:40])

	return ParseVRRPPacket(payload, true, srcIP, dstIP)
}

func TestAfPacket_UntaggedFrame(t *testing.T) {
	srcIP := net.IPv4(10, 0, 0, 1)
	dstIP := net.IPv4(224, 0, 0, 18)
	vrrpPkt := &VRRPPacket{
		VRID:         101,
		Priority:     200,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{net.IPv4(172, 16, 50, 10)},
	}

	frame := buildEthFrame(t, 0, srcIP, dstIP, vrrpPkt)
	parsed, err := parseAfPacketFrame(frame, len(frame), nil, 101)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.VRID != 101 {
		t.Errorf("VRID = %d, want 101", parsed.VRID)
	}
	if parsed.Priority != 200 {
		t.Errorf("Priority = %d, want 200", parsed.Priority)
	}
	if !parsed.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", parsed.SrcIP, srcIP)
	}
}

func TestAfPacket_VlanTaggedFrame(t *testing.T) {
	srcIP := net.IPv4(10, 0, 0, 1)
	dstIP := net.IPv4(224, 0, 0, 18)
	vrrpPkt := &VRRPPacket{
		VRID:         101,
		Priority:     200,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{net.IPv4(172, 16, 50, 10)},
	}

	frame := buildEthFrame(t, 50, srcIP, dstIP, vrrpPkt)
	parsed, err := parseAfPacketFrame(frame, len(frame), nil, 101)
	if err != nil {
		t.Fatalf("unexpected error parsing VLAN-tagged frame: %v", err)
	}
	if parsed.VRID != 101 {
		t.Errorf("VRID = %d, want 101", parsed.VRID)
	}
	if parsed.Priority != 200 {
		t.Errorf("Priority = %d, want 200", parsed.Priority)
	}
	if !parsed.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", parsed.SrcIP, srcIP)
	}
}

func TestAfPacket_VlanQinQFrame(t *testing.T) {
	srcIP := net.IPv4(10, 0, 0, 1)
	dstIP := net.IPv4(224, 0, 0, 18)
	vrrpPkt := &VRRPPacket{
		VRID:         101,
		Priority:     200,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{net.IPv4(172, 16, 50, 10)},
	}

	// Build QinQ frame (0x88a8 outer tag).
	vrrpData, err := vrrpPkt.Marshal(false, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	totalLen := 20 + len(vrrpData)
	ipHdr[2] = byte(totalLen >> 8)
	ipHdr[3] = byte(totalLen)
	ipHdr[8] = 255
	ipHdr[9] = 112
	copy(ipHdr[12:16], srcIP.To4())
	copy(ipHdr[16:20], dstIP.To4())

	var frame []byte
	frame = append(frame, make([]byte, 12)...) // dst+src MAC
	frame = append(frame, 0x88, 0xa8)          // 802.1ad (QinQ)
	frame = append(frame, 0x00, 50)            // outer VLAN
	frame = append(frame, 0x08, 0x00)          // real ethertype
	frame = append(frame, ipHdr...)
	frame = append(frame, vrrpData...)

	parsed, err := parseAfPacketFrame(frame, len(frame), nil, 101)
	if err != nil {
		t.Fatalf("unexpected error parsing QinQ frame: %v", err)
	}
	if parsed.VRID != 101 {
		t.Errorf("VRID = %d, want 101", parsed.VRID)
	}
}

// buildEthIPv6Frame constructs a minimal Ethernet frame with an IPv6 VRRP packet.
// If vlanID > 0, inserts an 802.1Q tag.
func buildEthIPv6Frame(t *testing.T, vlanID int, srcIP, dstIP net.IP, vrrpPkt *VRRPPacket) []byte {
	t.Helper()
	vrrpData, err := vrrpPkt.Marshal(true, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	// Build IPv6 header (40 bytes, no extension headers).
	ip6Hdr := make([]byte, 40)
	ip6Hdr[0] = 0x60                                          // version 6
	binary.BigEndian.PutUint16(ip6Hdr[4:6], uint16(len(vrrpData))) // payload length
	ip6Hdr[6] = 112                                            // next header = VRRP
	ip6Hdr[7] = 255                                            // hop limit
	copy(ip6Hdr[8:24], srcIP.To16())
	copy(ip6Hdr[24:40], dstIP.To16())

	var frame []byte
	ethDstSrc := make([]byte, 12)
	ethDstSrc[0] = 0x33 // IPv6 multicast dst
	ethDstSrc[1] = 0x33
	ethDstSrc[4] = 0x00
	ethDstSrc[5] = 0x12
	frame = append(frame, ethDstSrc...)

	if vlanID > 0 {
		frame = append(frame, 0x81, 0x00)
		frame = append(frame, byte(vlanID>>8), byte(vlanID))
		frame = append(frame, 0x86, 0xDD)
	} else {
		frame = append(frame, 0x86, 0xDD) // ethertype IPv6
	}
	frame = append(frame, ip6Hdr...)
	frame = append(frame, vrrpData...)
	return frame
}

func TestAfPacket_IPv6UntaggedFrame(t *testing.T) {
	srcIP := net.ParseIP("fe80::1")
	dstIP := net.ParseIP("ff02::12")
	vrrpPkt := &VRRPPacket{
		VRID:         101,
		Priority:     200,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{net.ParseIP("2001:db8::10")},
	}

	frame := buildEthIPv6Frame(t, 0, srcIP, dstIP, vrrpPkt)
	parsed, err := parseAfPacketFrame(frame, len(frame), nil, 101)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.VRID != 101 {
		t.Errorf("VRID = %d, want 101", parsed.VRID)
	}
	if parsed.Priority != 200 {
		t.Errorf("Priority = %d, want 200", parsed.Priority)
	}
	if !parsed.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %s, want %s", parsed.SrcIP, srcIP)
	}
	if len(parsed.IPAddresses) != 1 {
		t.Fatalf("expected 1 address, got %d", len(parsed.IPAddresses))
	}
	if !parsed.IPAddresses[0].Equal(net.ParseIP("2001:db8::10")) {
		t.Errorf("addr = %s, want 2001:db8::10", parsed.IPAddresses[0])
	}
}

func TestAfPacket_IPv6VlanTaggedFrame(t *testing.T) {
	srcIP := net.ParseIP("fe80::1")
	dstIP := net.ParseIP("ff02::12")
	vrrpPkt := &VRRPPacket{
		VRID:         101,
		Priority:     200,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{net.ParseIP("2001:db8::10")},
	}

	frame := buildEthIPv6Frame(t, 50, srcIP, dstIP, vrrpPkt)
	parsed, err := parseAfPacketFrame(frame, len(frame), nil, 101)
	if err != nil {
		t.Fatalf("unexpected error parsing VLAN-tagged IPv6 frame: %v", err)
	}
	if parsed.VRID != 101 {
		t.Errorf("VRID = %d, want 101", parsed.VRID)
	}
	if parsed.Priority != 200 {
		t.Errorf("Priority = %d, want 200", parsed.Priority)
	}
}

func TestAfPacket_IPv6SelfSentFiltered(t *testing.T) {
	srcIP := net.ParseIP("fe80::1")
	dstIP := net.ParseIP("ff02::12")
	vrrpPkt := &VRRPPacket{
		VRID:         101,
		Priority:     200,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{net.ParseIP("2001:db8::10")},
	}

	frame := buildEthIPv6Frame(t, 0, srcIP, dstIP, vrrpPkt)
	_, err := parseAfPacketFrame(frame, len(frame), srcIP, 101)
	if err == nil {
		t.Error("expected self-sent filter to reject IPv6 packet")
	}
}

func TestAfPacket_SelfSentFiltered(t *testing.T) {
	srcIP := net.IPv4(10, 0, 0, 1)
	dstIP := net.IPv4(224, 0, 0, 18)
	vrrpPkt := &VRRPPacket{
		VRID:         101,
		Priority:     200,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{net.IPv4(172, 16, 50, 10)},
	}

	frame := buildEthFrame(t, 50, srcIP, dstIP, vrrpPkt)
	_, err := parseAfPacketFrame(frame, len(frame), srcIP, 101)
	if err == nil {
		t.Error("expected self-sent filter to reject packet")
	}
}

func TestAfPacket_VRIDMismatchFiltered(t *testing.T) {
	srcIP := net.IPv4(10, 0, 0, 1)
	dstIP := net.IPv4(224, 0, 0, 18)
	vrrpPkt := &VRRPPacket{
		VRID:         101,
		Priority:     200,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{net.IPv4(172, 16, 50, 10)},
	}

	frame := buildEthFrame(t, 50, srcIP, dstIP, vrrpPkt)
	_, err := parseAfPacketFrame(frame, len(frame), nil, 102) // wrong VRID
	if err == nil {
		t.Error("expected VRID mismatch to reject packet")
	}
}

// --- ForceRGMaster preempt leak tests ---

func TestForceRGMaster_DoesNotLeakPreempt(t *testing.T) {
	m := NewManager()

	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   false, // preempt disabled
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)
	vi.setState(StateBackup)

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	// ForceRGMaster should set forcePreemptOnce, NOT cfg.Preempt.
	m.ForceRGMaster(1) // RG 1 → VRID 101

	vi.mu.RLock()
	preempt := vi.cfg.Preempt
	forceOnce := vi.forcePreemptOnce
	vi.mu.RUnlock()

	if preempt {
		t.Error("cfg.Preempt should remain false after ForceRGMaster")
	}
	if !forceOnce {
		t.Error("forcePreemptOnce should be true after ForceRGMaster")
	}

	// Verify preemptNowCh got signaled.
	select {
	case <-vi.preemptNowCh:
		// ok
	default:
		t.Error("preemptNowCh should have been signaled")
	}
}

func TestForcePreemptOnce_ClearedAfterUse(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   false,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 16), nil)

	// Simulate ForceRGMaster setting the flag.
	vi.mu.Lock()
	vi.forcePreemptOnce = true
	vi.mu.Unlock()

	// Simulate the preemptNowCh handler consuming the flag.
	vi.mu.Lock()
	force := vi.forcePreemptOnce
	vi.forcePreemptOnce = false
	vi.mu.Unlock()

	if !force {
		t.Error("forcePreemptOnce should have been true")
	}

	// After consumption, flag should be cleared.
	vi.mu.RLock()
	cleared := vi.forcePreemptOnce
	vi.mu.RUnlock()
	if cleared {
		t.Error("forcePreemptOnce should be false after consumption")
	}

	// cfg.Preempt should still be false.
	if vi.getPreempt() {
		t.Error("cfg.Preempt should remain false throughout")
	}
}

// mockPacketConn is a minimal PacketConn for testing receiverIPv6.
type mockPacketConn struct {
	data     []byte
	srcAddr  net.Addr
	readOnce chan struct{}
	closed   chan struct{}
}

func (m *mockPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-m.readOnce:
		// First read returns the packet.
		n := copy(p, m.data)
		return n, m.srcAddr, nil
	case <-m.closed:
		return 0, nil, net.ErrClosed
	}
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) { return len(p), nil }
func (m *mockPacketConn) Close() error                                 { close(m.closed); return nil }
func (m *mockPacketConn) LocalAddr() net.Addr                          { return nil }
func (m *mockPacketConn) SetDeadline(t time.Time) error                { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error            { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error           { return nil }

func TestReceiverIPv6_DeliversPacket(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   42,
		Priority:  100,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.localIPv6 = net.ParseIP("fe80::1")

	// Build a valid VRRPv3 packet.
	srcIP := net.ParseIP("fe80::2")
	dstIP := net.ParseIP("ff02::12")
	pkt := &VRRPPacket{
		VRID:         42,
		Priority:     200,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.ParseIP("2001:db8::1")},
	}
	data, err := pkt.Marshal(true, srcIP, dstIP)
	if err != nil {
		t.Fatal(err)
	}

	readOnce := make(chan struct{}, 1)
	readOnce <- struct{}{} // allow one read
	mock := &mockPacketConn{
		data:     data,
		srcAddr:  &net.IPAddr{IP: srcIP},
		readOnce: readOnce,
		closed:   make(chan struct{}),
	}
	vi.ipv6Conn = mock

	// Start receiver.
	go vi.receiverIPv6()
	defer close(vi.stopCh)

	// Wait for packet delivery.
	select {
	case rx := <-vi.rxCh:
		if rx.Priority != 200 {
			t.Errorf("priority = %d, want 200", rx.Priority)
		}
		if rx.VRID != 42 {
			t.Errorf("VRID = %d, want 42", rx.VRID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for IPv6 packet on rxCh")
	}
}

func TestEmitEvent_DropDoesNotPanic(t *testing.T) {
	// Create a channel with buffer 1 and fill it.
	eventCh := make(chan VRRPEvent, 1)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.setState(StateMaster)

	// First event should succeed.
	vi.emitEvent()
	if len(eventCh) != 1 {
		t.Errorf("eventCh length = %d, want 1", len(eventCh))
	}

	// Second event should be dropped (channel full) without panic.
	vi.emitEvent()
	if len(eventCh) != 1 {
		t.Errorf("eventCh length = %d, want 1 (dropped event should not grow)", len(eventCh))
	}
}

func TestEmitEvent_DropSilentDuringShutdown(t *testing.T) {
	// When stopCh is closed (shutting down), dropped events should not warn.
	eventCh := make(chan VRRPEvent, 1)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.setState(StateMaster)

	// Fill channel.
	vi.emitEvent()

	// Close stopCh to simulate shutdown.
	close(vi.stopCh)

	// This should drop silently without panic or warning.
	vi.emitEvent()
	if len(eventCh) != 1 {
		t.Errorf("eventCh length = %d, want 1", len(eventCh))
	}
}

func TestSendPacketIPv6_NilLocalIPv6_ReturnsError(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "lo",
		GroupID:   42,
		Priority:  200,
		VirtualAddresses: []string{"2001:db8::1/128"},
	}, &net.Interface{Name: "lo", Index: 1}, eventCh, nil)
	// localIPv6 is nil and interface has no link-local → should error.
	vi.localIPv6 = nil

	// Create a mock conn so ipv6Conn is non-nil (we test the srcIP path).
	vi.ipv6Conn = &mockPacketConn{
		closed: make(chan struct{}),
	}

	pkt := &VRRPPacket{
		VRID:         42,
		Priority:     200,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.ParseIP("2001:db8::1")},
	}
	err := vi.sendPacketIPv6(pkt)
	if err == nil {
		t.Fatal("expected error for nil localIPv6, got nil")
	}
	if !strings.Contains(err.Error(), "no link-local IPv6") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendPacketIPv6_WithLocalIPv6_SendsPacket(t *testing.T) {
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "lo",
		GroupID:   42,
		Priority:  200,
		VirtualAddresses: []string{"2001:db8::1/128"},
	}, &net.Interface{Name: "lo", Index: 1}, eventCh, nil)
	vi.localIPv6 = net.ParseIP("fe80::1")

	var sentData []byte
	var sentAddr net.Addr
	mock := &mockPacketConn{
		closed: make(chan struct{}),
	}
	// Override WriteTo to capture the sent data.
	vi.ipv6Conn = &capturingPacketConn{
		mockPacketConn: mock,
		onWriteTo: func(p []byte, addr net.Addr) {
			sentData = make([]byte, len(p))
			copy(sentData, p)
			sentAddr = addr
		},
	}

	pkt := &VRRPPacket{
		VRID:         42,
		Priority:     200,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.ParseIP("2001:db8::1")},
	}
	err := vi.sendPacketIPv6(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sentData == nil {
		t.Fatal("no data was sent")
	}
	// Verify Zone is not set on destination.
	ipAddr, ok := sentAddr.(*net.IPAddr)
	if !ok {
		t.Fatalf("addr type = %T, want *net.IPAddr", sentAddr)
	}
	if ipAddr.Zone != "" {
		t.Errorf("Zone = %q, want empty (socket has IPV6_MULTICAST_IF)", ipAddr.Zone)
	}
}

// capturingPacketConn wraps mockPacketConn to capture WriteTo calls.
type capturingPacketConn struct {
	*mockPacketConn
	onWriteTo func(p []byte, addr net.Addr)
}

func (c *capturingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.onWriteTo != nil {
		c.onWriteTo(p, addr)
	}
	return len(p), nil
}

// --- GARP suppression / epoch dedup tests (#104) ---

func TestSuppressGARPFlag(t *testing.T) {
	// Verify that the suppressGARP atomic flag can be set and read.
	vi := &vrrpInstance{}

	// Default: not suppressed.
	if vi.suppressGARP.Load() {
		t.Error("suppressGARP should default to false")
	}

	// Set suppressed.
	vi.suppressGARP.Store(true)
	if !vi.suppressGARP.Load() {
		t.Error("suppressGARP should be true after Store(true)")
	}

	// Clear suppression.
	vi.suppressGARP.Store(false)
	if vi.suppressGARP.Load() {
		t.Error("suppressGARP should be false after Store(false)")
	}
}

func TestGARPEpochDedup(t *testing.T) {
	// The garpEpoch increments on each becomeMaster() call.
	// sendGARP() skips if lastGARPEpoch == garpEpoch (already sent for this transition).
	vi := &vrrpInstance{}

	// Initial: epoch 0, lastGARPEpoch 0.
	if vi.garpEpoch.Load() != 0 {
		t.Errorf("initial garpEpoch = %d, want 0", vi.garpEpoch.Load())
	}
	if vi.lastGARPEpoch.Load() != 0 {
		t.Errorf("initial lastGARPEpoch = %d, want 0", vi.lastGARPEpoch.Load())
	}

	// Simulate first becomeMaster: epoch goes to 1.
	vi.garpEpoch.Add(1)
	if vi.garpEpoch.Load() != 1 {
		t.Errorf("garpEpoch after first transition = %d, want 1", vi.garpEpoch.Load())
	}

	// sendGARP would check: lastGARPEpoch(0) != garpEpoch(1) → proceed.
	// After sending, it records lastGARPEpoch = 1.
	epoch := vi.garpEpoch.Load()
	if vi.lastGARPEpoch.Load() == epoch && epoch > 0 {
		t.Error("should NOT skip — epoch changed since last send")
	}
	vi.lastGARPEpoch.Store(epoch)

	// Duplicate call: lastGARPEpoch(1) == garpEpoch(1) → skip.
	epoch = vi.garpEpoch.Load()
	if !(vi.lastGARPEpoch.Load() == epoch && epoch > 0) {
		t.Error("should skip — epoch unchanged since last send")
	}

	// Second becomeMaster: epoch goes to 2.
	vi.garpEpoch.Add(1)
	epoch = vi.garpEpoch.Load()
	if vi.lastGARPEpoch.Load() == epoch && epoch > 0 {
		t.Error("should NOT skip — new transition (epoch 2)")
	}
}

func TestGARPDampeningTime(t *testing.T) {
	// The lastGARPTime tracks Unix nanos of the last GARP send.
	// sendGARP() skips if time.Since(lastGARPTime) < 500ms.
	vi := &vrrpInstance{}

	// Initial: no dampening (lastGARPTime == 0).
	if vi.lastGARPTime.Load() != 0 {
		t.Errorf("initial lastGARPTime = %d, want 0", vi.lastGARPTime.Load())
	}

	// Simulate a GARP send at now.
	now := time.Now()
	vi.lastGARPTime.Store(now.UnixNano())

	// Check: too soon (< 500ms) → should be dampened.
	last := vi.lastGARPTime.Load()
	if last > 0 && time.Since(time.Unix(0, last)) >= 500*time.Millisecond {
		t.Error("should be dampened — sent just now")
	}

	// Simulate time passing: set lastGARPTime to 600ms ago.
	vi.lastGARPTime.Store(time.Now().Add(-600 * time.Millisecond).UnixNano())
	last = vi.lastGARPTime.Load()
	if last > 0 && time.Since(time.Unix(0, last)) < 500*time.Millisecond {
		t.Error("should NOT be dampened — 600ms elapsed")
	}
}

func TestManagerSetGARPSuppression(t *testing.T) {
	// Test that SetGARPSuppression sets the flag on matching instances.
	m := NewManager()
	eventCh := make(chan VRRPEvent, 16)

	// Create two instances: one for RG 1 (VRID 101), one for RG 2 (VRID 102).
	iface := &net.Interface{Index: 1, Name: "eth0"}
	vi1 := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
	}, iface, eventCh, nil)
	vi2 := newInstance(Instance{
		Interface: "eth1",
		GroupID:   102,
		Priority:  100,
	}, iface, eventCh, nil)

	m.mu.Lock()
	m.instances[instanceKey{iface: "eth0", groupID: 101}] = vi1
	m.instances[instanceKey{iface: "eth1", groupID: 102}] = vi2
	m.mu.Unlock()

	// Suppress GARP for RG 1 only.
	m.SetGARPSuppression(1, true)

	if !vi1.suppressGARP.Load() {
		t.Error("RG 1 instance should have GARP suppressed")
	}
	if vi2.suppressGARP.Load() {
		t.Error("RG 2 instance should NOT have GARP suppressed")
	}

	// Unsuppress RG 1.
	m.SetGARPSuppression(1, false)
	if vi1.suppressGARP.Load() {
		t.Error("RG 1 instance should have GARP unsuppressed")
	}
}
