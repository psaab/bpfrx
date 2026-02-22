package vrrp

import (
	"net"
	"testing"

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
	if !inst0.Preempt {
		t.Error("inst0.Preempt should be true")
	}
	if !inst0.AcceptData {
		t.Error("inst0.AcceptData should be true")
	}
	if inst0.AdvertiseInterval != 1 {
		t.Errorf("inst0.AdvertiseInterval = %d, want 1", inst0.AdvertiseInterval)
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
