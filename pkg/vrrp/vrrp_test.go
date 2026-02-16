package vrrp

import (
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestGenerateConfig_Basic(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          200,
			Preempt:           true,
			AdvertiseInterval: 1,
			VirtualAddresses:  []string{"10.0.1.1/24"},
		},
	}
	got := generateConfig(instances)

	checks := []string{
		"vrrp_instance VI_trust0_100",
		"state BACKUP",
		"interface trust0",
		"virtual_router_id 100",
		"priority 200",
		"advert_int 1",
		"10.0.1.1/24 dev trust0",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// With preempt=true, should NOT have "nopreempt"
	if strings.Contains(got, "nopreempt") {
		t.Error("unexpected nopreempt with Preempt=true")
	}
}

func TestGenerateConfig_NoPreempt(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          100,
			Preempt:           false,
			AdvertiseInterval: 2,
			VirtualAddresses:  []string{"10.0.1.1"},
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "nopreempt") {
		t.Error("missing nopreempt")
	}
	if !strings.Contains(got, "advert_int 2") {
		t.Error("missing advert_int 2")
	}
	// VIP without CIDR should get /32
	if !strings.Contains(got, "10.0.1.1/32 dev trust0") {
		t.Errorf("expected /32 suffix for VIP without CIDR, got:\n%s", got)
	}
}

func TestGenerateConfig_Auth(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          100,
			Preempt:           true,
			AdvertiseInterval: 1,
			AuthType:          "md5",
			AuthKey:           "secret123",
			VirtualAddresses:  []string{"10.0.1.1/24"},
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "auth_type AH") {
		t.Error("missing auth_type AH for md5")
	}
	if !strings.Contains(got, "auth_pass secret123") {
		t.Error("missing auth_pass")
	}
}

func TestGenerateConfig_AuthPass(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          100,
			Preempt:           true,
			AdvertiseInterval: 1,
			AuthType:          "",
			AuthKey:           "mykey",
			VirtualAddresses:  []string{"10.0.1.1/24"},
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "auth_type PASS") {
		t.Error("missing auth_type PASS for non-md5")
	}
}

func TestGenerateConfig_TrackInterface(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          200,
			Preempt:           true,
			AdvertiseInterval: 1,
			VirtualAddresses:  []string{"10.0.1.1/24"},
			TrackInterface:    "untrust0",
			TrackPriorityCost: 100,
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "track_interface") {
		t.Error("missing track_interface section")
	}
	if !strings.Contains(got, "untrust0 weight -100") {
		t.Errorf("missing track weight, got:\n%s", got)
	}
}

func TestGenerateConfig_AcceptData(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          100,
			AcceptData:        true,
			AdvertiseInterval: 1,
			VirtualAddresses:  []string{"10.0.1.1/24"},
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "accept") {
		t.Error("missing accept")
	}
}

func TestParseDataFile(t *testing.T) {
	data := `------< VRRP Topology >------
 VRRP Instance = VI_trust0_100
   State               = MASTER
   Last transition      = 1707868800
   Listening device     = trust0

 VRRP Instance = VI_untrust0_200
   State               = BACKUP
   Last transition      = 1707868801
`
	got := parseDataFile(data)
	if got["VI_trust0_100"] != "MASTER" {
		t.Errorf("VI_trust0_100: got %q, want MASTER", got["VI_trust0_100"])
	}
	if got["VI_untrust0_200"] != "BACKUP" {
		t.Errorf("VI_untrust0_200: got %q, want BACKUP", got["VI_untrust0_200"])
	}
}

func TestParseDataFile_Empty(t *testing.T) {
	got := parseDataFile("")
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

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

	// Sorted by name: reth0 before reth1.
	inst0 := instances[0]
	if inst0.Interface != "reth0" {
		t.Errorf("inst0.Interface = %q, want reth0", inst0.Interface)
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
	if inst1.Interface != "reth1" {
		t.Errorf("inst1.Interface = %q, want reth1", inst1.Interface)
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
			},
		},
	}
	instances := CollectRethInstances(cfg, map[int]int{1: 200})
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	if instances[0].Interface != "reth0-1" {
		t.Errorf("Interface = %q, want reth0-1 (slash replaced)", instances[0].Interface)
	}
}
