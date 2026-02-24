package daemon

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestRgIDFromVRID(t *testing.T) {
	tests := []struct {
		vrid int
		want int
	}{
		{100, 0},
		{101, 1},
		{102, 2},
		{110, 10},
	}
	for _, tt := range tests {
		got := rgIDFromVRID(tt.vrid)
		if got != tt.want {
			t.Errorf("rgIDFromVRID(%d) = %d, want %d", tt.vrid, got, tt.want)
		}
	}
}

func TestBuildZoneRGMap(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust", Interfaces: []string{"reth0.0"}},
				"untrust": {Name: "untrust", Interfaces: []string{"reth1.0"}},
				"dmz":     {Name: "dmz", Interfaces: []string{"ge-0/0/2"}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"reth1":    {Name: "reth1", RedundancyGroup: 2},
				"ge-0/0/2": {Name: "ge-0/0/2"}, // no RG
			},
		},
	}

	zoneIDs := map[string]uint16{
		"dmz":     1,
		"trust":   2,
		"untrust": 3,
	}

	m := buildZoneRGMap(cfg, zoneIDs)

	// trust (zone 2) → reth0 → RG 1
	if rg, ok := m[2]; !ok || rg != 1 {
		t.Errorf("zone 'trust' (ID 2): expected RG 1, got %d (ok=%v)", rg, ok)
	}

	// untrust (zone 3) → reth1 → RG 2
	if rg, ok := m[3]; !ok || rg != 2 {
		t.Errorf("zone 'untrust' (ID 3): expected RG 2, got %d (ok=%v)", rg, ok)
	}

	// dmz (zone 1) → ge-0/0/2 → no RG → not in map
	if _, ok := m[1]; ok {
		t.Error("zone 'dmz' (ID 1): should not be in zone RG map (no RG)")
	}
}

func TestBuildZoneRGMapEmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	m := buildZoneRGMap(cfg, nil)
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

func TestRethInterfacesForRG(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units:           map[int]*config.InterfaceUnit{0: {}},
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
					Units:           map[int]*config.InterfaceUnit{0: {VlanID: 50}},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
				"ge-0/0/1": {
					Name:            "ge-0/0/1",
					RedundantParent: "reth1",
				},
			},
		},
	}

	// RG 1 should resolve reth0 → ge-0/0/0 → ge0
	ifaces := rethInterfacesForRG(cfg, 1)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface for RG 1, got %d: %v", len(ifaces), ifaces)
	}

	// RG 2 should resolve reth1 → ge-0/0/1 → ge1.50 (VLAN)
	ifaces2 := rethInterfacesForRG(cfg, 2)
	if len(ifaces2) != 1 {
		t.Fatalf("expected 1 interface for RG 2, got %d: %v", len(ifaces2), ifaces2)
	}

	// RG 3 should return nothing
	ifaces3 := rethInterfacesForRG(cfg, 3)
	if len(ifaces3) != 0 {
		t.Fatalf("expected 0 interfaces for RG 3, got %d", len(ifaces3))
	}
}
