package cli

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestSessionDisplayVLANID(t *testing.T) {
	t.Run("prefers explicit vlan-id", func(t *testing.T) {
		unit := &config.InterfaceUnit{Number: 80, VlanID: 50}
		if got := sessionDisplayVLANID(unit); got != 50 {
			t.Fatalf("sessionDisplayVLANID() = %d, want 50", got)
		}
	})

	t.Run("falls back to unit number", func(t *testing.T) {
		unit := &config.InterfaceUnit{Number: 80}
		if got := sessionDisplayVLANID(unit); got != 80 {
			t.Fatalf("sessionDisplayVLANID() = %d, want 80", got)
		}
	})
}

func TestBuildSessionEgressIfaces_UsesUnitNumberWhenVlanIDUnset(t *testing.T) {
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{NodeID: 0},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						50: {Number: 50},
						80: {Number: 80},
					},
				},
				"ge-0/0/2": {
					Name:            "ge-0/0/2",
					RedundantParent: "reth0",
				},
				"ge-7/0/2": {
					Name:            "ge-7/0/2",
					RedundantParent: "reth0",
				},
			},
		},
	}

	m := buildSessionEgressIfacesWithLookup(cfg, func(name string) (int, error) {
		switch name {
		case "ge-0-0-2":
			return 6, nil
		case "ge-7-0-2":
			return 7, nil
		default:
			t.Fatalf("unexpected lookup name %q", name)
			return 0, nil
		}
	})
	if len(m) == 0 {
		t.Fatal("expected non-empty egress interface map")
	}

	var found50, found80 bool
	for key, name := range m {
		if key.vlanID == 50 && name == "reth0.50" {
			found50 = true
		}
		if key.vlanID == 80 && name == "reth0.80" {
			found80 = true
		}
	}
	if !found50 {
		t.Fatal("missing reth0.50 mapping")
	}
	if !found80 {
		t.Fatal("missing reth0.80 mapping")
	}
}
