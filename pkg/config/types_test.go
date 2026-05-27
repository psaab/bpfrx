package config

import (
	"testing"
)

func TestRethToPhysical(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"reth1":    {Name: "reth1", RedundancyGroup: 2},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
				"trust0":   {Name: "trust0"},
			},
		},
	}

	m := cfg.RethToPhysical()
	if len(m) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(m))
	}
	if m["reth0"] != "ge-0/0/0" {
		t.Errorf("reth0 → %q, want ge-0/0/0", m["reth0"])
	}
	if m["reth1"] != "ge-0/0/1" {
		t.Errorf("reth1 → %q, want ge-0/0/1", m["reth1"])
	}
}

func TestRethToPhysical_Empty(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"trust0": {Name: "trust0"},
			},
		},
	}
	m := cfg.RethToPhysical()
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

func TestResolveReth(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
	}

	tests := []struct {
		input string
		want  string
	}{
		{"reth0", "ge-0/0/0"},
		{"reth0.50", "ge-0/0/0.50"},
		{"trust0", "trust0"},
		{"trust0.0", "trust0.0"},
		{"reth1", "reth1"}, // not mapped
	}
	for _, tt := range tests {
		got := cfg.ResolveReth(tt.input)
		if got != tt.want {
			t.Errorf("ResolveReth(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRethToPhysical_PrefersLocalClusterMember(t *testing.T) {
	cfg := &Config{
		Chassis: ChassisConfig{
			Cluster: &ClusterConfig{NodeID: 0},
		},
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
				"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
			},
		},
	}

	if got := cfg.RethToPhysical()["reth0"]; got != "ge-0/0/2" {
		t.Fatalf("reth0 → %q, want ge-0/0/2", got)
	}
	if got := cfg.ResolveReth("reth0.80"); got != "ge-0/0/2.80" {
		t.Fatalf("ResolveReth(reth0.80) = %q, want ge-0/0/2.80", got)
	}
}

// --- ResolveKernelIfName tests (#1565) ---

func TestResolveKernelIfName_Plain(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
					0:  {Number: 0, VlanID: 0},
					80: {Number: 80, VlanID: 180},
				}},
				"em0":  {Name: "em0"},
				"fxp0": {Name: "fxp0"},
			},
		},
	}

	tests := []struct {
		in, want string
	}{
		{"em0", "em0"},
		{"fxp0", "fxp0"},
		{"lo", "lo"},
		{"ge-0/0/0", "ge-0-0-0"},
		{"ge-0/0/0.0", "ge-0-0-0"},     // unit 0 with vlan-id 0 collapses
		{"ge-0/0/0.80", "ge-0-0-0.180"}, // VLAN tag, NOT unit number
	}
	for _, tt := range tests {
		if got := cfg.ResolveKernelIfName(tt.in); got != tt.want {
			t.Errorf("ResolveKernelIfName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveKernelIfName_Reth(t *testing.T) {
	// Node 0: local member is ge-0/0/2.
	cfg := &Config{
		Chassis: ChassisConfig{Cluster: &ClusterConfig{NodeID: 0}},
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*InterfaceUnit{
					0:  {Number: 0, VlanID: 0},
					50: {Number: 50, VlanID: 50},
					80: {Number: 80, VlanID: 180},
				}},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
				"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
			},
		},
	}

	tests := []struct {
		in, want string
	}{
		{"reth0", "ge-0-0-2"},
		{"reth0.0", "ge-0-0-2"},        // unit 0 collapse
		{"reth0.50", "ge-0-0-2.50"},    // vlan-id == unit
		{"reth0.80", "ge-0-0-2.180"},   // vlan-id != unit — the failure case
	}
	for _, tt := range tests {
		if got := cfg.ResolveKernelIfName(tt.in); got != tt.want {
			t.Errorf("node 0: ResolveKernelIfName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	// Node 1: local member is ge-7/0/2.
	cfg.Chassis.Cluster.NodeID = 1
	if got := cfg.ResolveKernelIfName("reth0"); got != "ge-7-0-2" {
		t.Errorf("node 1: ResolveKernelIfName(reth0) = %q, want ge-7-0-2", got)
	}
	if got := cfg.ResolveKernelIfName("reth0.80"); got != "ge-7-0-2.180" {
		t.Errorf("node 1: ResolveKernelIfName(reth0.80) = %q, want ge-7-0-2.180", got)
	}
}

func TestResolveKernelIfName_Fab(t *testing.T) {
	// fab0 is a real kernel IPVLAN device — do NOT resolve to parent.
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"fab0": {Name: "fab0", LocalFabricMember: "ge-0/0/0", Units: map[int]*InterfaceUnit{
					0: {Number: 0, VlanID: 0},
				}},
				"fab1": {Name: "fab1", LocalFabricMember: "ge-0/0/0"},
			},
		},
	}
	tests := []struct {
		in, want string
	}{
		{"fab0", "fab0"},
		{"fab0.0", "fab0"}, // unit 0 collapse
		{"fab1", "fab1"},
	}
	for _, tt := range tests {
		if got := cfg.ResolveKernelIfName(tt.in); got != tt.want {
			t.Errorf("ResolveKernelIfName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveKernelIfName_Tunnel(t *testing.T) {
	// Interface-level tunnel: unit 0 maps to base Linux name.
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"gr-0/0/0": {
					Name:   "gr-0/0/0",
					Tunnel: &TunnelConfig{Source: "10.0.0.1", Destination: "10.0.0.2"},
					Units: map[int]*InterfaceUnit{
						0: {Number: 0},
					},
				},
			},
		},
	}
	if got := cfg.ResolveKernelIfName("gr-0/0/0.0"); got != "gr-0-0-0" {
		t.Errorf("interface-level tunnel: ResolveKernelIfName(gr-0/0/0.0) = %q, want gr-0-0-0", got)
	}

	// Per-unit tunnel: explicit unit.Tunnel.Name.
	cfgPerUnit := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"gr-0/0/0": {
					Name: "gr-0/0/0",
					Units: map[int]*InterfaceUnit{
						0: {Number: 0, Tunnel: &TunnelConfig{Name: "gr-0-0-0", Source: "10.0.0.1"}},
						1: {Number: 1, Tunnel: &TunnelConfig{Name: "gr-0-0-0u1", Source: "10.0.0.3"}},
					},
				},
			},
		},
	}
	if got := cfgPerUnit.ResolveKernelIfName("gr-0/0/0.0"); got != "gr-0-0-0" {
		t.Errorf("per-unit tunnel: ResolveKernelIfName(gr-0/0/0.0) = %q, want gr-0-0-0", got)
	}
	if got := cfgPerUnit.ResolveKernelIfName("gr-0/0/0.1"); got != "gr-0-0-0u1" {
		t.Errorf("per-unit tunnel: ResolveKernelIfName(gr-0/0/0.1) = %q, want gr-0-0-0u1", got)
	}
}

func TestResolveKernelIfName_TunnelOverridesVlan(t *testing.T) {
	// If a unit has both tunnel.Name and a vlan-id, tunnel wins.
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*InterfaceUnit{
					50: {Number: 50, VlanID: 999, Tunnel: &TunnelConfig{Name: "gr-foo"}},
				}},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
			},
		},
	}
	if got := cfg.ResolveKernelIfName("reth0.50"); got != "gr-foo" {
		t.Errorf("tunnel-overrides-vlan: ResolveKernelIfName(reth0.50) = %q, want gr-foo", got)
	}
}

func TestResolveKernelIfName_IRB(t *testing.T) {
	cfg := &Config{
		BridgeDomains: []*BridgeDomainConfig{
			{Name: "bd0", RoutingInterface: "irb.0"},
		},
	}
	if got := cfg.ResolveKernelIfName("irb.0"); got != "br-bd0" {
		t.Errorf("IRB: ResolveKernelIfName(irb.0) = %q, want br-bd0", got)
	}
}

func TestResolveKernelIfName_UnknownUnit(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
					0: {Number: 0},
				}},
			},
		},
	}
	// Unit 99 is not configured — fallback preserves suffix.
	if got := cfg.ResolveKernelIfName("ge-0/0/0.99"); got != "ge-0-0-0.99" {
		t.Errorf("unknown unit fallback: ResolveKernelIfName(ge-0/0/0.99) = %q, want ge-0-0-0.99", got)
	}
}

func TestResolveKernelIfName_MalformedSuffix(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
					0: {Number: 0},
				}},
			},
		},
	}
	// Non-numeric suffix must NOT silently map to unit 0.
	if got := cfg.ResolveKernelIfName("ge-0/0/0.foo"); got != "ge-0-0-0.foo" {
		t.Errorf("malformed suffix fallback: ResolveKernelIfName(ge-0/0/0.foo) = %q, want ge-0-0-0.foo", got)
	}
}

func TestResolveKernelIfName_InterfaceLevelTunnel(t *testing.T) {
	// Mirrors cluster cfg shape: gr-0/0/0 with tunnel{} and unit 0 only.
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"gr-0/0/0": {
					Name:   "gr-0/0/0",
					Tunnel: &TunnelConfig{Source: "2001:db8::1", Destination: "2001:db8::2"},
					Units: map[int]*InterfaceUnit{
						0: {Number: 0},
					},
				},
			},
		},
	}
	if got := cfg.ResolveKernelIfName("gr-0/0/0.0"); got != "gr-0-0-0" {
		t.Errorf("interface-level tunnel cluster-shape: got %q, want gr-0-0-0", got)
	}
}

func TestResolveKernelIfName_StXfrm(t *testing.T) {
	cfg := &Config{}
	tests := []struct {
		in, want string
	}{
		{"st0", "st0"},
		{"st0.0", "st0.0"},
		{"st0.5", "st0.5"},
		{"st1", "st1"},
		{"st1.10", "st1.10"},
	}
	for _, tt := range tests {
		if got := cfg.ResolveKernelIfName(tt.in); got != tt.want {
			t.Errorf("ResolveKernelIfName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveKernelIfName_NilInterfaces(t *testing.T) {
	cfg := &Config{}
	// Nil c.Interfaces.Interfaces must not panic; fallback to LinuxIfName.
	if got := cfg.ResolveKernelIfName("ge-0/0/0.80"); got != "ge-0-0-0.80" {
		t.Errorf("nil Interfaces: ResolveKernelIfName(ge-0/0/0.80) = %q, want ge-0-0-0.80", got)
	}
}

// --- DHCPLeaseKey tests (#1565) ---

func TestDHCPLeaseKey_Mappings(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
					0: {Number: 0, VlanID: 0},
					1: {Number: 1, VlanID: 80},
				}},
				"reth0": {Name: "reth0", Units: map[int]*InterfaceUnit{
					50: {Number: 50, VlanID: 50},
					80: {Number: 80, VlanID: 180},
				}},
				"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
			},
		},
	}

	tests := []struct {
		ref     string
		unit    int
		wantKey string
		wantOK  bool
	}{
		// No-VLAN unit: key is just the Linux base.
		{"ge-0/0/0", 0, "ge-0-0-0", true},
		// Positive VlanID: key is base + .VlanID.
		{"ge-0/0/0", 1, "ge-0-0-0.80", true},
		// Reth keys by CONFIG-LEVEL name, NOT resolved physical.
		{"reth0", 50, "reth0.50", true},
		{"reth0", 80, "reth0.180", true},
		// Unit not configured.
		{"ge-0/0/0", 99, "", false},
		// Base not configured.
		{"ge-9/9/9", 0, "", false},
		// Suffix in physRef must be stripped before lookup.
		{"reth0.50", 50, "reth0.50", true},
	}
	for _, tt := range tests {
		gotKey, gotOK := cfg.DHCPLeaseKey(tt.ref, tt.unit)
		if gotKey != tt.wantKey || gotOK != tt.wantOK {
			t.Errorf("DHCPLeaseKey(%q, %d) = (%q, %v), want (%q, %v)",
				tt.ref, tt.unit, gotKey, gotOK, tt.wantKey, tt.wantOK)
		}
	}
}
