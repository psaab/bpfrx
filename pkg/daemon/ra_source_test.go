package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

func TestBuildRAConfigsUsesStableRethLinkLocal(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{ClusterID: 22},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"2001:559:8585:ef00::1/64"}},
					},
				},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{
				{Interface: "reth1"},
			},
		},
	}

	ras := d.buildRAConfigs(cfg)
	if len(ras) != 1 {
		t.Fatalf("buildRAConfigs returned %d RAs, want 1", len(ras))
	}

	wantLL := cluster.StableRethLinkLocal(22, 2).String()
	if ras[0].SourceLinkLocal != wantLL {
		t.Fatalf("SourceLinkLocal = %q, want %q", ras[0].SourceLinkLocal, wantLL)
	}
}

func TestBuildRAConfigsPrefersExplicitLinkLocal(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{ClusterID: 22},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"fe80::face/64", "2001:559:8585:ef00::1/64"}},
					},
				},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{
				{Interface: "reth1"},
			},
		},
	}

	ras := d.buildRAConfigs(cfg)
	if len(ras) != 1 {
		t.Fatalf("buildRAConfigs returned %d RAs, want 1", len(ras))
	}
	if ras[0].SourceLinkLocal != "fe80::face" {
		t.Fatalf("SourceLinkLocal = %q, want fe80::face", ras[0].SourceLinkLocal)
	}
}

// TestBuildRAConfigsPrefersLinkLocalOnNonZeroUnit is the #2996 bug case: RA
// configured on a bare interface whose link-local lives on a NON-ZERO unit
// (e.g. a VLAN subinterface). The old Units[0]-only lookup missed it and fell
// back to an auto-selected link-local. The configured address must win.
func TestBuildRAConfigsPrefersLinkLocalOnNonZeroUnit(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/2": {
					Name: "ge-0/0/2",
					Units: map[int]*config.InterfaceUnit{
						0:  {Addresses: []string{"2001:db8::1/64"}},
						50: {VlanID: 50, Addresses: []string{"fe80::50/64", "2001:db8:50::1/64"}},
					},
				},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{
				{Interface: "ge-0/0/2"},
			},
		},
	}

	ras := d.buildRAConfigs(cfg)
	if len(ras) != 1 {
		t.Fatalf("buildRAConfigs returned %d RAs, want 1", len(ras))
	}
	if ras[0].SourceLinkLocal != "fe80::50" {
		t.Fatalf("SourceLinkLocal = %q, want fe80::50 (link-local on unit 50)", ras[0].SourceLinkLocal)
	}
}

// TestBuildRAConfigsUnitQualifiedInterface covers a unit-qualified RA interface
// name ("ge-0/0/2.50"). cfg.Interfaces.Interfaces is keyed by the base name, so
// the lookup must split off the unit and prefer THAT unit's configured
// link-local.
func TestBuildRAConfigsUnitQualifiedInterface(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/2": {
					Name: "ge-0/0/2",
					Units: map[int]*config.InterfaceUnit{
						0:  {Addresses: []string{"fe80::aaaa/64"}},
						50: {VlanID: 50, Addresses: []string{"fe80::5050/64", "2001:db8:50::1/64"}},
						80: {VlanID: 80, Addresses: []string{"fe80::8080/64"}},
					},
				},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{
				{Interface: "ge-0/0/2.50"},
			},
		},
	}

	ras := d.buildRAConfigs(cfg)
	if len(ras) != 1 {
		t.Fatalf("buildRAConfigs returned %d RAs, want 1", len(ras))
	}
	if ras[0].SourceLinkLocal != "fe80::5050" {
		t.Fatalf("SourceLinkLocal = %q, want fe80::5050 (link-local on the bound unit 50)", ras[0].SourceLinkLocal)
	}
	// And the resolved (Linux) interface name must reflect the unit.
	if ras[0].Interface != "ge-0-0-2.50" {
		t.Fatalf("resolved Interface = %q, want ge-0-0-2.50", ras[0].Interface)
	}
}

func TestBuildRAConfigsDoesNotMutateConfiguredRAEntries(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{ClusterID: 22},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"2001:559:8585:ef00::1/64"}},
					},
				},
				"ge-0/0/1": {
					Name:            "ge-0/0/1",
					RedundantParent: "reth1",
				},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{
				{
					Interface:  "reth1",
					DNSServers: []string{"2001:4860:4860::8888"},
					Prefixes: []*config.RAPrefix{
						{Prefix: "2001:559:8585:ef00::/64", OnLink: true, Autonomous: true},
					},
				},
			},
		},
	}

	ras := d.buildRAConfigs(cfg)
	if len(ras) != 1 {
		t.Fatalf("buildRAConfigs returned %d RAs, want 1", len(ras))
	}
	if ras[0].Interface != "ge-0-0-1" {
		t.Fatalf("returned Interface = %q, want ge-0-0-1", ras[0].Interface)
	}
	if ras[0].SourceLinkLocal == "" {
		t.Fatal("returned SourceLinkLocal is empty, want stable fallback")
	}

	gotCfg := cfg.Protocols.RouterAdvertisement[0]
	if gotCfg.Interface != "reth1" {
		t.Fatalf("configured Interface mutated to %q, want reth1", gotCfg.Interface)
	}
	if gotCfg.SourceLinkLocal != "" {
		t.Fatalf("configured SourceLinkLocal mutated to %q, want empty", gotCfg.SourceLinkLocal)
	}
	if len(gotCfg.Prefixes) != 1 || gotCfg.Prefixes[0].Prefix != "2001:559:8585:ef00::/64" {
		t.Fatalf("configured prefixes mutated to %#v", gotCfg.Prefixes)
	}
	if len(gotCfg.DNSServers) != 1 || gotCfg.DNSServers[0] != "2001:4860:4860::8888" {
		t.Fatalf("configured DNSServers mutated to %#v", gotCfg.DNSServers)
	}
}
