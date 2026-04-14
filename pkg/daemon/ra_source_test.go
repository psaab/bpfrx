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
