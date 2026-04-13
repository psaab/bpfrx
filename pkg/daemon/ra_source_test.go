package daemon

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/config"
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
