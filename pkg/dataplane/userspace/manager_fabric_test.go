package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildFabricSnapshotsUsesLocalMemberAndPeer(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		FabricInterface:    "fab0",
		FabricPeerAddress:  "10.99.1.2",
		Fabric1Interface:   "fab1",
		Fabric1PeerAddress: "10.99.2.2",
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fab0": {Name: "fab0", LocalFabricMember: "ge-0/0/0"},
		"fab1": {Name: "fab1", LocalFabricMember: "ge-7/0/0"},
	}

	fabrics := buildFabricSnapshots(cfg)
	if len(fabrics) != 2 {
		t.Fatalf("len(fabrics) = %d, want 2", len(fabrics))
	}
	if fabrics[0].Name != "fab0" || fabrics[0].ParentInterface != "ge-0/0/0" || fabrics[0].ParentLinuxName != "ge-0-0-0" || fabrics[0].PeerAddress != "10.99.1.2" {
		t.Fatalf("fabrics[0] = %+v", fabrics[0])
	}
	if fabrics[1].Name != "fab1" || fabrics[1].ParentInterface != "ge-7/0/0" || fabrics[1].ParentLinuxName != "ge-7-0-0" || fabrics[1].PeerAddress != "10.99.2.2" {
		t.Fatalf("fabrics[1] = %+v", fabrics[1])
	}
}
