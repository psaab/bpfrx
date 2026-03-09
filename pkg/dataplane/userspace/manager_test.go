package userspace

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestDeriveUserspaceConfigDefaults(t *testing.T) {
	cfg := deriveUserspaceConfig(&config.Config{})
	if cfg.Workers != 1 {
		t.Fatalf("Workers = %d, want 1", cfg.Workers)
	}
	if cfg.RingEntries != 1024 {
		t.Fatalf("RingEntries = %d, want 1024", cfg.RingEntries)
	}
	if cfg.ControlSocket == "" {
		t.Fatal("ControlSocket is empty")
	}
	if cfg.StateFile == "" {
		t.Fatal("StateFile is empty")
	}
}

func TestBuildSnapshotSummary(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.HostName = "fw-test"
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0"},
		"ge-0/0/1": {Name: "ge-0/0/1"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{FromZone: "trust", ToZone: "untrust"}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.0.1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:              "vrf1",
			Inet6StaticRoutes: []*config.StaticRoute{{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "fe80::1", Interface: "ge-0/0/0.0"}}}},
		},
	}

	snap := buildSnapshot(cfg, config.UserspaceConfig{Workers: 2, RingEntries: 2048}, 11, 5)
	if snap.Generation != 11 {
		t.Fatalf("Generation = %d, want 11", snap.Generation)
	}
	if snap.FIBGeneration != 5 {
		t.Fatalf("FIBGeneration = %d, want 5", snap.FIBGeneration)
	}
	if snap.MapPins.Ctrl == "" || snap.MapPins.Bindings == "" || snap.MapPins.XSK == "" {
		t.Fatalf("MapPins = %+v, want all paths populated", snap.MapPins)
	}
	if snap.Summary.HostName != "fw-test" {
		t.Fatalf("HostName = %q", snap.Summary.HostName)
	}
	if snap.Summary.InterfaceCount != 2 {
		t.Fatalf("InterfaceCount = %d, want 2", snap.Summary.InterfaceCount)
	}
	if snap.Summary.ZoneCount != 2 {
		t.Fatalf("ZoneCount = %d, want 2", snap.Summary.ZoneCount)
	}
	if snap.Summary.PolicyCount != 1 {
		t.Fatalf("PolicyCount = %d, want 1", snap.Summary.PolicyCount)
	}
	if snap.Summary.SchedulerCount != 1 {
		t.Fatalf("SchedulerCount = %d, want 1", snap.Summary.SchedulerCount)
	}
	if !snap.Summary.HAEnabled {
		t.Fatal("HAEnabled = false, want true")
	}
	if len(snap.Interfaces) != 2 {
		t.Fatalf("len(Interfaces) = %d, want 2", len(snap.Interfaces))
	}
	if snap.Interfaces[0].Name != "ge-0/0/0" {
		t.Fatalf("Interfaces[0].Name = %q", snap.Interfaces[0].Name)
	}
	if snap.Interfaces[0].LinuxName != "ge-0-0-0" {
		t.Fatalf("Interfaces[0].LinuxName = %q", snap.Interfaces[0].LinuxName)
	}
	if len(snap.Routes) != 2 {
		t.Fatalf("len(Routes) = %d, want 2", len(snap.Routes))
	}
	if snap.Routes[0].Table != "inet.0" || snap.Routes[0].Destination != "0.0.0.0/0" {
		t.Fatalf("Routes[0] = %+v", snap.Routes[0])
	}
	if snap.Routes[1].Table != "vrf1.inet6.0" || snap.Routes[1].Destination != "::/0" {
		t.Fatalf("Routes[1] = %+v", snap.Routes[1])
	}
}

func TestBuildSnapshotIncludesUnitInterfaces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name:            "reth0",
			RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"10.0.61.1/24", "2001:559:8585:ef00::1/64"}},
				50: {Number: 50, Addresses: []string{"172.16.50.8/24", "2001:559:8585:50::8/64"}},
			},
		},
	}

	snap := buildSnapshot(cfg, config.UserspaceConfig{Workers: 2, RingEntries: 2048}, 1, 0)
	got := map[string]bool{}
	for _, iface := range snap.Interfaces {
		got[iface.Name] = true
	}
	for _, name := range []string{"reth0", "reth0.0", "reth0.50"} {
		if !got[name] {
			t.Fatalf("snapshot missing interface %s: %+v", name, snap.Interfaces)
		}
	}
}
