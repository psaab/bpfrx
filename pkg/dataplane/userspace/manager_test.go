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
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{FromZone: "trust", ToZone: "untrust"}}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "src",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules: []*config.NATRule{{
			Name: "snat",
			Match: config.NATMatch{
				SourceAddresses: []string{"0.0.0.0/0"},
			},
			Then: config.NATThen{
				Type:      config.NATSource,
				Interface: true,
			},
		}},
	}}
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
	if snap.MapPins.Ctrl == "" || snap.MapPins.Bindings == "" || snap.MapPins.Heartbeat == "" || snap.MapPins.XSK == "" || snap.MapPins.LocalV4 == "" || snap.MapPins.LocalV6 == "" {
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
	if snap.Interfaces[0].Zone != "untrust" {
		t.Fatalf("Interfaces[0].Zone = %q, want untrust", snap.Interfaces[0].Zone)
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
	if len(snap.SourceNAT) != 1 {
		t.Fatalf("len(SourceNAT) = %d, want 1", len(snap.SourceNAT))
	}
	if !snap.SourceNAT[0].InterfaceMode || snap.SourceNAT[0].FromZone != "trust" || snap.SourceNAT[0].ToZone != "untrust" {
		t.Fatalf("SourceNAT[0] = %+v", snap.SourceNAT[0])
	}
}

func TestBuildLocalAddressEntries(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "reth0.50",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "172.16.50.8/24"},
					{Family: "inet6", Address: "2001:559:8585:50::8/64"},
				},
			},
			{
				Name: "reth1.0",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.61.1/24"},
					{Family: "inet6", Address: "fe80::1/128"},
					{Family: "inet6", Address: "2001:559:8585:ef00::1/64"},
				},
			},
		},
	}
	got := buildLocalAddressEntries(snapshot)
	if len(got) != 5 {
		t.Fatalf("len(got) = %d, want 5 (%+v)", len(got), got)
	}
}

func TestDeriveUserspaceCapabilitiesDetectsFirewallFeatures(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"trust": {Name: "trust"}}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{Name: "src"}}
	cfg.Security.Flow.AllowDNSReply = true
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{"f1": {Name: "f1"}}
	cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{"gw1": {Name: "gw1"}}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{}

	caps := deriveUserspaceCapabilities(cfg)
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true, want false")
	}
	if len(caps.UnsupportedReasons) < 5 {
		t.Fatalf("UnsupportedReasons = %+v, want multiple reasons", caps.UnsupportedReasons)
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
				50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:559:8585:50::8/64"}},
			},
		},
		"ge-0/0/2": {
			Name:            "ge-0/0/2",
			RedundantParent: "reth0",
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"reth0.50"}},
	}

	snap := buildSnapshot(cfg, config.UserspaceConfig{Workers: 2, RingEntries: 2048}, 1, 0)
	got := map[string]InterfaceSnapshot{}
	for _, iface := range snap.Interfaces {
		got[iface.Name] = iface
	}
	for _, name := range []string{"reth0", "reth0.0", "reth0.50"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("snapshot missing interface %s: %+v", name, snap.Interfaces)
		}
	}
	if got["reth0"].LinuxName != "ge-0-0-2" {
		t.Fatalf("reth0 LinuxName = %q, want ge-0-0-2", got["reth0"].LinuxName)
	}
	if got["reth0.0"].LinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.0 LinuxName = %q, want ge-0-0-2", got["reth0.0"].LinuxName)
	}
	if got["reth0.0"].ParentLinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.0 ParentLinuxName = %q, want ge-0-0-2", got["reth0.0"].ParentLinuxName)
	}
	if got["reth0.50"].LinuxName != "ge-0-0-2.50" {
		t.Fatalf("reth0.50 LinuxName = %q, want ge-0-0-2.50", got["reth0.50"].LinuxName)
	}
	if got["reth0.50"].ParentLinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.50 ParentLinuxName = %q, want ge-0-0-2", got["reth0.50"].ParentLinuxName)
	}
	if got["reth0.50"].VLANID != 50 {
		t.Fatalf("reth0.50 VLANID = %d, want 50", got["reth0.50"].VLANID)
	}
	if got["reth0.50"].Zone != "wan" {
		t.Fatalf("reth0.50 Zone = %q, want wan", got["reth0.50"].Zone)
	}
	if len(got["reth0.50"].Addresses) != 2 {
		t.Fatalf("reth0.50 Addresses = %+v, want config fallback addresses", got["reth0.50"].Addresses)
	}
}

func TestMergeInterfaceAddressSnapshots(t *testing.T) {
	live := []InterfaceAddressSnapshot{
		{Family: "inet", Address: "169.254.1.1/32", Scope: 253},
		{Family: "inet6", Address: "fe80::1/128", Scope: 253},
	}
	configured := []InterfaceAddressSnapshot{
		{Family: "inet", Address: "172.16.50.8/24", Scope: 0},
		{Family: "inet6", Address: "2001:559:8585:50::8/64", Scope: 0},
		{Family: "inet", Address: "169.254.1.1/32", Scope: 253},
	}

	got := mergeInterfaceAddressSnapshots(live, configured)
	if len(got) != 4 {
		t.Fatalf("len(got) = %d, want 4 (%+v)", len(got), got)
	}
	want := map[string]bool{
		"inet/169.254.1.1/32":          true,
		"inet/172.16.50.8/24":          true,
		"inet6/2001:559:8585:50::8/64": true,
		"inet6/fe80::1/128":            true,
	}
	for _, addr := range got {
		key := addr.Family + "/" + addr.Address
		if !want[key] {
			t.Fatalf("unexpected address %s in %+v", key, got)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing addresses: %+v from %+v", want, got)
	}
}
