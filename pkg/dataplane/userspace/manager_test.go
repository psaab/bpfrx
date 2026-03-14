package userspace

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestFindUserspaceEgressInterfaceSnapshotPrefersVLANUnit(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:            "ge-0/0/2",
				Ifindex:         6,
				ParentIfindex:   0,
				RedundancyGroup: 1,
			},
			{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			},
		},
	}
	iface, ok := findUserspaceEgressInterfaceSnapshot(snapshot, 6, 80)
	if !ok {
		t.Fatal("expected VLAN unit match")
	}
	if iface.Ifindex != 12 || iface.ParentIfindex != 6 || iface.RedundancyGroup != 1 {
		t.Fatalf("unexpected interface snapshot: %+v", iface)
	}
}

func TestSessionSyncEgressLockedDerivesOwnerAndTxPath(t *testing.T) {
	m := &Manager{
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{
				{
					Name:            "reth0.80",
					Ifindex:         12,
					ParentIfindex:   6,
					VLANID:          80,
					RedundancyGroup: 1,
				},
			},
		},
	}
	egress, tx, owner := m.sessionSyncEgressLocked(6, 80)
	if egress != 12 {
		t.Fatalf("egress = %d, want 12", egress)
	}
	if tx != 6 {
		t.Fatalf("tx = %d, want 6", tx)
	}
	if owner != 1 {
		t.Fatalf("owner = %d, want 1", owner)
	}
}

func TestMergeHAStateFromMaps(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	rgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("NewMap(rg_active): %v", err)
	}
	defer rgMap.Close()
	wdMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("NewMap(ha_watchdog): %v", err)
	}
	defer wdMap.Close()

	rgID := uint32(2)
	active := uint8(1)
	watchdog := uint64(12345)
	if err := rgMap.Update(rgID, active, ebpf.UpdateAny); err != nil {
		t.Fatalf("rgMap.Update: %v", err)
	}
	if err := wdMap.Update(rgID, watchdog, ebpf.UpdateAny); err != nil {
		t.Fatalf("wdMap.Update: %v", err)
	}

	merged, err := mergeHAStateFromMaps(rgMap, wdMap, map[int]HAGroupStatus{
		0: {RGID: 0, Active: false},
	})
	if err != nil {
		t.Fatalf("mergeHAStateFromMaps: %v", err)
	}
	if !merged[2].Active {
		t.Fatal("merged[2].Active = false, want true")
	}
	if got := merged[2].WatchdogTimestamp; got != watchdog {
		t.Fatalf("merged[2].WatchdogTimestamp = %d, want %d", got, watchdog)
	}
	if _, ok := merged[0]; !ok {
		t.Fatal("existing RG 0 state was dropped")
	}
}

func TestMacStringSuppressesZeroAndFormatsValue(t *testing.T) {
	if got := macString([]byte{0, 0, 0, 0, 0, 0}); got != "" {
		t.Fatalf("zero MAC = %q, want empty", got)
	}
	if got := macString([]byte{0x02, 0xbf, 0x72, 0x01, 0x01, 0x01}); got != "02:bf:72:01:01:01" {
		t.Fatalf("formatted MAC = %q", got)
	}
}

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
		"ge-0/0/0": {
			Name: "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}},
			},
		},
		"ge-0/0/1": {
			Name: "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "allow-all",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Security.DefaultPolicy = config.PolicyDeny
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
	if len(snap.Interfaces) != 4 {
		t.Fatalf("len(Interfaces) = %d, want 4", len(snap.Interfaces))
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
	if len(snap.Routes) < 4 {
		t.Fatalf("len(Routes) = %d, want at least 4", len(snap.Routes))
	}
	var sawDefaultV4, sawDefaultV6, sawConnectedV4, sawConnectedV6 bool
	for _, route := range snap.Routes {
		switch {
		case route.Table == "inet.0" && route.Destination == "0.0.0.0/0":
			sawDefaultV4 = true
		case route.Table == "vrf1.inet6.0" && route.Destination == "::/0":
			sawDefaultV6 = true
		case route.Table == "inet.0" && route.Destination == "10.0.0.0/24":
			sawConnectedV4 = true
		case route.Table == "inet6.0" && route.Destination == "2001:db8::/64":
			sawConnectedV6 = true
		}
	}
	if !sawDefaultV4 || !sawDefaultV6 || !sawConnectedV4 || !sawConnectedV6 {
		t.Fatalf("Routes = %+v", snap.Routes)
	}
	if len(snap.SourceNAT) != 1 {
		t.Fatalf("len(SourceNAT) = %d, want 1", len(snap.SourceNAT))
	}
	if !snap.SourceNAT[0].InterfaceMode || snap.SourceNAT[0].FromZone != "trust" || snap.SourceNAT[0].ToZone != "untrust" {
		t.Fatalf("SourceNAT[0] = %+v", snap.SourceNAT[0])
	}
	if snap.DefaultPolicy != "deny" {
		t.Fatalf("DefaultPolicy = %q, want deny", snap.DefaultPolicy)
	}
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	if snap.Policies[0].Action != "deny" && snap.Policies[0].Action != "permit" {
		t.Fatalf("Policies[0].Action = %q", snap.Policies[0].Action)
	}
}

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

func TestBuildRouteSnapshotsNormalizesFamilyFromDestination(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name: "blue",
			StaticRoutes: []*config.StaticRoute{
				{Destination: "2001:db8:1::/64", NextTable: "core"},
			},
		},
	}
	routes := buildRouteSnapshots(cfg, nil)
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if routes[0].Family != "inet6" || routes[0].Table != "blue.inet6.0" {
		t.Fatalf("routes[0] = %+v, want family inet6 table blue.inet6.0", routes[0])
	}
	if routes[1].Family != "inet6" || routes[1].Table != "inet6.0" {
		t.Fatalf("routes[1] = %+v, want family inet6 table inet6.0", routes[1])
	}
}

func TestBuildRouteSnapshotsIncludesConnectedPrefixes(t *testing.T) {
	routes := buildRouteSnapshots(&config.Config{}, []InterfaceSnapshot{
		{
			Name: "reth1.0",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.61.1/24", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet6", Address: "2001:559:8585:ef00::1/64", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet6", Address: "fe80::1/64", Scope: int(netlink.SCOPE_LINK)},
			},
		},
	})
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if routes[0].Destination != "10.0.61.0/24" || routes[0].Table != "inet.0" {
		t.Fatalf("routes[0] = %+v", routes[0])
	}
	if routes[1].Destination != "2001:559:8585:ef00::/64" || routes[1].Table != "inet6.0" {
		t.Fatalf("routes[1] = %+v", routes[1])
	}
}

func TestBuildLocalAddressEntries(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "reth0.50",
				Zone: "wan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "172.16.50.8/24"},
					{Family: "inet6", Address: "2001:559:8585:50::8/64"},
				},
			},
			{
				Name: "reth1.0",
				Zone: "lan",
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

func TestBuildLocalAddressEntriesIncludesInterfaceSNATAddressesForFallback(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "reth0.80",
				Zone: "wan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "172.16.80.8/24"},
					{Family: "inet6", Address: "2001:559:8585:80::8/64"},
				},
			},
			{
				Name: "reth1.0",
				Zone: "lan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.61.1/24"},
					{Family: "inet6", Address: "2001:559:8585:ef00::1/64"},
				},
			},
		},
		SourceNAT: []SourceNATRuleSnapshot{{
			Name:          "snat",
			FromZone:      "lan",
			ToZone:        "wan",
			InterfaceMode: true,
		}},
	}
	got := buildLocalAddressEntries(snapshot)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%+v)", len(got), got)
	}
	var sawWanV4, sawWanV6, sawLanV4, sawLanV6 bool
	lanV4 := uint32(0x0a003d01)
	var wanV6 [16]byte
	copy(wanV6[:], []byte(net.ParseIP("2001:559:8585:80::8").To16()))
	var lanV6 [16]byte
	copy(lanV6[:], []byte(net.ParseIP("2001:559:8585:ef00::1").To16()))
	for _, entry := range got {
		if entry.v4 && entry.v4Key == 0xac105008 {
			sawWanV4 = true
		}
		if entry.v4 && entry.v4Key == lanV4 {
			sawLanV4 = true
		}
		if !entry.v4 && entry.v6Key.Addr == wanV6 {
			sawWanV6 = true
		}
		if !entry.v4 && entry.v6Key.Addr == lanV6 {
			sawLanV6 = true
		}
	}
	if sawWanV4 || sawWanV6 {
		t.Fatalf("WAN interface NAT addresses unexpectedly included in local map: %+v", got)
	}
	if !sawLanV4 || !sawLanV6 {
		t.Fatalf("missing LAN interface addresses in local map: %+v", got)
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
	if len(caps.UnsupportedReasons) < 3 {
		t.Fatalf("UnsupportedReasons = %+v, want multiple reasons", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsDNSFlowKnobs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.AllowDNSReply = true
	cfg.Security.Flow.AllowEmbeddedICMP = true

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsHAFabricConfigs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:         22,
		PrivateRGElection: true,
		FabricInterface:   "fab0",
		FabricPeerAddress: "10.99.13.2",
	}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDesiredForwardingArmedTracksClusterOwnership(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
			1: {RGID: 1, Active: false},
			2: {RGID: 2, Active: false},
		},
	}
	if m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = true, want false with no active data RG")
	}
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: true}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true with active data RG")
	}
}

func TestDesiredForwardingArmedDefaultsOnStandalone(t *testing.T) {
	m := &Manager{
		clusterHA: false,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
	}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true on standalone supported config")
	}
}

func TestStopLockedClearsLastStatus(t *testing.T) {
	m := &Manager{
		lastStatus: ProcessStatus{
			PID:              1234,
			Enabled:          true,
			ForwardingArmed:  true,
			Capabilities:     UserspaceCapabilities{ForwardingSupported: true},
		},
	}

	m.stopLocked()

	if m.lastStatus.PID != 0 {
		t.Fatalf("lastStatus.PID = %d, want 0", m.lastStatus.PID)
	}
	if m.lastStatus.Enabled {
		t.Fatal("lastStatus.Enabled = true, want false")
	}
	if m.lastStatus.ForwardingArmed {
		t.Fatal("lastStatus.ForwardingArmed = true, want false")
	}
	if m.lastStatus.Capabilities.ForwardingSupported {
		t.Fatal("lastStatus.Capabilities.ForwardingSupported = true, want false")
	}
}

func TestUserspaceSupportsSimpleZonePolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "allow-all",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true")
	}
	snap := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if snap.DefaultPolicy != "deny" || len(snap.Policies) != 1 || snap.Policies[0].Action != "permit" {
		t.Fatalf("unexpected policy snapshot: %+v", snap.Policies)
	}
}

func TestUserspaceSupportsAddressBookPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"lan-subnet": {Name: "lan-subnet", Value: "10.0.61.0/24"},
			"wan-host":   {Name: "wan-host", Value: "172.16.80.200/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"wan-targets": {
				Name:      "wan-targets",
				Addresses: []string{"wan-host"},
			},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-address-book",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"lan-subnet"},
				DestinationAddresses: []string{"wan-targets"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true with resolvable address-book entries")
	}
	snap := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	if got := snap.Policies[0].SourceAddresses; len(got) != 1 || got[0] != "10.0.61.0/24" {
		t.Fatalf("SourceAddresses = %+v, want expanded address-book prefix", got)
	}
	if got := snap.Policies[0].DestinationAddresses; len(got) != 1 || got[0] != "172.16.80.200/32" {
		t.Fatalf("DestinationAddresses = %+v, want expanded address-set prefix", got)
	}
}

func TestUserspaceRejectsUnknownAddressBookPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-missing-address-book",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"missing-src"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = true, want false with unresolved address-book entry")
	}
}

func TestUserspaceSupportsNamedApplicationPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"web-apps": {
			Name:         "web-apps",
			Applications: []string{"junos-http", "junos-https"},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-web",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"web-apps"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true with resolvable application-set")
	}
	snap := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	terms := snap.Policies[0].ApplicationTerms
	if len(terms) != 2 {
		t.Fatalf("ApplicationTerms = %+v, want two expanded applications", terms)
	}
	if terms[0].Protocol != "tcp" || terms[0].DestinationPort == "" {
		t.Fatalf("unexpected first application term: %+v", terms[0])
	}
}

func TestUserspaceRejectsUnknownApplicationPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-missing-app",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"missing-app"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = true, want false with unresolved application")
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
