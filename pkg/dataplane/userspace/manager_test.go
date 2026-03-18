package userspace

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/vishvananda/netlink"
)

func hostToNetwork16(v uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return binary.NativeEndian.Uint16(raw[:])
}

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

func TestSessionSyncTunnelEndpointIDLockedMatchesLogicalTunnelIfindex(t *testing.T) {
	m := &Manager{
		lastSnapshot: &ConfigSnapshot{
			TunnelEndpoints: []TunnelEndpointSnapshot{{
				ID:      3,
				Ifindex: 586,
			}},
		},
	}
	if got := m.sessionSyncTunnelEndpointIDLocked(586); got != 3 {
		t.Fatalf("tunnel endpoint id = %d, want 3", got)
	}
	if got := m.sessionSyncTunnelEndpointIDLocked(24); got != 0 {
		t.Fatalf("tunnel endpoint id for non-tunnel ifindex = %d, want 0", got)
	}
}

func TestBuildSessionSyncRequestV4ConvertsPortsToHostOrder(t *testing.T) {
	m := &Manager{
		inner: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			}},
		},
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := &dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		Flags:       dataplane.SessFlagSNAT,
		LogFlags:    dataplane.LogFlagUserspaceFabricIngress,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    binary.NativeEndian.Uint32([]byte{172, 16, 80, 8}),
		NATSrcPort:  hostToNetwork16(40000),
	}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.SrcPort != 50952 || req.DstPort != 5201 {
		t.Fatalf("unexpected host-order request ports: %+v", req)
	}
	if req.NATSrcPort != 40000 {
		t.Fatalf("unexpected nat src port: %d", req.NATSrcPort)
	}
	if !req.FabricIngress {
		t.Fatalf("expected fabric_ingress to be preserved: %+v", req)
	}
}

func TestBuildSessionSyncRequestV4PreservesTunnelEndpointIdentity(t *testing.T) {
	m := &Manager{
		inner: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "gr-0/0/0.0",
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
			TunnelEndpoints: []TunnelEndpointSnapshot{{
				ID:      3,
				Ifindex: 586,
			}},
		},
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{10, 255, 192, 41},
		SrcPort:  hostToNetwork16(4459),
		DstPort:  hostToNetwork16(4459),
		Protocol: 1,
	}
	val := &dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		FibIfindex:  586,
		FibVlanID:   80,
		FibDmac:     [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		FibSmac:     [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08},
	}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.TunnelEndpointID != 3 {
		t.Fatalf("unexpected tunnel endpoint id: %d", req.TunnelEndpointID)
	}
	if req.EgressIfindex != 586 {
		t.Fatalf("unexpected egress ifindex: %d", req.EgressIfindex)
	}
	if req.TXIfindex != 0 {
		t.Fatalf("unexpected tx ifindex: %d", req.TXIfindex)
	}
}

func TestBuildSessionSyncRequestV6ConvertsPortsToHostOrder(t *testing.T) {
	m := &Manager{
		inner: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			}},
		},
	}
	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:559:8585:ef00::100").To16())
	copy(dstIP[:], net.ParseIP("2001:559:8585:80::200").To16())
	var natSrc [16]byte
	copy(natSrc[:], net.ParseIP("2001:559:8585:80::8").To16())
	key := dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := &dataplane.SessionValueV6{
		IngressZone: 1,
		EgressZone:  2,
		Flags:       dataplane.SessFlagSNAT,
		LogFlags:    dataplane.LogFlagUserspaceFabricIngress,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    natSrc,
		NATSrcPort:  hostToNetwork16(40000),
	}
	req := m.buildSessionSyncRequestV6("upsert", key, val)
	if req.SrcPort != 50952 || req.DstPort != 5201 {
		t.Fatalf("unexpected host-order request ports: %+v", req)
	}
	if req.NATSrcPort != 40000 {
		t.Fatalf("unexpected nat src port: %d", req.NATSrcPort)
	}
	if !req.FabricIngress {
		t.Fatalf("expected fabric_ingress to be preserved: %+v", req)
	}
}

func TestShouldMirrorUserspaceSessionSkipsReverseEntries(t *testing.T) {
	if !shouldMirrorUserspaceSession(0) {
		t.Fatal("expected forward sessions to be mirrored")
	}
	if shouldMirrorUserspaceSession(1) {
		t.Fatal("expected reverse sessions to be skipped")
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

func TestSeedHAGroupInventoryLockedSeedsConfiguredStandbyGroups(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true, WatchdogTimestamp: 111},
			2: {RGID: 2, Active: true, WatchdogTimestamp: 222},
			9: {RGID: 9, Active: true, WatchdogTimestamp: 999},
		},
	}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 1},
					{ID: 2},
				},
			},
		},
	}

	m.seedHAGroupInventoryLocked(cfg)

	if _, ok := m.haGroups[1]; !ok {
		t.Fatal("expected configured standby RG1 to be seeded")
	}
	if group := m.haGroups[2]; !group.Active || group.WatchdogTimestamp != 222 {
		t.Fatalf("configured RG2 state not preserved: %+v", group)
	}
	if group := m.haGroups[0]; !group.Active || group.WatchdogTimestamp != 111 {
		t.Fatalf("RG0 state not preserved: %+v", group)
	}
	if _, ok := m.haGroups[9]; ok {
		t.Fatal("unexpected stale RG9 retained after seeding from config")
	}
}

func TestDesiredForwardingArmedUsesSeededConfiguredDataRGs(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: make(map[int]HAGroupStatus),
		lastSnapshot: &ConfigSnapshot{
			Config: &config.Config{
				Chassis: config.ChassisConfig{
					Cluster: &config.ClusterConfig{
						RedundancyGroups: []*config.RedundancyGroup{
							{ID: 1},
							{ID: 2},
						},
					},
				},
			},
		},
	}

	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true for configured standby data RGs")
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

func TestBuildTunnelEndpointSnapshotsBuildsUnitEndpoint(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0,
				},
			},
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:559:8585:80::8",
				Destination: "2602:ffd3:0:2::7",
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{
			Name:            "gr-0/0/0.0",
			Zone:            "sfmix",
			LinuxName:       "gr-0-0-0",
			Ifindex:         362,
			RedundancyGroup: 1,
			MTU:             1476,
		},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if endpoints[0].ID != 1 {
		t.Fatalf("endpoint id = %d, want 1", endpoints[0].ID)
	}
	if endpoints[0].Interface != "gr-0/0/0.0" {
		t.Fatalf("endpoint interface = %q, want gr-0/0/0.0", endpoints[0].Interface)
	}
	if endpoints[0].TransportTable != "inet6.0" {
		t.Fatalf("endpoint transport table = %q, want inet6.0", endpoints[0].TransportTable)
	}
	if endpoints[0].OuterFamily != "inet6" {
		t.Fatalf("endpoint outer family = %q, want inet6", endpoints[0].OuterFamily)
	}
}

func TestBuildTunnelEndpointSnapshotsUsesConfiguredTransportTable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0,
				},
			},
			Tunnel: &config.TunnelConfig{
				Name:            "gr-0-0-0",
				Mode:            "gre",
				Source:          "172.16.50.8",
				Destination:     "198.51.100.7",
				RoutingInstance: "transport",
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{
			Name:      "gr-0/0/0.0",
			LinuxName: "gr-0-0-0",
			Ifindex:   362,
		},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if endpoints[0].TransportTable != "transport.inet.0" {
		t.Fatalf("endpoint transport table = %q, want transport.inet.0", endpoints[0].TransportTable)
	}
	if endpoints[0].OuterFamily != "inet" {
		t.Fatalf("endpoint outer family = %q, want inet", endpoints[0].OuterFamily)
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
	// Firewall filters (inet/inet6) and single-rate policers are now supported.
	// Only three-color policers remain unsupported.
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{"f1": {Name: "f1"}}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; firewall filters and flow monitoring are now supported. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesGatesThreeColorPolicers(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.ThreeColorPolicers = map[string]*config.ThreeColorPolicerConfig{
		"tcp1": {Name: "tcp1", CIR: 1000000, CBS: 50000},
	}

	caps := deriveUserspaceCapabilities(cfg)
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true, want false for three-color policers")
	}
	found := false
	for _, r := range caps.UnsupportedReasons {
		if r == "three-color policers are not implemented in the userspace dataplane" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected three-color policer unsupported reason, got: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsFirewallFilters(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-RE": {Name: "protect-RE"},
	}
	cfg.Firewall.Policers = map[string]*config.PolicerConfig{
		"1mbps": {Name: "1mbps", BandwidthLimit: 125000, BurstSizeLimit: 50000},
	}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsIPsecConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
		"gw1": {Name: "gw1"},
	}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn1": {Name: "vpn1", Gateway: "gw1"},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; IPsec should not gate userspace forwarding. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsTunnelInterfaces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {
			Name:   "st0",
			Tunnel: &config.TunnelConfig{},
			Units: map[int]*config.InterfaceUnit{
				0: {Tunnel: &config.TunnelConfig{}},
			},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; tunnel interfaces should not gate userspace forwarding. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsFlowMonitoring(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, want true (flow monitoring now supported); reasons: %+v", caps.UnsupportedReasons)
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

func TestDesiredForwardingArmedKeepsClusterStandbyArmed(t *testing.T) {
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
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true on standby HA node with data RGs")
	}
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: true}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true with active data RG")
	}
}

func TestDesiredForwardingArmedRequiresDataRGOrActiveLocalOnlyGroup(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
		},
	}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true with active local-only RG")
	}
	m.haGroups[0] = HAGroupStatus{RGID: 0, Active: false}
	if m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = true, want false with no data RG and no active local-only RG")
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
			PID:             1234,
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
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

func TestUserspaceSupportsGlobalPolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "global-allow",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
		Action: config.PolicyPermit,
	}}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true with simple global policies")
	}
}

func TestBuildPolicySnapshotsIncludesGlobalPolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "zone-allow",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "global-deny-all",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
		Action: config.PolicyDeny,
	}}
	snap := buildPolicySnapshots(cfg)
	if len(snap) != 2 {
		t.Fatalf("len(snap) = %d, want 2", len(snap))
	}
	if snap[0].FromZone != "trust" || snap[0].ToZone != "untrust" {
		t.Fatalf("snap[0] = %+v, want zone-specific policy", snap[0])
	}
	if snap[1].FromZone != "junos-global" || snap[1].ToZone != "junos-global" {
		t.Fatalf("snap[1] = %+v, want global policy", snap[1])
	}
	if snap[1].Name != "global-deny-all" {
		t.Fatalf("snap[1].Name = %q, want global-deny-all", snap[1].Name)
	}
}

func TestUserspaceSupportsScreenProfilesBasic(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true, SynFin: true},
			ICMP: config.ICMPScreen{FloodThreshold: 100},
		},
	}
	if !userspaceSupportsScreenProfiles(cfg) {
		t.Fatal("basic screen profile should be supported")
	}
}

func TestUserspaceSupportsScreenProfilesRejectsSynCookie(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.SynFloodProtectionMode = "syn-cookie"
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true},
		},
	}
	if userspaceSupportsScreenProfiles(cfg) {
		t.Fatal("syn-cookie mode should not be supported")
	}
}

func TestUserspaceSupportsScreenProfilesAllowsPortScan(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"scan": {
			Name: "scan",
			TCP:  config.TCPScreen{PortScanThreshold: 100},
		},
	}
	if !userspaceSupportsScreenProfiles(cfg) {
		t.Fatal("port scan threshold should now be supported in userspace dataplane")
	}
}

func TestUserspaceSupportsScreenProfilesAllowsSessionLimit(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"limit": {
			Name:         "limit",
			LimitSession: config.LimitSessionScreen{SourceIPBased: 100},
		},
	}
	if !userspaceSupportsScreenProfiles(cfg) {
		t.Fatal("session limiting should now be supported in userspace dataplane")
	}
}

func TestDeriveUserspaceCapabilitiesAllowsBasicScreenProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "basic"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true, SynFin: true},
			ICMP: config.ICMPScreen{FloodThreshold: 100},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesRejectsSynCookieScreen(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.SynFloodProtectionMode = "syn-cookie"
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "flood"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"flood": {
			Name: "flood",
			TCP:  config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 100}},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true, want false (syn-cookie)")
	}
}

func TestBuildScreenSnapshotsMatchesZoneToProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", ScreenProfile: "basic"},
		"untrust": {Name: "untrust"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true, SynFin: true},
			ICMP: config.ICMPScreen{FloodThreshold: 50},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].Zone != "trust" {
		t.Fatalf("Zone = %q, want trust", snaps[0].Zone)
	}
	if !snaps[0].Land || !snaps[0].SynFin {
		t.Fatalf("unexpected screen flags: %+v", snaps[0])
	}
	if snaps[0].ICMPFloodThreshold != 50 {
		t.Fatalf("ICMPFloodThreshold = %d, want 50", snaps[0].ICMPFloodThreshold)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsSessionTimeouts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 120,
	}
	cfg.Security.Flow.UDPSessionTimeout = 30
	cfg.Security.Flow.ICMPSessionTimeout = 10
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestBuildFlowSnapshotIncludesTimeouts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.AllowDNSReply = true
	cfg.Security.Flow.AllowEmbeddedICMP = true
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 120,
	}
	cfg.Security.Flow.UDPSessionTimeout = 30
	cfg.Security.Flow.ICMPSessionTimeout = 10
	snap := buildFlowSnapshot(cfg)
	if !snap.AllowDNSReply {
		t.Fatal("AllowDNSReply = false")
	}
	if !snap.AllowEmbeddedICMP {
		t.Fatal("AllowEmbeddedICMP = false")
	}
	if snap.TCPSessionTimeout != 120 {
		t.Fatalf("TCPSessionTimeout = %d, want 120", snap.TCPSessionTimeout)
	}
	if snap.UDPSessionTimeout != 30 {
		t.Fatalf("UDPSessionTimeout = %d, want 30", snap.UDPSessionTimeout)
	}
	if snap.ICMPSessionTimeout != 10 {
		t.Fatalf("ICMPSessionTimeout = %d, want 10", snap.ICMPSessionTimeout)
	}
}

func TestBuildFlowSnapshotNilTCPSession(t *testing.T) {
	cfg := &config.Config{}
	snap := buildFlowSnapshot(cfg)
	if snap.TCPSessionTimeout != 0 {
		t.Fatalf("TCPSessionTimeout = %d, want 0", snap.TCPSessionTimeout)
	}
}

func TestBuildInterfaceSnapshotSetsTunnelFlag(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {
			Name:   "st0",
			Tunnel: &config.TunnelConfig{},
			Units: map[int]*config.InterfaceUnit{
				0: {},
			},
		},
		"ge-0-0-0": {
			Name: "ge-0-0-0",
		},
	}
	snaps := buildInterfaceSnapshots(cfg)
	tunnelFound := false
	nonTunnelFound := false
	for _, snap := range snaps {
		if snap.Name == "st0" || snap.Name == "st0.0" {
			if !snap.Tunnel {
				t.Errorf("interface %s: Tunnel = false, want true", snap.Name)
			}
			tunnelFound = true
		}
		if snap.Name == "ge-0-0-0" {
			if snap.Tunnel {
				t.Errorf("interface %s: Tunnel = true, want false", snap.Name)
			}
			nonTunnelFound = true
		}
	}
	if !tunnelFound {
		t.Error("tunnel interface st0/st0.0 not found in snapshots")
	}
	if !nonTunnelFound {
		t.Error("non-tunnel interface ge-0-0-0 not found in snapshots")
	}
}

func TestBuildScreenSnapshotsIncludesAdvancedFields(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "advanced"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"advanced": {
			Name: "advanced",
			TCP:  config.TCPScreen{PortScanThreshold: 100},
			IP:   config.IPScreen{IPSweepThreshold: 50},
			LimitSession: config.LimitSessionScreen{
				SourceIPBased:      200,
				DestinationIPBased: 300,
			},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].PortScanThreshold != 100 {
		t.Fatalf("PortScanThreshold = %d, want 100", snaps[0].PortScanThreshold)
	}
	if snaps[0].IPSweepThreshold != 50 {
		t.Fatalf("IPSweepThreshold = %d, want 50", snaps[0].IPSweepThreshold)
	}
	if snaps[0].SessionLimitSrc != 200 {
		t.Fatalf("SessionLimitSrc = %d, want 200", snaps[0].SessionLimitSrc)
	}
	if snaps[0].SessionLimitDst != 300 {
		t.Fatalf("SessionLimitDst = %d, want 300", snaps[0].SessionLimitDst)
	}
}

func TestBuildFlowExportSnapshot(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9: &config.NetFlowV9Config{
			Templates: map[string]*config.NetFlowV9Template{
				"tmpl1": {
					Name:              "tmpl1",
					FlowActiveTimeout: 120,
				},
			},
		},
	}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"inst1": {
				Name:      "inst1",
				InputRate: 100,
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: "10.0.1.1", Port: 9995, Version9Template: "tmpl1"},
					},
				},
			},
		},
	}

	snap := buildFlowExportSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil flow export snapshot")
	}
	if snap.CollectorAddress != "10.0.1.1" {
		t.Fatalf("CollectorAddress = %q, want 10.0.1.1", snap.CollectorAddress)
	}
	if snap.CollectorPort != 9995 {
		t.Fatalf("CollectorPort = %d, want 9995", snap.CollectorPort)
	}
	if snap.SamplingRate != 100 {
		t.Fatalf("SamplingRate = %d, want 100", snap.SamplingRate)
	}
	if snap.ActiveTimeout != 120 {
		t.Fatalf("ActiveTimeout = %d, want 120", snap.ActiveTimeout)
	}
}

func TestBuildFlowExportSnapshotNilWhenNoConfig(t *testing.T) {
	cfg := &config.Config{}
	snap := buildFlowExportSnapshot(cfg)
	if snap != nil {
		t.Fatal("expected nil flow export snapshot with no config")
	}
}

func TestBuildUserspaceIngressIfindexesIncludesFabricParent(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/1",
				Zone:    "lan",
				Ifindex: 11,
			},
			{
				Name:    "ge-0/0/2",
				Zone:    "wan",
				Ifindex: 12,
			},
		},
		Fabrics: []FabricSnapshot{
			{
				Name:            "fab0",
				ParentInterface: "ge-0/0/0",
				ParentLinuxName: "ge-0-0-0",
				ParentIfindex:   21,
				OverlayLinux:    "fab0",
				OverlayIfindex:  101,
				RXQueues:        1,
				PeerAddress:     "10.99.13.2",
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	found := false
	for _, idx := range ifindexes {
		if idx == 21 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("fabric parent ifindex 21 not in ingress ifindexes: %v", ifindexes)
	}
	if len(ifindexes) != 3 {
		t.Fatalf("expected 3 ingress ifindexes (2 data + 1 fabric), got %d: %v", len(ifindexes), ifindexes)
	}
}

func TestBuildUserspaceIngressIfindexesDeduplicatesFabricParent(t *testing.T) {
	// If the fabric parent is already in the data interface list, it should
	// not be duplicated.
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/0",
				Zone:    "lan",
				Ifindex: 21,
			},
		},
		Fabrics: []FabricSnapshot{
			{
				Name:            "fab0",
				ParentInterface: "ge-0/0/0",
				ParentLinuxName: "ge-0-0-0",
				ParentIfindex:   21,
				OverlayLinux:    "fab0",
				OverlayIfindex:  101,
				RXQueues:        1,
				PeerAddress:     "10.99.13.2",
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	count := 0
	for _, idx := range ifindexes {
		if idx == 21 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("fabric parent ifindex 21 appeared %d times in ingress ifindexes: %v", count, ifindexes)
	}
}
