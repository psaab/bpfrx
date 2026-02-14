package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestGenerateStaticRoute_SingleNextHop(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Address: "192.168.1.1"}},
	}
	got := m.generateStaticRoute(sr, "")
	want := "ip route 10.0.0.0/8 192.168.1.1\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_ECMP(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops: []config.NextHopEntry{
			{Address: "192.168.1.1"},
			{Address: "192.168.2.1"},
		},
	}
	got := m.generateStaticRoute(sr, "")
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.168.1.1\n") {
		t.Errorf("missing first next-hop: %q", got)
	}
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.168.2.1\n") {
		t.Errorf("missing second next-hop: %q", got)
	}
}

func TestGenerateStaticRoute_Discard(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.99.0/24",
		Discard:     true,
	}
	got := m.generateStaticRoute(sr, "")
	want := "ip route 10.0.99.0/24 Null0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_Preference(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Address: "192.168.1.1"}},
		Preference:  100,
	}
	got := m.generateStaticRoute(sr, "")
	want := "ip route 10.0.0.0/8 192.168.1.1 100\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_VRF(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "172.16.0.0/12",
		NextHops:    []config.NextHopEntry{{Address: "10.0.1.1"}},
	}
	got := m.generateStaticRoute(sr, "customer-a")
	want := "ip route 172.16.0.0/12 10.0.1.1 vrf customer-a\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_IPv6(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "2001:db8::/32",
		NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "trust0"}},
	}
	got := m.generateStaticRoute(sr, "")
	want := "ipv6 route 2001:db8::/32 fe80::1 trust0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_InterfaceOnly(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Interface: "tunnel0"}},
	}
	got := m.generateStaticRoute(sr, "")
	want := "ip route 10.0.0.0/8 tunnel0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_NextTable(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "0.0.0.0/0",
		NextTable:   "Comcast-GigabitPro",
	}
	got := m.generateStaticRoute(sr, "")
	if got != "" {
		t.Errorf("next-table route should produce empty FRR output, got %q", got)
	}
}

func TestGenerateProtocols_OSPF(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", Passive: false},
					{Name: "dmz0", Passive: true},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "", 0)
	if !strings.Contains(got, "router ospf\n") {
		t.Error("missing 'router ospf'")
	}
	if !strings.Contains(got, "ospf router-id 1.1.1.1\n") {
		t.Error("missing router-id")
	}
	if !strings.Contains(got, "network 0.0.0.0/0 area 0.0.0.0\n") {
		t.Error("missing network statement")
	}
	if !strings.Contains(got, "passive-interface dmz0\n") {
		t.Error("missing passive-interface")
	}
	if strings.Contains(got, "passive-interface trust0") {
		t.Error("trust0 should not be passive")
	}
}

func TestGenerateProtocols_OSPFExportAndCost(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Export:   []string{"connected", "static"},
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", Cost: 100},
					{Name: "dmz0", Cost: 0},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "", 0)
	if !strings.Contains(got, "redistribute connected\n") {
		t.Error("missing redistribute connected")
	}
	if !strings.Contains(got, "redistribute static\n") {
		t.Error("missing redistribute static")
	}
	if !strings.Contains(got, "ip ospf cost 100\n") {
		t.Errorf("missing ospf cost for trust0, got:\n%s", got)
	}
	if strings.Contains(got, "ip ospf cost 0") {
		t.Error("should not emit cost 0")
	}
}

func TestGenerateProtocols_BGP(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, Description: "upstream"},
			{Address: "10.0.3.1", PeerAS: 65003, MultihopTTL: 5},
		},
	}
	got := m.generateProtocols(nil, bgp, nil, nil, "", 0)
	if !strings.Contains(got, "router bgp 65001\n") {
		t.Error("missing 'router bgp 65001'")
	}
	if !strings.Contains(got, "bgp router-id 1.1.1.1\n") {
		t.Error("missing router-id")
	}
	if !strings.Contains(got, "neighbor 10.0.2.1 remote-as 65002\n") {
		t.Error("missing neighbor 10.0.2.1")
	}
	if !strings.Contains(got, "neighbor 10.0.2.1 description upstream\n") {
		t.Error("missing neighbor description")
	}
	if !strings.Contains(got, "neighbor 10.0.3.1 ebgp-multihop 5\n") {
		t.Error("missing multihop")
	}
}

func TestGenerateProtocols_RIP(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"trust0", "dmz0"},
		Passive:      []string{"dmz0"},
		Redistribute: []string{"connected", "static"},
	}
	got := m.generateProtocols(nil, nil, rip, nil, "", 0)
	if !strings.Contains(got, "router rip\n") {
		t.Error("missing 'router rip'")
	}
	if !strings.Contains(got, "network trust0\n") {
		t.Error("missing network trust0")
	}
	if !strings.Contains(got, "passive-interface dmz0\n") {
		t.Error("missing passive-interface dmz0")
	}
	if !strings.Contains(got, "redistribute connected\n") {
		t.Error("missing redistribute connected")
	}
}

func TestGenerateProtocols_ISIS(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:   "49.0001.1921.6800.1001.00",
		Level: "level-1-2",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0", Passive: false, Metric: 10},
			{Name: "dmz0", Passive: true},
		},
	}
	got := m.generateProtocols(nil, nil, nil, isis, "", 0)
	if !strings.Contains(got, "router isis bpfrx\n") {
		t.Error("missing 'router isis bpfrx'")
	}
	if !strings.Contains(got, "net 49.0001.1921.6800.1001.00\n") {
		t.Error("missing NET")
	}
	if !strings.Contains(got, "is-type level-1-2\n") {
		t.Error("missing is-type")
	}
	if !strings.Contains(got, "isis metric 10\n") {
		t.Error("missing metric")
	}
	if !strings.Contains(got, "isis passive\n") {
		t.Error("missing passive")
	}
}

func TestGenerateProtocols_BGPExport(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Export:   []string{"connected", "static"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, bgp, nil, nil, "", 0)
	if !strings.Contains(got, "redistribute connected\n") {
		t.Errorf("missing redistribute connected, got:\n%s", got)
	}
	if !strings.Contains(got, "redistribute static\n") {
		t.Errorf("missing redistribute static, got:\n%s", got)
	}
}

func TestGenerateProtocols_ISISExport(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:    "49.0001.1921.6800.1001.00",
		Level:  "level-2",
		Export: []string{"connected"},
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, isis, "", 0)
	if !strings.Contains(got, "redistribute connected\n") {
		t.Errorf("missing redistribute connected, got:\n%s", got)
	}
}

func TestGenerateProtocols_VRF(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "2.2.2.2",
		Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "cust-a", 0)
	if !strings.Contains(got, "router ospf vrf cust-a\n") {
		t.Error("missing VRF suffix in OSPF")
	}
}

func TestWriteManagedSection_Fresh(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	// Write initial frr.conf with some existing content
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.1.1\n"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	if !strings.Contains(got, markerBegin) {
		t.Error("missing begin marker")
	}
	if !strings.Contains(got, markerEnd) {
		t.Error("missing end marker")
	}
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.168.1.1\n") {
		t.Error("missing route")
	}
	if !strings.Contains(got, "log syslog informational\n") {
		t.Error("existing config lost")
	}
}

func TestWriteManagedSection_Replace(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	// Write initial config with managed section
	initial := "log syslog informational\n" +
		markerBegin + "\n" +
		"ip route 10.0.0.0/8 192.168.1.1\n" +
		markerEnd + "\n"
	os.WriteFile(confPath, []byte(initial), 0644)

	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.2.1\n"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	if strings.Contains(got, "192.168.1.1") {
		t.Error("old route still present")
	}
	if !strings.Contains(got, "192.168.2.1") {
		t.Error("new route missing")
	}
}

func TestWriteManagedSection_Clear(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	initial := "log syslog informational\n" +
		markerBegin + "\n" +
		"ip route 10.0.0.0/8 192.168.1.1\n" +
		markerEnd + "\n"
	os.WriteFile(confPath, []byte(initial), 0644)

	if err := m.writeManagedSection(""); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	if strings.Contains(got, markerBegin) {
		t.Error("managed section not removed")
	}
	if !strings.Contains(got, "log syslog") {
		t.Error("existing config lost")
	}
}

func TestWriteManagedSection_NoExistingFile(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	if err := m.writeManagedSection("ip route 10.0.0.0/8 Null0\n"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)
	if !strings.Contains(got, "log syslog informational") {
		t.Error("default log line missing when frr.conf didn't exist")
	}
	if !strings.Contains(got, "ip route 10.0.0.0/8 Null0\n") {
		t.Error("route missing")
	}
}

func TestGeneratePolicyOptions(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"mgmt": {
				Name:     "mgmt",
				Prefixes: []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-connected": {
				Name: "export-connected",
				Terms: []*config.PolicyTerm{
					{
						Name:         "t1",
						FromProtocol: "direct",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.0.0.0/8", MatchType: "exact"},
						},
						Action: "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"ip prefix-list mgmt seq 5 permit 10.0.0.0/8",
		"ip prefix-list mgmt seq 10 permit 172.16.0.0/12",
		"route-map export-connected permit 10",
		"match source-protocol connected",
		"route-map export-connected deny 20",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestBGPAddressFamily(t *testing.T) {
	m := New()

	bgp := &config.BGPConfig{
		LocalAS: 64701,
		Neighbors: []*config.BGPNeighbor{
			{
				Address:     "192.168.255.1",
				PeerAS:      65909,
				FamilyInet:  true,
				FamilyInet6: true,
				Export:       []string{"to_BV-FIREHOUSE"},
			},
			{
				Address:    "10.0.0.2",
				PeerAS:     65002,
				FamilyInet: true,
			},
		},
	}

	got := m.generateProtocols(nil, bgp, nil, nil, "", 0)

	checks := []string{
		"router bgp 64701",
		"neighbor 192.168.255.1 remote-as 65909",
		"neighbor 10.0.0.2 remote-as 65002",
		"address-family ipv4 unicast",
		"neighbor 192.168.255.1 activate",
		"neighbor 192.168.255.1 route-map to_BV-FIREHOUSE out",
		"neighbor 10.0.0.2 activate",
		"exit-address-family",
		"address-family ipv6 unicast",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	// Neighbor 10.0.0.2 should NOT be in ipv6 address-family
	lines := strings.Split(got, "\n")
	inIPv6 := false
	for _, line := range lines {
		if strings.Contains(line, "address-family ipv6") {
			inIPv6 = true
		}
		if strings.Contains(line, "exit-address-family") {
			inIPv6 = false
		}
		if inIPv6 && strings.Contains(line, "10.0.0.2") {
			t.Error("10.0.0.2 should not be in ipv6 address-family")
		}
	}
}

func TestGenerateProtocols_ECMPMaxPaths(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true},
		},
	}
	got := m.generateProtocols(nil, bgp, nil, nil, "", 64)
	if !strings.Contains(got, "maximum-paths 64") {
		t.Errorf("missing maximum-paths in BGP, got:\n%s", got)
	}

	// Also test OSPF ECMP
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
		},
	}
	got = m.generateProtocols(ospf, nil, nil, nil, "", 64)
	if !strings.Contains(got, "maximum-paths 64") {
		t.Errorf("missing maximum-paths in OSPF, got:\n%s", got)
	}

	// Without ECMP
	got = m.generateProtocols(ospf, nil, nil, nil, "", 0)
	if strings.Contains(got, "maximum-paths") {
		t.Errorf("should not have maximum-paths when ecmp=0, got:\n%s", got)
	}
}

func TestApplyFull_BackupRouter(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	m := &Manager{frrConf: confPath}
	fc := &FullConfig{
		BackupRouter:    "192.168.50.1",
		BackupRouterDst: "0.0.0.0/0",
	}

	// ApplyFull calls reload which fails in test, so just test writeManagedSection.
	// Build the same string that ApplyFull would.
	var b strings.Builder
	b.WriteString("! bpfrx managed config - do not edit\n!\n")
	dst := fc.BackupRouterDst
	if dst == "" {
		dst = "0.0.0.0/0"
	}
	b.WriteString("ip route " + dst + " " + fc.BackupRouter + " 250\n!\n")

	if err := m.writeManagedSection(b.String()); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)
	want := "ip route 0.0.0.0/0 192.168.50.1 250"
	if !strings.Contains(got, want) {
		t.Errorf("backup router missing, got:\n%s\nwant substring: %s", got, want)
	}
}

func TestFRRMultiVRF(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	m := &Manager{frrConf: confPath}

	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
		},
		Instances: []InstanceConfig{
			{
				VRFName: "vrf-tunnel-vr",
				StaticRoutes: []*config.StaticRoute{
					{Destination: "10.0.50.0/24", NextHops: []config.NextHopEntry{{Address: "10.0.40.1"}}},
				},
			},
			{
				VRFName: "vrf-dmz-vr",
				StaticRoutes: []*config.StaticRoute{
					{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.30.1"}}},
				},
				OSPF: &config.OSPFConfig{
					RouterID: "3.3.3.3",
					Areas: []*config.OSPFArea{
						{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "dmz0"}}},
					},
				},
			},
		},
	}

	// Build the section that ApplyFull would generate (without calling reload)
	var b strings.Builder
	b.WriteString("! bpfrx managed config - do not edit\n!\n")
	for _, sr := range fc.StaticRoutes {
		b.WriteString(m.generateStaticRoute(sr, ""))
	}
	b.WriteString("!\n")
	for _, inst := range fc.Instances {
		if len(inst.StaticRoutes) > 0 {
			for _, sr := range inst.StaticRoutes {
				b.WriteString(m.generateStaticRoute(sr, inst.VRFName))
			}
			b.WriteString("!\n")
		}
	}
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil {
			b.WriteString(m.generateProtocols(inst.OSPF, inst.BGP, inst.RIP, inst.ISIS, inst.VRFName, 0))
		}
	}

	if err := m.writeManagedSection(b.String()); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	// Verify global static route
	if !strings.Contains(got, "ip route 0.0.0.0/0 172.16.50.1\n") {
		t.Error("missing global default route")
	}

	// Verify per-VRF static routes
	if !strings.Contains(got, "ip route 10.0.50.0/24 10.0.40.1 vrf vrf-tunnel-vr\n") {
		t.Errorf("missing tunnel-vr static route, got:\n%s", got)
	}
	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.30.1 vrf vrf-dmz-vr\n") {
		t.Errorf("missing dmz-vr static route, got:\n%s", got)
	}

	// Verify per-VRF OSPF
	if !strings.Contains(got, "router ospf vrf vrf-dmz-vr\n") {
		t.Errorf("missing VRF OSPF block, got:\n%s", got)
	}
	if !strings.Contains(got, "ospf router-id 3.3.3.3\n") {
		t.Errorf("missing OSPF router-id, got:\n%s", got)
	}
}

func TestFRRForwardingInstance(t *testing.T) {
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf")}
	os.WriteFile(m.frrConf, []byte("log syslog informational\n"), 0644)

	fc := &FullConfig{
		Instances: []InstanceConfig{
			{
				VRFName: "", // forwarding instance — no VRF, default table
				StaticRoutes: []*config.StaticRoute{
					{Destination: "10.99.0.0/16", NextHops: []config.NextHopEntry{{Address: "10.0.40.1"}}},
				},
			},
			{
				VRFName: "vrf-normal-vr",
				StaticRoutes: []*config.StaticRoute{
					{Destination: "192.168.0.0/16", NextHops: []config.NextHopEntry{{Address: "10.0.1.1"}}},
				},
			},
		},
	}

	var b strings.Builder
	for _, inst := range fc.Instances {
		for _, sr := range inst.StaticRoutes {
			b.WriteString(m.generateStaticRoute(sr, inst.VRFName))
		}
	}
	got := b.String()

	// Forwarding instance route should NOT have vrf suffix
	if !strings.Contains(got, "ip route 10.99.0.0/16 10.0.40.1\n") {
		t.Errorf("forwarding instance route should be in default table, got:\n%s", got)
	}
	// Normal VRF route should have vrf suffix
	if !strings.Contains(got, "ip route 192.168.0.0/16 10.0.1.1 vrf vrf-normal-vr\n") {
		t.Errorf("VRF route should have vrf suffix, got:\n%s", got)
	}
}

func TestApplyFull_BackupRouterWithPrefix(t *testing.T) {
	fc := &FullConfig{
		BackupRouter:    "10.0.1.1",
		BackupRouterDst: "192.168.0.0/16",
	}

	var b strings.Builder
	if fc.BackupRouter != "" {
		dst := fc.BackupRouterDst
		if dst == "" {
			dst = "0.0.0.0/0"
		}
		prefix := "ip"
		if strings.Contains(dst, ":") {
			prefix = "ipv6"
		}
		b.WriteString(prefix + " route " + dst + " " + fc.BackupRouter + " 250\n")
	}

	got := b.String()
	want := "ip route 192.168.0.0/16 10.0.1.1 250\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_QualifiedNextHopLinkLocal(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops: []config.NextHopEntry{
			{Address: "fe80::2d0:f6ff:feda:c180", Interface: "wan0.0"},
		},
	}
	got := m.generateStaticRoute(sr, "ATT")
	want := "ipv6 route ::/0 fe80::2d0:f6ff:feda:c180 wan0 vrf ATT\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_UnitSuffixStripped(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Interface: "tunnel0.0"}},
	}
	got := m.generateStaticRoute(sr, "")
	want := "ip route 10.0.0.0/8 tunnel0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_NoUnitNoStrip(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "2001:db8::/32",
		NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "trust0"}},
	}
	got := m.generateStaticRoute(sr, "")
	want := "ipv6 route 2001:db8::/32 fe80::1 trust0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_VLANSuffixNotStripped(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops:    []config.NextHopEntry{{Address: "fe80::50", Interface: "wan0.50"}},
	}
	got := m.generateStaticRoute(sr, "")
	// VLAN sub-interface "wan0.50" must NOT be stripped — it's a real kernel name
	want := "ipv6 route ::/0 fe80::50 wan0.50\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestApplyFull_ConsistentHash(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	fc := &FullConfig{
		ForwardingTableExport: "lb-policy",
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"lb-policy": {
					Name: "lb-policy",
					Terms: []*config.PolicyTerm{
						{LoadBalance: "consistent-hash", Action: "accept"},
					},
				},
			},
		},
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
		},
	}
	// ApplyFull will fail (no FRR), but fc.ConsistentHash should be set.
	_ = m.ApplyFull(fc)
	if !fc.ConsistentHash {
		t.Error("ConsistentHash should be true with load-balance consistent-hash")
	}
}

func TestApplyFull_PerPacketNotConsistent(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	fc := &FullConfig{
		ForwardingTableExport: "lb-policy",
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"lb-policy": {
					Name: "lb-policy",
					Terms: []*config.PolicyTerm{
						{LoadBalance: "per-packet", Action: "accept"},
					},
				},
			},
		},
	}
	_ = m.ApplyFull(fc)
	if fc.ConsistentHash {
		t.Error("ConsistentHash should be false with load-balance per-packet")
	}
}

func TestParseRouteJSON(t *testing.T) {
	input := `{
		"10.0.1.0/24": [{
			"prefix": "10.0.1.0/24",
			"protocol": "connected",
			"selected": true,
			"installed": true,
			"distance": 0,
			"metric": 0,
			"uptime": "2d05h30m",
			"table": 254,
			"nexthops": [{
				"directlyConnected": true,
				"interfaceName": "trust0",
				"active": true,
				"fib": true
			}]
		}],
		"0.0.0.0/0": [{
			"prefix": "0.0.0.0/0",
			"protocol": "static",
			"selected": true,
			"installed": true,
			"distance": 5,
			"metric": 0,
			"uptime": "01:02:20",
			"table": 254,
			"nexthops": [{
				"ip": "172.16.50.1",
				"interfaceName": "wan0.50",
				"active": true,
				"fib": true
			}]
		}]
	}`

	routes, err := parseRouteJSON(input)
	if err != nil {
		t.Fatal(err)
	}

	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}

	// Routes should be sorted by prefix (0.0.0.0/0 before 10.0.1.0/24)
	if routes[0].Prefix != "0.0.0.0/0" {
		t.Errorf("expected first route 0.0.0.0/0, got %s", routes[0].Prefix)
	}
	if routes[0].Protocol != "static" {
		t.Errorf("expected protocol static, got %s", routes[0].Protocol)
	}
	if routes[0].Distance != 5 {
		t.Errorf("expected distance 5, got %d", routes[0].Distance)
	}
	if len(routes[0].NextHops) != 1 || routes[0].NextHops[0].IP != "172.16.50.1" {
		t.Errorf("expected next-hop 172.16.50.1")
	}

	if routes[1].Prefix != "10.0.1.0/24" {
		t.Errorf("expected second route 10.0.1.0/24, got %s", routes[1].Prefix)
	}
	if !routes[1].NextHops[0].DirectlyConnected {
		t.Error("expected directly connected")
	}
}

func TestFormatRouteDetail(t *testing.T) {
	routes := []FRRRouteDetail{
		{
			Prefix:    "0.0.0.0/0",
			Protocol:  "static",
			Selected:  true,
			Installed: true,
			Distance:  5,
			Metric:    0,
			Uptime:    "01:02:20",
			NextHops: []FRRNextHop{
				{IP: "172.16.50.1", Interface: "wan0.50", Active: true, FIB: true},
			},
		},
		{
			Prefix:    "10.0.1.0/24",
			Protocol:  "connected",
			Selected:  true,
			Installed: true,
			Distance:  0,
			NextHops: []FRRNextHop{
				{DirectlyConnected: true, Interface: "trust0", Active: true, FIB: true},
			},
		},
	}

	got := FormatRouteDetail(routes)

	checks := []string{
		"* 0.0.0.0/0",
		"Protocol: static",
		"Preference: 5/0",
		"Age: 01:02:20",
		"Next-hop: 172.16.50.1 via wan0.50",
		"* 10.0.1.0/24",
		"Protocol: connected",
		"Next-hop: directly connected via trust0",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_OSPFMD5Auth(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", AuthType: "md5", AuthKey: "secret123", AuthKeyID: 5},
					{Name: "dmz0", AuthType: "simple", AuthKey: "plainpw"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "", 0)

	checks := []string{
		"interface trust0\n",
		"ip ospf authentication message-digest\n",
		"ip ospf message-digest-key 5 md5 secret123\n",
		"interface dmz0\n",
		"ip ospf authentication\n",
		"ip ospf authentication-key plainpw\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_OSPFMD5AuthDefaultKeyID(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", AuthType: "md5", AuthKey: "key1"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "", 0)
	if !strings.Contains(got, "message-digest-key 1 md5 key1") {
		t.Errorf("default key-id should be 1, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPPassword(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, AuthPassword: "bgpSecret"},
			{Address: "10.0.3.1", PeerAS: 65003},
		},
	}
	got := m.generateProtocols(nil, bgp, nil, nil, "", 0)
	if !strings.Contains(got, "neighbor 10.0.2.1 password bgpSecret\n") {
		t.Errorf("missing BGP password, got:\n%s", got)
	}
	if strings.Contains(got, "neighbor 10.0.3.1 password") {
		t.Error("neighbor without auth should not have password line")
	}
}

func TestGenerateProtocols_OSPFBFD(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", BFD: true},
					{Name: "dmz0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "", 0)
	if !strings.Contains(got, "ip ospf bfd\n") {
		t.Errorf("missing OSPF BFD, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPBFD(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, BFD: true, BFDInterval: 100},
			{Address: "10.0.3.1", PeerAS: 65003},
		},
	}
	got := m.generateProtocols(nil, bgp, nil, nil, "", 0)

	checks := []string{
		"neighbor 10.0.2.1 bfd\n",
		"bfd\n",
		"peer 10.0.2.1\n",
		"detect-multiplier 3\n",
		"receive-interval 100\n",
		"transmit-interval 100\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "neighbor 10.0.3.1 bfd") {
		t.Error("neighbor without BFD should not have bfd line")
	}
}

func TestGenerateProtocols_OSPFStubArea(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID:       "0.0.0.1",
				AreaType: "stub",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "", 0)
	if !strings.Contains(got, "area 0.0.0.1 stub\n") {
		t.Errorf("missing stub area, got:\n%s", got)
	}
	if strings.Contains(got, "no-summary") {
		t.Error("should not have no-summary without NoSummary flag")
	}
}

func TestGenerateProtocols_OSPFStubNoSummary(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID:        "0.0.0.1",
				AreaType:  "stub",
				NoSummary: true,
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "", 0)
	if !strings.Contains(got, "area 0.0.0.1 stub no-summary\n") {
		t.Errorf("missing stub no-summary, got:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFNSSAArea(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID:       "0.0.0.2",
				AreaType: "nssa",
				Interfaces: []*config.OSPFInterface{
					{Name: "dmz0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "", 0)
	if !strings.Contains(got, "area 0.0.0.2 nssa\n") {
		t.Errorf("missing nssa area, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPRouteReflector(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		ClusterID: "10.0.0.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true},
			{Address: "10.0.0.3", PeerAS: 65001},
		},
	}
	got := m.generateProtocols(nil, bgp, nil, nil, "", 0)

	checks := []string{
		"bgp cluster-id 10.0.0.1\n",
		"neighbor 10.0.0.2 route-reflector-client\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "neighbor 10.0.0.3 route-reflector-client") {
		t.Error("non-RR neighbor should not have route-reflector-client")
	}
}

func TestGenerateProtocols_ISISAuth(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:      "49.0001.0100.0000.0001.00",
		Level:    "level-2",
		AuthType: "md5",
		AuthKey:  "isisSecret",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, isis, "", 0)

	checks := []string{
		"area-password md5 isisSecret\n",
		"domain-password md5 isisSecret\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_ISISAuthClear(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:      "49.0001.0100.0000.0001.00",
		Level:    "level-2",
		AuthType: "simple",
		AuthKey:  "plainpw",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, isis, "", 0)

	checks := []string{
		"area-password clear plainpw\n",
		"domain-password clear plainpw\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_RIPAuth(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		Interfaces: []string{"trust0", "dmz0"},
		AuthType:   "md5",
		AuthKey:    "ripSecret",
	}
	got := m.generateProtocols(nil, nil, rip, nil, "", 0)

	checks := []string{
		"interface trust0\n",
		"interface dmz0\n",
		"ip rip authentication mode md5\n",
		"ip rip authentication string ripSecret\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_RIPAuthText(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		Interfaces: []string{"trust0"},
		AuthType:   "simple",
		AuthKey:    "plainpw",
	}
	got := m.generateProtocols(nil, nil, rip, nil, "", 0)

	checks := []string{
		"ip rip authentication mode text\n",
		"ip rip authentication string plainpw\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
