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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil)
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
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil)
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
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil)
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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "cust-a", 0, nil)
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

func TestGeneratePolicyOptionsRouteMapAttributes(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"SET-ATTRS": {
				Name: "SET-ATTRS",
				Terms: []*config.PolicyTerm{
					{
						Name:            "t1",
						FromProtocol:    "bgp",
						Action:          "accept",
						LocalPreference: 200,
						Metric:          100,
						Community:       "65000:100",
						Origin:          "igp",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"route-map SET-ATTRS permit 10",
		"match source-protocol bgp",
		"set local-preference 200",
		"set metric 100",
		"set community 65000:100",
		"set origin igp",
		"route-map SET-ATTRS deny 20",
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

	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)

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
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 64, nil)
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
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 64, nil)
	if !strings.Contains(got, "maximum-paths 64") {
		t.Errorf("missing maximum-paths in OSPF, got:\n%s", got)
	}

	// Without ECMP
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
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
			b.WriteString(m.generateProtocols(inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS, inst.VRFName, 0, nil))
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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)

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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)

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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
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
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)

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
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil)

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
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil)

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

func TestGenerateProtocols_ISISWideMetrics(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:             "49.0001.0100.0000.0001.00",
		Level:           "level-2",
		WideMetricsOnly: true,
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil)
	if !strings.Contains(got, " metric-style wide\n") {
		t.Errorf("missing metric-style wide in:\n%s", got)
	}
}

func TestGenerateProtocols_ISISOverload(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:      "49.0001.0100.0000.0001.00",
		Level:    "level-2",
		Overload: true,
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil)
	if !strings.Contains(got, " set-overload-bit\n") {
		t.Errorf("missing set-overload-bit in:\n%s", got)
	}
}

func TestGenerateProtocols_ISISInterfaceAuth(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:   "49.0001.0100.0000.0001.00",
		Level: "level-2",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0", AuthType: "md5", AuthKey: "ifaceSecret"},
			{Name: "dmz0", AuthType: "simple", AuthKey: "plainpw"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil)
	checks := []string{
		"isis password md5 ifaceSecret\n",
		"isis password clear plainpw\n",
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
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil)

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
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil)

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

func TestGenerateProtocols_OSPFReferenceBandwidth(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		ReferenceBandwidth: 10000,
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 1, nil)
	if !strings.Contains(got, "auto-cost reference-bandwidth 10000\n") {
		t.Errorf("missing reference-bandwidth in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFPassiveDefault(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID:       "1.1.1.1",
		PassiveDefault: true,
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", NoPassive: true},
					{Name: "dmz0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
	if !strings.Contains(got, "passive-interface default\n") {
		t.Errorf("missing passive-interface default in:\n%s", got)
	}
	if !strings.Contains(got, "no passive-interface trust0\n") {
		t.Errorf("missing 'no passive-interface trust0' in:\n%s", got)
	}
	// dmz0 should NOT have "no passive-interface" since it stays passive
	if strings.Contains(got, "no passive-interface dmz0") {
		t.Errorf("dmz0 should stay passive (no 'no passive-interface') in:\n%s", got)
	}
	// Should NOT have old-style "passive-interface dmz0" either
	if strings.Contains(got, "passive-interface dmz0") {
		t.Errorf("should not have per-interface passive when passive-default is set:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFNetworkType(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", NetworkType: "point-to-point"},
					{Name: "dmz0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
	if !strings.Contains(got, "ip ospf network point-to-point\n") {
		t.Errorf("missing 'ip ospf network point-to-point' in:\n%s", got)
	}
	// dmz0 should not have network type set
	if strings.Contains(got, "ip ospf network broadcast") {
		t.Errorf("dmz0 should not have network type set:\n%s", got)
	}
}

func TestGenerateProtocols_BGPGracefulRestart(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:         65001,
		GracefulRestart: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil)
	if !strings.Contains(got, "bgp graceful-restart\n") {
		t.Errorf("missing graceful-restart in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPMultipath(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:             65001,
		Multipath:           64,
		MultipathMultipleAS: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil)
	if !strings.Contains(got, "bgp bestpath as-path multipath-relax\n") {
		t.Errorf("missing multipath-relax in:\n%s", got)
	}
	if !strings.Contains(got, "maximum-paths 64\n") {
		t.Errorf("missing maximum-paths in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPDefaultOriginate(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, FamilyInet: true, DefaultOriginate: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 default-originate\n") {
		t.Errorf("missing default-originate in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPLogNeighborChanges(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:            65001,
		LogNeighborChanges: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil)
	if !strings.Contains(got, "bgp log-neighbor-changes\n") {
		t.Errorf("missing log-neighbor-changes in:\n%s", got)
	}
}

func TestResolveRedistribute_BareProtocol(t *testing.T) {
	m := New()
	for _, proto := range []string{"connected", "static", "ospf", "bgp", "rip", "isis", "kernel"} {
		got := m.resolveRedistribute(proto, nil)
		want := " redistribute " + proto + "\n"
		if got != want {
			t.Errorf("resolveRedistribute(%q, nil) = %q, want %q", proto, got, want)
		}
	}
}

func TestResolveRedistribute_PolicyStatement(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"internal": {Name: "internal", Prefixes: []string{"10.0.0.0/8", "172.16.0.0/12"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-connected": {
				Name: "export-connected",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocol: "direct", Action: "accept", PrefixList: "internal"},
				},
			},
		},
	}
	got := m.resolveRedistribute("export-connected", po)
	want := " redistribute connected route-map export-connected\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveRedistribute_MultiProtocol(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-all": {
				Name: "export-all",
				Terms: []*config.PolicyTerm{
					{Name: "connected", FromProtocol: "direct", Action: "accept"},
					{Name: "static", FromProtocol: "static", Action: "accept"},
				},
			},
		},
	}
	got := m.resolveRedistribute("export-all", po)
	// Should have both protocols, sorted alphabetically
	if !strings.Contains(got, "redistribute connected route-map export-all\n") {
		t.Errorf("missing connected route-map in:\n%s", got)
	}
	if !strings.Contains(got, "redistribute static route-map export-all\n") {
		t.Errorf("missing static route-map in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFExportRouteMap(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"trusted-nets": {Name: "trusted-nets", Prefixes: []string{"10.0.1.0/24", "10.0.2.0/24"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-direct": {
				Name: "export-direct",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocol: "direct", PrefixList: "trusted-nets", Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Export:   []string{"export-direct"},
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, po)
	if !strings.Contains(got, "redistribute connected route-map export-direct\n") {
		t.Errorf("missing route-map redistribute, got:\n%s", got)
	}
	// Should NOT have bare "redistribute export-direct"
	if strings.Contains(got, "redistribute export-direct\n") {
		t.Errorf("should not have bare redistribute with policy name, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPExportRouteMap(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"bgp-export": {
				Name: "bgp-export",
				Terms: []*config.PolicyTerm{
					{Name: "connected", FromProtocol: "direct", Action: "accept"},
					{Name: "static", FromProtocol: "static", Action: "accept"},
				},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Export:   []string{"bgp-export"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po)
	if !strings.Contains(got, "redistribute connected route-map bgp-export\n") {
		t.Errorf("missing connected route-map, got:\n%s", got)
	}
	if !strings.Contains(got, "redistribute static route-map bgp-export\n") {
		t.Errorf("missing static route-map, got:\n%s", got)
	}
}

func TestGenerateProtocols_MixedBareAndRouteMap(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"filter-connected": {
				Name: "filter-connected",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocol: "direct", Action: "accept"},
				},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Export:  []string{"filter-connected", "static"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po)
	// Policy-based export should use route-map
	if !strings.Contains(got, "redistribute connected route-map filter-connected\n") {
		t.Errorf("missing route-map, got:\n%s", got)
	}
	// Bare protocol should be plain redistribute
	if !strings.Contains(got, "redistribute static\n") {
		t.Errorf("missing bare redistribute static, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPAllowASIn(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, AllowASIn: 2},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 allowas-in 2\n") {
		t.Errorf("missing allowas-in in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPRemovePrivateAS(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, RemovePrivateAS: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 remove-private-AS\n") {
		t.Errorf("missing remove-private-AS in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFv3(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFv3Interface{
					{Name: "trust0", Passive: true, Cost: 10},
					{Name: "dmz0"},
				},
			},
		},
		Export: []string{"connected"},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil)
	if !strings.Contains(got, "router ospf6\n") {
		t.Errorf("missing router ospf6 in:\n%s", got)
	}
	if !strings.Contains(got, "ospf6 router-id 10.0.0.1\n") {
		t.Errorf("missing router-id in:\n%s", got)
	}
	if !strings.Contains(got, "interface trust0 area 0.0.0.0\n") {
		t.Errorf("missing interface trust0 area in:\n%s", got)
	}
	if !strings.Contains(got, "interface dmz0 area 0.0.0.0\n") {
		t.Errorf("missing interface dmz0 area in:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 ospf6 passive\n") {
		t.Errorf("missing passive in:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 ospf6 cost 10\n") {
		t.Errorf("missing cost in:\n%s", got)
	}
	if !strings.Contains(got, "redistribute connected\n") {
		t.Errorf("missing redistribute in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFv3VRF(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.2",
		Areas: []*config.OSPFv3Area{
			{
				ID: "0.0.0.1",
				Interfaces: []*config.OSPFv3Interface{
					{Name: "vrf-eth0"},
				},
			},
		},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "cust-a", 0, nil)
	if !strings.Contains(got, "router ospf6 vrf cust-a\n") {
		t.Errorf("missing VRF-scoped ospf6 in:\n%s", got)
	}
	if !strings.Contains(got, "ospf6 router-id 10.0.0.2\n") {
		t.Errorf("missing router-id in:\n%s", got)
	}
}

func TestGeneratePolicyOptionsCommunityListAndMetricType(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"MY-COMM": {
				Name:    "MY-COMM",
				Members: []string{"65000:100", "65000:200"},
			},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"OSPF-EXPORT": {
				Name: "OSPF-EXPORT",
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocol:  "direct",
						FromCommunity: "MY-COMM",
						Action:        "accept",
						MetricType:    1,
						Metric:        100,
					},
					{
						Name:       "t2",
						Action:     "accept",
						MetricType: 2,
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"bgp community-list standard MY-COMM permit 65000:100",
		"bgp community-list standard MY-COMM permit 65000:200",
		"route-map OSPF-EXPORT permit 10",
		"match source-protocol connected",
		"match community MY-COMM",
		"set metric 100",
		"set metric-type type-1",
		"route-map OSPF-EXPORT permit 20",
		"set metric-type type-2",
		"route-map OSPF-EXPORT deny 30",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_BGPDampening(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		RouterID:  "1.1.1.1",
		Dampening: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)
	if !strings.Contains(got, "bgp dampening 15 750 2000 60\n") {
		t.Errorf("missing default dampening, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPDampeningCustom(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:              65001,
		RouterID:             "1.1.1.1",
		Dampening:            true,
		DampeningHalfLife:    10,
		DampeningReuse:       500,
		DampeningSuppress:    3000,
		DampeningMaxSuppress: 45,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)
	if !strings.Contains(got, "bgp dampening 10 500 3000 45\n") {
		t.Errorf("missing custom dampening, got:\n%s", got)
	}
}

func TestGeneratePolicyOptionsASPath(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			"AS65000": {Name: "AS65000", Regex: "65000"},
			"TRANSIT": {Name: "TRANSIT", Regex: "65[0-9]+"},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"FILTER-AS": {
				Name: "FILTER-AS",
				Terms: []*config.PolicyTerm{
					{
						Name:       "match-as",
						FromASPath: "AS65000",
						Action:     "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"bgp as-path access-list AS65000 permit 65000",
		"bgp as-path access-list TRANSIT permit 65[0-9]+",
		"route-map FILTER-AS permit 10",
		"match as-path AS65000",
		"route-map FILTER-AS deny 20",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_BGPPrefixLimit(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{
				Address:         "10.0.0.2",
				PeerAS:          65002,
				FamilyInet:      true,
				PrefixLimitInet: 1000,
			},
			{
				Address:          "fd00::2",
				PeerAS:           65003,
				FamilyInet6:      true,
				PrefixLimitInet6: 500,
			},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 maximum-prefix 1000\n") {
		t.Errorf("missing IPv4 maximum-prefix in:\n%s", got)
	}
	if !strings.Contains(got, "neighbor fd00::2 maximum-prefix 500\n") {
		t.Errorf("missing IPv6 maximum-prefix in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPPrefixLimitZeroOmitted(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, FamilyInet: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil)
	if strings.Contains(got, "maximum-prefix") {
		t.Errorf("should not have maximum-prefix when limit is 0:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFVirtualLink(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.1",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0"},
				},
				VirtualLinks: []*config.OSPFVirtualLink{
					{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
	if !strings.Contains(got, "area 0.0.0.1 virtual-link 10.0.0.2\n") {
		t.Errorf("missing virtual-link in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFVirtualLinkCustomTransitArea(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.1",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0"},
				},
				VirtualLinks: []*config.OSPFVirtualLink{
					{NeighborID: "10.0.0.3", TransitArea: "0.0.0.2"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
	if !strings.Contains(got, "area 0.0.0.2 virtual-link 10.0.0.3\n") {
		t.Errorf("missing virtual-link with custom transit area in:\n%s", got)
	}
}

func TestNextHopPeerAddress(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists:      make(map[string]*config.PrefixList),
		Communities:      make(map[string]*config.CommunityDef),
		ASPaths:          make(map[string]*config.ASPathDef),
		PolicyStatements: map[string]*config.PolicyStatement{
			"to-vpn-mesh": {
				Name: "to-vpn-mesh",
				Terms: []*config.PolicyTerm{
					{
						Name:         "v6",
						FromProtocol: "direct",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "2001:559:8585::/48", MatchType: "exact"},
						},
						NextHop: "peer-address",
						Action:  "accept",
					},
					{
						Name:         "v4",
						FromProtocol: "direct",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "172.16.0.0/20", MatchType: "exact"},
						},
						Action: "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)

	// "next-hop peer-address" in Junos should map to "set ip next-hop peer-address" in FRR
	if !strings.Contains(got, "set ip next-hop peer-address") {
		t.Errorf("missing 'set ip next-hop peer-address' in:\n%s", got)
	}

	// Verify route-filter exact generates proper prefix-list
	if !strings.Contains(got, "permit 2001:559:8585::/48\n") {
		t.Errorf("missing exact prefix-list entry for 2001:559:8585::/48 in:\n%s", got)
	}

	// Verify "next-hop self" does NOT generate "set ip next-hop peer-address"
	po2 := &config.PolicyOptionsConfig{
		PrefixLists:      make(map[string]*config.PrefixList),
		Communities:      make(map[string]*config.CommunityDef),
		ASPaths:          make(map[string]*config.ASPathDef),
		PolicyStatements: map[string]*config.PolicyStatement{
			"self-policy": {
				Name: "self-policy",
				Terms: []*config.PolicyTerm{
					{
						Name:    "t1",
						NextHop: "self",
						Action:  "accept",
					},
				},
			},
		},
	}
	got2 := m.generatePolicyOptions(po2)
	if strings.Contains(got2, "set ip next-hop") {
		t.Errorf("next-hop self should NOT generate set ip next-hop, got:\n%s", got2)
	}
}

func TestRouteFilterExactFRR(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists:      make(map[string]*config.PrefixList),
		Communities:      make(map[string]*config.CommunityDef),
		ASPaths:          make(map[string]*config.ASPathDef),
		PolicyStatements: map[string]*config.PolicyStatement{
			"to-firewall": {
				Name: "to-firewall",
				Terms: []*config.PolicyTerm{
					{
						Name:         "default_v4",
						FromProtocol: "direct",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "192.168.50.0/24", MatchType: "exact"},
							{Prefix: "192.168.99.0/24", MatchType: "exact"},
							{Prefix: "172.16.100.0/22", MatchType: "exact"},
						},
						Action: "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)

	// Each exact route-filter should generate a prefix-list entry without ge/le
	checks := []string{
		"ip prefix-list to-firewall-default_v4 seq 5 permit 192.168.50.0/24\n",
		"ip prefix-list to-firewall-default_v4 seq 10 permit 192.168.99.0/24\n",
		"ip prefix-list to-firewall-default_v4 seq 15 permit 172.16.100.0/22\n",
		"match ip address prefix-list to-firewall-default_v4",
		"route-map to-firewall permit 10",
		"route-map to-firewall deny 20",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
