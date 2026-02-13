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
	got := m.generateProtocols(ospf, nil, nil, nil, "")
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
	got := m.generateProtocols(ospf, nil, nil, nil, "")
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
	got := m.generateProtocols(nil, bgp, nil, nil, "")
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
	got := m.generateProtocols(nil, nil, rip, nil, "")
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
	got := m.generateProtocols(nil, nil, nil, isis, "")
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

func TestGenerateProtocols_VRF(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "2.2.2.2",
		Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, "cust-a")
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
