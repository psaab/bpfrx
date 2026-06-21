package dhcpserver

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// keaReservationView mirrors the JSON shape generateKea4Config emits for a
// per-subnet `reservations` entry, used to read back the rendered config.
type keaReservationView struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
	Hostname  string `json:"hostname"`
}

type keaSubnet4View struct {
	Subnet       string               `json:"subnet"`
	Reservations []keaReservationView `json:"reservations"`
}

type keaReservation6View struct {
	HWAddress   string   `json:"hw-address"`
	IPAddresses []string `json:"ip-addresses"`
	Hostname    string   `json:"hostname"`
}

type keaSubnet6View struct {
	Subnet       string                `json:"subnet"`
	Reservations []keaReservation6View `json:"reservations"`
}

func readSubnet4(t *testing.T, path string) []keaSubnet4View {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out struct {
		Dhcp4 struct {
			Subnet4 []keaSubnet4View `json:"subnet4"`
		} `json:"Dhcp4"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal kea4: %v", err)
	}
	return out.Dhcp4.Subnet4
}

func readSubnet6(t *testing.T, path string) []keaSubnet6View {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out struct {
		Dhcp6 struct {
			Subnet6 []keaSubnet6View `json:"subnet6"`
		} `json:"Dhcp6"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal kea6: %v", err)
	}
	return out.Dhcp6.Subnet6
}

// TestKea4StaticBindingRendersReservation is the FAIL-ON-REVERT proof for
// the v4 half of #2243: a pool carrying a static-binding must render a Kea
// per-subnet `reservations` entry mapping hw-address -> ip-address (+
// hostname). Deleting the render loop drops the entry and fails this test.
func TestKea4StaticBindingRendersReservation(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"g0": {
					Name:       "g0",
					Interfaces: []string{"ge-0-0-0"},
					Pools: []*config.DHCPPool{{
						Name:     "p0",
						Subnet:   "10.0.1.0/24",
						RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200",
						StaticBindings: []*config.DHCPStaticBinding{
							{MACAddress: "00:11:22:33:44:55", FixedAddress: "10.0.1.50", HostName: "printer"},
						},
					}},
				},
			},
		},
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	subs := readSubnet4(t, m.confPath4)
	if len(subs) != 1 {
		t.Fatalf("want 1 subnet, got %d", len(subs))
	}
	res := subs[0].Reservations
	if len(res) != 1 {
		t.Fatalf("want 1 reservation, got %d (%+v)", len(res), res)
	}
	if res[0].HWAddress != "00:11:22:33:44:55" {
		t.Errorf("hw-address: got %q, want 00:11:22:33:44:55", res[0].HWAddress)
	}
	if res[0].IPAddress != "10.0.1.50" {
		t.Errorf("ip-address: got %q, want 10.0.1.50", res[0].IPAddress)
	}
	if res[0].Hostname != "printer" {
		t.Errorf("hostname: got %q, want printer", res[0].Hostname)
	}
}

// TestKea4NoStaticBindingOmitsReservations is the no-regression guard: a
// pool without static-bindings must emit NO `reservations` key (omitempty),
// matching pre-#2243 output byte-for-byte.
func TestKea4NoStaticBindingOmitsReservations(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.Apply(v4Config("ge-0-0-0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	subs := readSubnet4(t, m.confPath4)
	if len(subs) != 1 {
		t.Fatalf("want 1 subnet, got %d", len(subs))
	}
	if subs[0].Reservations != nil {
		t.Errorf("config without static-bindings must omit reservations, got %+v", subs[0].Reservations)
	}
}

// TestKea6StaticBindingRendersReservation is the FAIL-ON-REVERT proof for
// the v6 half: hw-address -> ip-addresses[] (Kea v6 uses an address array).
func TestKea6StaticBindingRendersReservation(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := &config.DHCPServerConfig{
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"g0": {
					Name:       "g0",
					Interfaces: []string{"ge-0-0-0"},
					Pools: []*config.DHCPPool{{
						Name:     "p0",
						Subnet:   "2001:db8::/64",
						RangeLow: "2001:db8::100", RangeHigh: "2001:db8::200",
						StaticBindings: []*config.DHCPStaticBinding{
							{MACAddress: "00:11:22:33:44:66", FixedAddress: "2001:db8::50", HostName: "nas"},
						},
					}},
				},
			},
		},
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	subs := readSubnet6(t, m.confPath6)
	if len(subs) != 1 {
		t.Fatalf("want 1 subnet, got %d", len(subs))
	}
	res := subs[0].Reservations
	if len(res) != 1 {
		t.Fatalf("want 1 reservation, got %d (%+v)", len(res), res)
	}
	if res[0].HWAddress != "00:11:22:33:44:66" {
		t.Errorf("hw-address: got %q", res[0].HWAddress)
	}
	if len(res[0].IPAddresses) != 1 || res[0].IPAddresses[0] != "2001:db8::50" {
		t.Errorf("ip-addresses: got %+v, want [2001:db8::50]", res[0].IPAddresses)
	}
	if res[0].Hostname != "nas" {
		t.Errorf("hostname: got %q, want nas", res[0].Hostname)
	}
}
