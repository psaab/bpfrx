package dhcpserver

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// readIfacesConfig4 decodes Dhcp4.interfaces-config with dhcp-socket-type as a
// *string on purpose. Decoding it into a plain string would make "key absent"
// and "key present but empty" both read as "", so an absence assertion could
// never fail — the pointer keeps the three states distinct.
func readIfacesConfig4(t *testing.T, m *Manager) (ifaces []string, socketType *string, raw string) {
	t.Helper()
	data, err := os.ReadFile(m.confPath4)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Dhcp4 struct {
			InterfacesConfig struct {
				Interfaces []string `json:"interfaces"`
				SocketType *string  `json:"dhcp-socket-type"`
			} `json:"interfaces-config"`
		} `json:"Dhcp4"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal rendered Kea config: %v", err)
	}
	return out.Dhcp4.InterfacesConfig.Interfaces, out.Dhcp4.InterfacesConfig.SocketType, string(data)
}

// The #7318 leaf must render only when the operator selected a value, and the
// absent case must stay byte-identical to pre-#7318 output.
//
// The two subtests are a PAIR and neither is meaningful alone. "unset omits the
// key" would pass against a build that cannot emit the key at all (a typo in
// the JSON name, a dead branch, the field never read); "udp renders" is what
// proves the harness CAN produce the very thing the first subtest asserts is
// absent. Read together they show the omission is a decision, not an inability.
func TestSocketTypeRendersOnlyWhenSelected7318(t *testing.T) {
	t.Run("unset omits the key entirely", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		if err := m.Apply(v4Config("ge-0-0-1")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		_, st, raw := readIfacesConfig4(t, m)
		if st != nil {
			t.Errorf("dhcp-socket-type must be ABSENT when unset, got %q", *st)
		}
		// Belt and braces: the key name must not appear at all, so a future
		// render that emits `"dhcp-socket-type": null` (which decodes to a nil
		// *string and would slip past the check above) is still caught.
		if strings.Contains(raw, "dhcp-socket-type") {
			t.Errorf("rendered config must not mention dhcp-socket-type when unset:\n%s", raw)
		}
	})

	t.Run("udp renders the selected value", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		cfg := v4Config("ge-0-0-1")
		cfg.DHCPLocalServer.SocketType = config.DHCPSocketTypeUDP
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		ifaces, st, _ := readIfacesConfig4(t, m)
		if st == nil {
			t.Fatal("dhcp-socket-type must be rendered when selected")
		}
		if *st != config.DHCPSocketTypeUDP {
			t.Errorf("dhcp-socket-type = %q, want %q", *st, config.DHCPSocketTypeUDP)
		}
		// The key must land INSIDE interfaces-config, next to interfaces —
		// Kea ignores it anywhere else, so a render that put it at the Dhcp4
		// top level would be silently inert. Decoding through the nested
		// struct above is what pins that.
		if len(ifaces) != 1 || ifaces[0] != "ge-0-0-1" {
			t.Errorf("interfaces = %v, want [ge-0-0-1] alongside the socket type", ifaces)
		}
	})

	// An explicit `raw` is honoured rather than silently dropped. It is
	// semantically identical to omitting the key, but the operator asked for
	// it, and dropping it would make `show configuration` disagree with the
	// rendered file.
	t.Run("explicit raw renders raw", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		cfg := v4Config("ge-0-0-1")
		cfg.DHCPLocalServer.SocketType = config.DHCPSocketTypeRaw
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		_, st, _ := readIfacesConfig4(t, m)
		if st == nil || *st != config.DHCPSocketTypeRaw {
			t.Errorf("explicit raw must render as %q, got %v", config.DHCPSocketTypeRaw, st)
		}
	})
}

// Kea's Dhcp6 has no raw mode, so the v6 render must never grow the key no
// matter what the v4 side selected.
func TestSocketTypeNeverRendersOnTheV6Path7318(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := v4Config("ge-0-0-1")
	cfg.DHCPLocalServer.SocketType = config.DHCPSocketTypeUDP
	// Give the manager a real v6 server so a Dhcp6 file is actually rendered.
	cfg.DHCPv6LocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{
			"g6": {Name: "g6", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
				{Name: "p6", Subnet: "2001:db8:1::/64", RangeLow: "2001:db8:1::10", RangeHigh: "2001:db8:1::20"},
			}},
		},
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	data, err := os.ReadFile(m.confPath6)
	if err != nil {
		// A skip here would be a void cell: it would report healthy whether
		// or not the v6 render leaks the key. The fixture below carries a
		// real v6 server precisely so this file exists.
		t.Fatalf("expected a rendered Dhcp6 config to inspect: %v", err)
	}
	if !strings.Contains(string(data), "interfaces-config") {
		t.Fatalf("v6 render is not the config under test:\n%s", data)
	}
	if strings.Contains(string(data), "dhcp-socket-type") {
		t.Errorf("Dhcp6 must never carry dhcp-socket-type:\n%s", data)
	}
}
