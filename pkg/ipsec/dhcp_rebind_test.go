package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dhcpBoundConfig builds a config with one IPsec gateway whose
// local_addrs resolves from the named external interface unit. dhcp
// controls whether that unit is DHCP-managed; addr (CIDR, "" to omit)
// gives the unit a deterministic configured address so PrepareConfig can
// resolve a stable local-address in CI without a real kernel lease.
func dhcpBoundConfig(extIface, localAddr, addr string, dhcp bool) *config.Config {
	unit := &config.InterfaceUnit{DHCP: dhcp}
	if addr != "" {
		unit.PrimaryAddress = addr
		unit.Addresses = []string{addr}
	}
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name:  "wan0",
					Units: map[int]*config.InterfaceUnit{0: unit},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {
						Name:          "gw",
						Address:       "203.0.113.1",
						ExternalIface: extIface,
						LocalAddress:  localAddr,
					},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {Gateway: "gw"},
				},
			},
		},
	}
}

// TestHasDHCPBoundGateway covers the scoping predicate that gates the
// daemon's DHCP-lease-change swanctl re-render (#2884): true only when a
// gateway resolves local_addrs dynamically from a DHCP interface, so an
// unrelated lease refresh never triggers a reload storm.
func TestHasDHCPBoundGateway(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{
			name: "dynamic gateway on dhcp interface",
			cfg:  dhcpBoundConfig("wan0.0", "", "192.0.2.10/24", true),
			want: true,
		},
		{
			name: "bare interface ref with a dhcp unit",
			cfg:  dhcpBoundConfig("wan0", "", "192.0.2.10/24", true),
			want: true,
		},
		{
			name: "explicit local-address is not lease-dependent",
			cfg:  dhcpBoundConfig("wan0.0", "192.0.2.10", "192.0.2.10/24", true),
			want: false,
		},
		{
			name: "interface is not dhcp-managed",
			cfg:  dhcpBoundConfig("wan0.0", "", "192.0.2.10/24", false),
			want: false,
		},
		{
			name: "no external interface",
			cfg:  dhcpBoundConfig("", "", "192.0.2.10/24", true),
			want: false,
		},
		{
			name: "nil config",
			cfg:  nil,
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasDHCPBoundGateway(tc.cfg); got != tc.want {
				t.Fatalf("HasDHCPBoundGateway = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPrepareConfigReResolvesDHCPLocalAddress proves that PrepareConfig
// re-derives local_addrs from the CURRENT interface address each time it
// runs — so re-invoking it after a lease change yields the new bind
// address rather than a cached stale one (#2884).
func TestPrepareConfigReResolvesDHCPLocalAddress(t *testing.T) {
	m := &Manager{configDir: t.TempDir()}

	old := dhcpBoundConfig("wan0.0", "", "198.51.100.7/24", true)
	got := m.renderMust(t, PrepareConfig(old))
	if !strings.Contains(got, "local_addrs = 198.51.100.7") {
		t.Fatalf("first render missing original local_addrs:\n%s", got)
	}

	// Simulate a DHCP renew to a new lease address.
	renewed := dhcpBoundConfig("wan0.0", "", "203.0.113.42/24", true)
	got = m.renderMust(t, PrepareConfig(renewed))
	if !strings.Contains(got, "local_addrs = 203.0.113.42") {
		t.Fatalf("re-render did not pick up the new lease address:\n%s", got)
	}
	if strings.Contains(got, "local_addrs = 198.51.100.7") {
		t.Fatalf("re-render retained the stale lease address:\n%s", got)
	}
}

// renderMust renders the swanctl config for prepared, failing the test on
// error.
func (m *Manager) renderMust(t *testing.T, prepared *config.IPsecConfig) string {
	t.Helper()
	got, err := m.renderConfig(prepared)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	return got
}
