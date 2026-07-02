// #3710: AddresslessEnforcingZones (#3698) reports the host-inbound fail-open
// admit window at ZONE granularity — a zone is silent the moment ANY of its
// interfaces resolves an address in EITHER family. Host-inbound ENFORCEMENT is
// per-destination-address and per-family, so a MIXED zone (a DHCP-pending
// interface beside a statically-addressed sibling, or the v6 side of a
// dual-stack edge whose v6 lease lands after v4) still has a real per-interface /
// per-family fail-open window that the zone-level collapse cannot express.
// AddresslessEnforcingInterfaces surfaces that finer detail. These tests are
// fail-on-revert: collapse the reporter back to zone granularity and the mixed
// cases stop surfacing; the fully-addressed / lifeline / static / VIP cases must
// stay silent (the low-noise contract).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// mixedZoneCfg3710 builds a config that exercises every arm of the per-interface
// reporter: a mixed zone (addressed sibling + DHCP-pending sibling), a mixed
// dual-stack interface (static v4 + DHCPv6-pending v6), a fully-addressed zone, a
// DHCP lifeline (fxp0) that must stay silent, and a VIP-scoped zone.
func mixedZoneCfg3710() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// trust: two units. ge-0-0-0.0 is statically addressed; ge-0-0-1.0 is a
		// DHCP WAN with no lease yet. The addressed sibling makes the ZONE scoped
		// (#3698 stays silent), so ge-0-0-1.0's window is only visible per
		// interface.
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.10/24"}},
		}},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		// dual: static v4 present, v6 via DHCPv6 pending. inet resolves (scopes the
		// zone), so #3698 is silent; the inet6 window is per-family only.
		"ge-0-0-2": {Name: "ge-0-0-2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.2.10/24"}, DHCPv6: true},
		}},
		// mgmt: fxp0 is a lifeline and DHCP — must NEVER be reported.
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		// ha: no static address, DHCP configured, but a configured VRRP VIP scopes
		// the deny from config on both nodes — the inet family resolves, so no
		// inet window; there is no v6 client, so no inet6 window.
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, VRRPGroups: map[string]*config.VRRPGroup{
				"10.0.9.1/24": {VirtualAddresses: []string{"10.0.9.1"}},
			}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-0.0", "ge-0-0-1.0"}},
		"dual":  {Name: "dual", Interfaces: []string{"ge-0-0-2.0"}},
		"mgmt":  {Name: "mgmt", Interfaces: []string{"fxp0.0"}},
		"ha":    {Name: "ha", Interfaces: []string{"reth0.0"}},
	}
	return cfg
}

func TestAddresslessEnforcingInterfaces(t *testing.T) {
	got := AddresslessEnforcingInterfaces(mixedZoneCfg3710())

	// Exactly two per-interface/per-family windows are open:
	//   trust / ge-0-0-1.0 / inet  (DHCP WAN, no lease — hidden by addressed sibling)
	//   dual  / ge-0-0-2.0 / inet6 (DHCPv6 pending — hidden by the resolved v4)
	type key struct{ zone, iface, family, reason string }
	want := map[key]bool{
		{"trust", "ge-0-0-1.0", "inet", AddresslessDHCPPending}: true,
		{"dual", "ge-0-0-2.0", "inet6", AddresslessDHCPPending}: true,
	}
	if len(got) != len(want) {
		t.Fatalf("AddresslessEnforcingInterfaces = %+v, want exactly %d entries %v", got, len(want), want)
	}
	for _, g := range got {
		k := key{g.Zone, g.Interface, g.Family, g.Reason}
		if !want[k] {
			t.Errorf("unexpected per-interface window %+v", g)
		}
		delete(want, k)
	}
	for k := range want {
		t.Errorf("missing per-interface window %+v", k)
	}
}

// TestAddresslessEnforcingInterfacesSorted pins the deterministic (zone,
// interface, family) ordering the metric / log rely on for stable output.
func TestAddresslessEnforcingInterfacesSorted(t *testing.T) {
	got := AddresslessEnforcingInterfaces(mixedZoneCfg3710())
	if len(got) < 2 {
		t.Fatalf("precondition: expected >=2 windows, got %+v", got)
	}
	for i := 1; i < len(got); i++ {
		a, b := got[i-1], got[i]
		if a.Zone > b.Zone ||
			(a.Zone == b.Zone && a.Interface > b.Interface) ||
			(a.Zone == b.Zone && a.Interface == b.Interface && a.Family > b.Family) {
			t.Errorf("not sorted at %d: %+v then %+v", i, a, b)
		}
	}
}

// TestAddresslessEnforcingInterfacesLowNoise proves the entries that must stay
// SILENT: a lifeline, a statically-addressed unit, a VIP-scoped unit, and the
// resolved family of a dual-stack edge.
func TestAddresslessEnforcingInterfacesLowNoise(t *testing.T) {
	for _, g := range AddresslessEnforcingInterfaces(mixedZoneCfg3710()) {
		switch {
		case g.Interface == "fxp0.0":
			t.Error("fxp0 is a lifeline (DHCP but never host-inbound-denied) — must not be reported")
		case g.Interface == "ge-0-0-0.0":
			t.Error("ge-0-0-0.0 is statically addressed — must not be reported")
		case g.Interface == "reth0.0":
			t.Error("reth0.0 inet is scoped by its VRRP VIP from config — must not be reported")
		case g.Interface == "ge-0-0-2.0" && g.Family == "inet":
			t.Error("ge-0-0-2.0 inet is statically addressed — only its inet6 side is in the window")
		}
	}
}

// TestAddresslessEnforcingInterfacesHealsOnLease asserts each window closes once
// the pending family resolves an address — the self-heal path the daemon relies
// on to clear its state-transition warning.
func TestAddresslessEnforcingInterfacesHealsOnLease(t *testing.T) {
	cfg := mixedZoneCfg3710()
	if len(AddresslessEnforcingInterfaces(cfg)) != 2 {
		t.Fatalf("precondition: expected 2 windows")
	}
	// The DHCP WAN lease lands (v4) and the DHCPv6 lease lands (v6).
	cfg.Interfaces.Interfaces["ge-0-0-1"].Units[0].Addresses = []string{"203.0.113.5/24"}
	cfg.Interfaces.Interfaces["ge-0-0-2"].Units[0].Addresses = []string{"10.0.2.10/24", "2001:db8:2::10/64"}
	if got := AddresslessEnforcingInterfaces(cfg); len(got) != 0 {
		t.Errorf("after leases install = %+v, want empty (all windows closed)", got)
	}
}

// TestAddresslessEnforcingInterfacesIPv4OnlyNoV6Noise proves the low-noise gate:
// an IPv4-only interface (no v6 client configured) is NOT reported as addressless
// in inet6 — it never intends to acquire a v6 address, so there is no window.
func TestAddresslessEnforcingInterfacesIPv4OnlyNoV6Noise(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true}, // v4 DHCP only, no v6 client
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-0.0"}},
	}
	got := AddresslessEnforcingInterfaces(cfg)
	if len(got) != 1 || got[0].Family != "inet" {
		t.Fatalf("IPv4-only DHCP = %+v, want exactly [trust ge-0-0-0.0 inet]", got)
	}
}

// TestAddresslessEnforcingInterfacesEmptyConfig guards the nil / no-zone /
// no-interface fast paths.
func TestAddresslessEnforcingInterfacesEmptyConfig(t *testing.T) {
	if got := AddresslessEnforcingInterfaces(nil); got != nil {
		t.Errorf("nil cfg = %v, want nil", got)
	}
	if got := AddresslessEnforcingInterfaces(&config.Config{}); got != nil {
		t.Errorf("no-zone cfg = %v, want nil", got)
	}
}
