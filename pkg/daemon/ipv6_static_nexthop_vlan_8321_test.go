package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8321 finding 07: the FRR static-route next-hop interface must be named for
// the VLAN ID, not the unit number.
//
// An 802.1q sub-interface where the two differ — `set interfaces ge-0-0-1
// unit 10 vlan-id 100` — is created by networkd as `ge-0-0-1.100`. Formatting
// `ge-0-0-1.10` made the static route name an interface that does not exist,
// so zebra flagged it inactive and blackholed every destination behind it.
//
// The convention is not a judgement call: FIVE other sites in this package
// already resolve it this way — daemon_dhcp.go:311-315, daemon_ha_vip.go at
// 327/393/678, and daemon_neighbor.go:130. This was the one that did not, and
// that asymmetry is what makes the finding decidable without a box.
//
// THE FIXTURE MUST HAVE unit != vlan-id. The pre-existing
// TestInferIPv6StaticNextHopInterfaces uses units 50 and 80 with NO VlanID set,
// so it exercises the fallback and passes identically against both
// implementations — which is exactly why the defect survived it.

func TestStaticNextHopUsesVlanIDNotUnitNumber8321(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/1": {
					Units: map[int]*config.InterfaceUnit{
						// The discriminating shape: unit 10, VLAN 100.
						10: {VlanID: 100, Addresses: []string{"2001:db8:aa::8/64"}},
					},
				},
			},
		},
		RoutingOptions: config.RoutingOptionsConfig{
			Inet6StaticRoutes: []*config.StaticRoute{
				{
					Destination: "2001:db8:ffff::/48",
					NextHops:    []config.NextHopEntry{{Address: "2001:db8:aa::1"}},
				},
			},
		},
	}

	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	iface := got[""]["2001:db8:aa::1"]
	if iface == "ge-0-0-1.10" {
		t.Fatalf("next-hop interface = %q — named for the UNIT (10) rather than "+
			"the VLAN ID (100). networkd creates ge-0-0-1.100, so zebra receives "+
			"a route naming an interface that does not exist and blackholes it.",
			iface)
	}
	if iface != "ge-0-0-1.100" {
		t.Fatalf("next-hop interface = %q, want ge-0-0-1.100", iface)
	}
}

func TestStaticNextHopFallsBackToUnitWithoutAVlanID8321(t *testing.T) {
	// The other side, and it is why this is not a substitution of one field for
	// the other. A unit with NO vlan-id is not a tagged sub-interface, and there
	// `base.<unit>` is the correct netdev name — which is what the pre-existing
	// test relies on. Without this cell, replacing unitNum with VlanID outright
	// would pass the cell above and break every untagged unit.
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/1": {
					Units: map[int]*config.InterfaceUnit{
						7: {Addresses: []string{"2001:db8:bb::8/64"}},
					},
				},
			},
		},
		RoutingOptions: config.RoutingOptionsConfig{
			Inet6StaticRoutes: []*config.StaticRoute{
				{
					Destination: "2001:db8:ffff::/48",
					NextHops:    []config.NextHopEntry{{Address: "2001:db8:bb::1"}},
				},
			},
		},
	}
	if got := inferIPv6StaticNextHopInterfaces(cfg, nil)[""]["2001:db8:bb::1"]; got != "ge-0-0-1.7" {
		t.Fatalf("next-hop interface = %q, want ge-0-0-1.7 — a unit with no "+
			"vlan-id must still resolve to base.<unit>", got)
	}
}
