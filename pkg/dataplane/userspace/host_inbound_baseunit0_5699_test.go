package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestHostInboundBaseUnit0NoConflict_5699 is the #5699 (codex-182 M22)
// fail-on-revert guard. A non-VLAN unit 0 collapses onto the base netdev
// (ge-0/0/0.0 → Linux ge-0-0-0), so the base-interface snapshot and the unit-0
// snapshot enumerate the IDENTICAL live kernel address. The base ref keys that
// address under overrideByIface[base] (base-level override only) while unit 0
// keys it under overrideByIface[base.0] (base ∪ unit-0 override). A
// per-interface host-inbound override on the unit-0 ref therefore made the two
// signatures diverge, emitting the SINGLE live address into TWO host-inbound
// views with conflicting admit sets — the kernel host-inbound chain matches
// destination address only, so the verdict is order-dependent (deterministic
// false-deny).
//
// The fix skips the base's redundant contribution when unit 0 exists, so the
// address resolves to ONE view carrying the unit-0-authoritative (base ∪
// unit-0) admit set.
//
// The base snapshot's addresses come only from the LIVE kernel
// (buildLinkSnapshot), which returns nothing in a test env — so the conflict is
// invisible unless the base netdev actually carries the address. This test
// injects that via the buildLinkSnapshot seam to reproduce the deployed-box
// behavior.
//
// FAIL-ON-REVERT: remove the base-snapshot skip in BuildZoneHostInboundViews and
// the live address appears in TWO views again — the count assertion goes RED.
func TestHostInboundBaseUnit0NoConflict_5699(t *testing.T) {
	// Simulate the deployed box: the base netdev ge-0-0-0 (== unit-0 netdev for
	// a non-VLAN unit 0) carries the configured address live.
	prev := buildLinkSnapshot
	defer func() { buildLinkSnapshot = prev }()
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-0" {
			return 2, 1500, "02:00:00:00:00:01", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.1.10/24"},
			}
		}
		return 0, 0, "", nil
	}

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.10/24"}},
		}},
	}
	// Zone trust admits `ping` at the zone level; the unit-0 ref declares a
	// per-interface host-inbound override of `ssh`, which REPLACES the zone set
	// on that unit (#6515) — so base sig (ping, no base-level override) !=
	// unit-0 sig (ssh). The signatures differing is what this test needs; #6515
	// changed WHICH sets differ, not that they do.
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"ge-0/0/0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ping"}},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"ge-0/0/0.0": {SystemServices: []string{"ssh"}},
			},
		},
	}

	views := BuildZoneHostInboundViews(cfg)

	var carrying []ZoneHostInboundView
	for _, v := range views {
		for _, a := range v.V4Addrs {
			if a == "10.0.1.10" {
				carrying = append(carrying, v)
			}
		}
	}
	if len(carrying) != 1 {
		t.Fatalf("live address 10.0.1.10 appears in %d host-inbound views, want exactly 1 "+
			"(the #5699 base-vs-unit-0 conflict); views carrying it: %+v", len(carrying), carrying)
	}
	// Precedence: the single view must carry the unit-0-authoritative admit set
	// (the unit-0 override `ssh`, which replaces the zone-level `ping`, #6515),
	// NOT the base ref's zone-level-only (ping) set. Asserting the ABSENCE of
	// `ping` as well as the presence of `ssh` is what pins precedence: a view
	// carrying both would mean the base contributed after all.
	got := carrying[0]
	if !containsAll(got.SystemServices, []string{"ssh"}) {
		t.Fatalf("winning view services = %v, want the unit-0 override set [ssh] "+
			"(unit-0 override must win, not the base ref's zone-level ping)", got.SystemServices)
	}
	for _, s := range got.SystemServices {
		if s == "ping" {
			t.Fatalf("winning view services = %v: the base ref's zone-level `ping` must not "+
				"appear — the unit-0 stanza replaces the zone set (#6515) and the base's "+
				"redundant contribution is skipped (#5699)", got.SystemServices)
		}
	}
}

// TestHostInboundVlanUnit0KeepsBaseAddress_5699 guards against an over-firing
// skip: for a VLAN unit 0 (VlanID>0) the unit resolves to a DISTINCT netdev
// (ge-0-0-0.100), so the base netdev (ge-0-0-0) and unit-0 enumerate DISJOINT
// addresses. The base's own live address (e.g. a stray/DHCP addr on the raw
// netdev) must therefore STILL be deny-scoped — skipping the base here would
// drop it from every host-inbound view, and the kernel input chain would fall
// through to `policy accept` (FAIL-OPEN).
//
// FAIL-ON-REVERT: a guard that skips the base whenever unit 0 merely EXISTS
// (`ifc.Units[0] != nil`) drops the base address and this test goes RED.
func TestHostInboundVlanUnit0KeepsBaseAddress_5699(t *testing.T) {
	prev := buildLinkSnapshot
	defer func() { buildLinkSnapshot = prev }()
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		switch linuxName {
		case "ge-0-0-0": // base raw netdev carries a live (stray/DHCP) address
			return 2, 1500, "02:00:00:00:00:01", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.9.9/24"},
			}
		case "ge-0-0-0.100": // the VLAN unit netdev (distinct)
			return 3, 1500, "02:00:00:00:00:01", nil
		}
		return 0, 0, "", nil
	}

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			// unit 0 is a VLAN unit -> Linux ge-0-0-0.100, a DIFFERENT netdev
			// from the base ge-0-0-0.
			0: {Number: 0, VlanID: 100, Addresses: []string{"172.16.100.8/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"ge-0/0/0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ping"}},
		},
	}

	views := BuildZoneHostInboundViews(cfg)
	var baseScoped bool
	for _, v := range views {
		for _, a := range v.V4Addrs {
			if a == "10.0.9.9" {
				baseScoped = true
			}
		}
	}
	if !baseScoped {
		t.Fatalf("VLAN unit-0 case: the base netdev's live address 10.0.9.9 was DROPPED from all "+
			"host-inbound views (fail-open) — base and unit-0 are DISJOINT netdevs, the base must "+
			"stay deny-scoped; views=%+v", views)
	}
}

// TestHostInboundNoUnit0KeepsBase_5699 confirms the unchanged behavior: a
// physical interface with NO unit 0 keeps the base as the sole carrier of its
// live address (never dropped).
func TestHostInboundNoUnit0KeepsBase_5699(t *testing.T) {
	prev := buildLinkSnapshot
	defer func() { buildLinkSnapshot = prev }()
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-0" {
			return 2, 1500, "02:00:00:00:00:01", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.9.9/24"},
			}
		}
		return 0, 0, "", nil
	}

	cfg := &config.Config{}
	// No units at all on the physical interface.
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"ge-0/0/0"}, // base ref (no unit 0 exists)
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ping"}},
		},
	}

	views := BuildZoneHostInboundViews(cfg)
	var baseScoped bool
	for _, v := range views {
		for _, a := range v.V4Addrs {
			if a == "10.0.9.9" {
				baseScoped = true
			}
		}
	}
	if !baseScoped {
		t.Fatalf("no-unit-0 case: the base netdev's live address 10.0.9.9 must stay deny-scoped; views=%+v", views)
	}
}

func containsAll(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
