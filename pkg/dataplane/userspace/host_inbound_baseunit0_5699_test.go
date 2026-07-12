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
	// Zone trust admits `ping` at the zone level; the unit-0 ref adds `ssh` via a
	// per-interface host-inbound override — so base sig (ping) != unit-0 sig
	// (ping+ssh).
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
	// Precedence: the single view must carry the unit-0-authoritative merged
	// admit set (zone ping ∪ unit-0 ssh), NOT the base-only (ping) set.
	got := carrying[0]
	if !containsAll(got.SystemServices, []string{"ping", "ssh"}) {
		t.Fatalf("winning view services = %v, want the unit-0 merged set [ping ssh] "+
			"(unit-0 override must win, not the base-only ping)", got.SystemServices)
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
