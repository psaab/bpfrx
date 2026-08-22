package config

import (
	"strings"
	"testing"
)

// #6515: the zone-level `host-inbound-traffic` stanza and a per-interface one do
// not COMBINE — the interface stanza REPLACES the zone stanza for that
// interface. Juniper, Security Zones (security-zone-configuration): "You can
// configure these parameters at the zone level, in which case they affect all
// interfaces of the zone, or at the interface level. (Interface configuration
// overrides that of the zone.)"
//
// Before #6515 the two were UNIONed and the in-tree comments asserted "Junos
// additive semantics", so an interface stanza could only ever WIDEN admission.

// TestEffectiveHostInboundTokens_6515 is the resolver table. The `overridden`
// column is the whole point: it is stanza PRESENCE, not emptiness, so an
// explicit `host-inbound-traffic { }` on an interface is a deny-all override and
// must not fall back to the zone set.
func TestEffectiveHostInboundTokens_6515(t *testing.T) {
	cases := []struct {
		name        string
		zone, iface []string
		overridden  bool
		want        []string
	}{
		{"no override falls back to the zone set", []string{"ssh", "ping"}, nil, false, []string{"ssh", "ping"}},
		{"override replaces the zone set", []string{"ssh", "ping"}, []string{"https"}, true, []string{"https"}},
		{"override does not inherit unlisted zone tokens", []string{"ssh"}, []string{"ospf"}, true, []string{"ospf"}},
		{"empty override is deny-all, not a fallback", []string{"ssh"}, nil, true, nil},
		{"empty override with empty zone stays empty", nil, nil, true, nil},
		{"no override and no zone set is empty", nil, nil, false, nil},
		{"override is normalized (trim, dedup, drop empties)", []string{"ssh"}, []string{"https", " https ", ""}, true, []string{"https"}},
		{"zone set is normalized when it is the answer", []string{"ssh", "ssh", " "}, nil, false, []string{"ssh"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveHostInboundTokens(tc.zone, tc.iface, tc.overridden)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("EffectiveHostInboundTokens(%v, %v, %v) = %v, want %v",
					tc.zone, tc.iface, tc.overridden, got, tc.want)
			}
		})
	}
}

// TestInterfaceHostInboundEffectiveReplacesZoneNotInterfaceLevels_6515 pins the
// two rules apart. #6515 replaced the ZONE level; it did not touch how a
// physical-interface override and a unit-level override combine WITH EACH OTHER
// (#3720) — both are interface-level statements and still union.
//
// Written as one fixture carrying all three levels so a regression in either
// direction is visible: collapsing the physical∪unit union would drop `ping`,
// and reverting the zone replace would add `ssh`.
func TestInterfaceHostInboundEffectiveReplacesZoneNotInterfaceLevels_6515(t *testing.T) {
	z := &ZoneConfig{
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
		InterfaceHostInbound: map[string]*HostInboundTraffic{
			"ge-0/0/9":   {SystemServices: []string{"ping"}},
			"ge-0/0/9.0": {SystemServices: []string{"https"}},
		},
	}
	svc, _, overridden := z.InterfaceHostInboundEffective("ge-0/0/9.0")
	if !overridden {
		t.Fatal("ge-0/0/9.0 declares an override (and inherits its physical parent's)")
	}
	got := strings.Join(svc, ",")
	if got != "ping,https" {
		t.Fatalf("effective svc = %v, want [ping https]: the physical and unit overrides are "+
			"both INTERFACE-level and still union (#3720), while the zone's `ssh` is "+
			"REPLACED (#6515)", svc)
	}
	for _, s := range svc {
		if s == "ssh" {
			t.Fatalf("effective svc = %v: the zone-level `ssh` must not survive on an "+
				"interface that declares its own host-inbound-traffic (#6515)", svc)
		}
	}
}

// TestHostInboundOverrideReplaceAdvisory_6515 covers the migration advisory that
// ships with the flip: it must name every zone token an interface stanza takes
// away, and must stay silent where nothing is actually lost — a warning that
// fires on configs losing nothing is one operators learn to ignore.
func TestHostInboundOverrideReplaceAdvisory_6515(t *testing.T) {
	build := func(zoneSvc, zoneProto []string, ifSvc, ifProto []string, ifRef string) *Config {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{
			"trust": {
				Name:               "trust",
				Interfaces:         []string{ifRef, "ge-0/0/8.0"},
				HostInboundTraffic: &HostInboundTraffic{SystemServices: zoneSvc, Protocols: zoneProto},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					ifRef: {SystemServices: ifSvc, Protocols: ifProto},
				},
			},
		}
		return cfg
	}

	t.Run("names the lost services and protocols", func(t *testing.T) {
		cfg := build([]string{"ssh", "https"}, []string{"ospf"}, []string{"ping"}, nil, "ge-0/0/9.0")
		got := validateHostInboundOverrideReplaceWarnings(cfg)
		if len(got) != 1 {
			t.Fatalf("want exactly one advisory, got %d: %v", len(got), got)
		}
		for _, want := range []string{`"trust"`, `"ge-0/0/9.0"`, "ssh", "https", "ospf", "REPLACES"} {
			if !strings.Contains(got[0], want) {
				t.Errorf("advisory must mention %q so the operator can act on it, got: %s", want, got[0])
			}
		}
		if strings.Contains(got[0], "ge-0/0/8.0") {
			t.Errorf("the sibling interface declares no stanza and loses nothing; it must not "+
				"be named, got: %s", got[0])
		}
	})

	t.Run("silent when the override is a superset", func(t *testing.T) {
		cfg := build([]string{"ssh"}, nil, []string{"ssh", "ping"}, nil, "ge-0/0/9.0")
		if got := validateHostInboundOverrideReplaceWarnings(cfg); len(got) != 0 {
			t.Fatalf("an override repeating every zone token loses nothing; want no advisory, got: %v", got)
		}
	})

	t.Run("silent when the override full-admits", func(t *testing.T) {
		cfg := build([]string{"ssh"}, []string{"ospf"}, []string{"any-service"}, nil, "ge-0/0/9.0")
		if got := validateHostInboundOverrideReplaceWarnings(cfg); len(got) != 0 {
			t.Fatalf("an `any-service` override admits everything the zone did; want no advisory, got: %v", got)
		}
	})

	t.Run("silent when the override `all` covers the zone token", func(t *testing.T) {
		cfg := build([]string{"ssh"}, nil, []string{"all"}, nil, "ge-0/0/9.0")
		if got := validateHostInboundOverrideReplaceWarnings(cfg); len(got) != 0 {
			t.Fatalf("`all` expands to a union including ssh, so nothing is lost; got: %v", got)
		}
	})

	t.Run("fires when the zone `all` is narrowed by the override", func(t *testing.T) {
		cfg := build([]string{"all"}, nil, []string{"ssh"}, nil, "ge-0/0/9.0")
		got := validateHostInboundOverrideReplaceWarnings(cfg)
		if len(got) != 1 {
			t.Fatalf("a zone `all` narrowed to `ssh` loses most of the expansion; want one advisory, got %d: %v", len(got), got)
		}
	})

	t.Run("silent on a lifeline interface", func(t *testing.T) {
		cfg := build([]string{"ssh"}, nil, []string{"ping"}, nil, "fxp0.0")
		if got := validateHostInboundOverrideReplaceWarnings(cfg); len(got) != 0 {
			t.Fatalf("fxp0 is excluded from host-inbound deny scoping, so nothing is lost there "+
				"and an advisory would be a false alarm; got: %v", got)
		}
	})

	t.Run("silent when the zone declares no stanza", func(t *testing.T) {
		cfg := build(nil, nil, []string{"ping"}, nil, "ge-0/0/9.0")
		cfg.Security.Zones["trust"].HostInboundTraffic = nil
		if got := validateHostInboundOverrideReplaceWarnings(cfg); len(got) != 0 {
			t.Fatalf("with no zone-level stanza there is nothing for the override to replace; got: %v", got)
		}
	})
}

// TestDuplicateHostLocalAddressGateUsesReplaceSemantics_6515 binds the #3718
// commit gate to the same resolver enforcement uses. The gate rejects a
// firewall-local address reachable from two zones with DIFFERING effective
// host-inbound sets, so it compares SIGNATURES — and a signature built from a
// different combination rule than the kernel chain uses compares the wrong sets.
// Reverting effectiveHostInboundSigLocal to a union left every other test in
// pkg/config green, which is what this test exists to stop.
//
// Fixture: 10.0.0.1 lives on ge-0/0/0.0 in zone `a` and on ge-0/0/1.0 in zone
// `b` (the #3718 shared-address topology). Zone `a` admits ssh with no
// interface stanza; zone `b` admits ping at the zone level but its interface
// declares `ssh`. Under REPLACE both sides resolve to {ssh} — one policy for the
// address, so the commit is accepted. Under a UNION zone `b` resolves to
// {ping, ssh} and the gate rejects a config that is in fact unambiguous.
func TestDuplicateHostLocalAddressGateUsesReplaceSemantics_6515(t *testing.T) {
	build := func(bIfaceSvc []string) *Config {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			}},
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			}},
		}
		cfg.Security.Zones = map[string]*ZoneConfig{
			"a": {
				Name:               "a",
				Interfaces:         []string{"ge-0/0/0.0"},
				HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
			},
			"b": {
				Name:               "b",
				Interfaces:         []string{"ge-0/0/1.0"},
				HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ping"}},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"ge-0/0/1.0": {SystemServices: bIfaceSvc},
				},
			},
		}
		return cfg
	}

	if err := validateDuplicateHostLocalAddressStrict(build([]string{"ssh"})); err != nil {
		t.Fatalf("both zones resolve 10.0.0.1 to {ssh} under replace semantics, so the address "+
			"has ONE host-inbound policy and the commit must be accepted; got: %v", err)
	}
	// Anti-vacuity: the gate must still fire when the two sides genuinely differ,
	// or the assertion above would be satisfied by a gate that never rejects.
	if err := validateDuplicateHostLocalAddressStrict(build([]string{"https"})); err == nil {
		t.Fatal("zone a resolves 10.0.0.1 to {ssh} and zone b to {https}: the address IS " +
			"host-inbound-ambiguous and the #3718 gate must reject it")
	}
}
