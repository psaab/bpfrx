package config

import "testing"

// #5250 (A3-b2 F3). HostInboundLifelineInterface's unconditional fabric arm was
// `strings.HasPrefix(base, "fab")`, so EVERY name starting with "fab" bought an
// unconditional host-inbound deny exemption. That exemption is enforcement, not
// display: junosHostNonLifelineRefs and JunosHostZoneIngressNetdevs both SKIP a
// lifeline, so a `deny` policy toward junos-host on such an interface produced
// no kernel rule at all.
//
// The only fabric devices that exist are fab0/fab1 (the daemon's IPVLANs, and
// the config interfaces that carry `fabric-options member-interfaces`), so the
// arm is now `fab` + digits. Anything else must be DECLARED as a
// chassis-cluster fabric/control interface to stay exempt — the #3277 path,
// which this test also pins.
func TestLifelineFabricArmIsExactShaped(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
		why  string
	}{
		{"fab0", true, "the primary fabric IPVLAN"},
		{"fab1", true, "the secondary fabric IPVLAN (#4038)"},
		{"fab0.0", true, "unit suffix is stripped before matching"},
		{"fab10", true, "a multi-digit fabric index is still a fabric device"},
		{"em0", true, "the em0 arm is exact and unchanged"},

		{"fab-foo", false, "a hyphenated name is not a fabric device"},
		{"fabric", false, "an interface literally named fabric is an ordinary NIC"},
		{"fabX", false, "a non-digit suffix is not a fabric index"},
		{"fab", false, "bare `fab` names no device"},
		{"fab0x", false, "trailing non-digits are not a fabric index"},
		{"fab_0", false, "an underscore is not a digit"},
		{"em1", false, "the em arm never was a prefix"},
	} {
		if got := HostInboundLifelineInterface(tc.name, nil); got != tc.want {
			t.Errorf("HostInboundLifelineInterface(%q) = %v, want %v — %s",
				tc.name, got, tc.want, tc.why)
		}
	}
}

// A fabric interface under a non-fab<N> name is still exempt when the config
// DECLARES it, so narrowing the unconditional arm did not regress #3277.
func TestLifelineDeclaredFabricNameStaysExempt(t *testing.T) {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{
		ControlInterface: "fxp1",
		FabricInterface:  "fab-foo",
	}
	set := HostInboundLifelineSet(cfg)

	for _, name := range []string{"fab-foo", "fab-foo.0", "fxp1", "fxp1.0"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("%q is a DECLARED chassis-cluster interface and must stay a lifeline", name)
		}
	}
	// The same name with nothing declaring it is NOT a lifeline — that is the
	// whole delta this fix introduces.
	if HostInboundLifelineInterface("fab-foo", nil) {
		t.Error("an UNDECLARED fab-foo must not be a lifeline")
	}
}

// The production gate, not just the predicate: a zone whose interface is named
// fab-guest and carries a junos-host deny must now produce a kernel ingress
// netdev and a rendered policy. Before the fix the lifeline skip in
// JunosHostZoneIngressNetdevs/junosHostNonLifelineRefs dropped it silently, so
// the deny was accepted at commit and enforced nowhere.
func TestUndeclaredFabNameIsHostInboundEnforced(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"fab-guest": {Name: "fab-guest", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.9.9.1/24"}},
		}},
		"fab0": {Name: "fab0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.99.0.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"guest": {Name: "guest", Interfaces: []string{"fab-guest.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"fabzone": {Name: "fabzone", Interfaces: []string{"fab0.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"bad-net": {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "guest", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("block-guest", []string{"bad-net"}, []string{"any"})}},
		{FromZone: "fabzone", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("block-fab", []string{"bad-net"}, []string{"any"})}},
	}

	nd := JunosHostZoneIngressNetdevs(cfg)
	if got := nd["guest"]; len(got) == 0 {
		t.Fatalf("zone guest on fab-guest.0 must contribute an ingress netdev; got %v — "+
			"the HasPrefix(\"fab\") lifeline skip is back and the deny enforces nowhere", got)
	}
	// fab0 is a real fabric device and keeps its exemption.
	if got := nd["fabzone"]; len(got) != 0 {
		t.Errorf("zone fabzone on fab0.0 is a LIFELINE and must contribute no ingress netdev, got %v", got)
	}

	proj := BuildJunosHostDenyProjection(cfg)
	if !proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("guest", "block-guest")] {
		t.Error("the fab-guest deny must render a kernel rule")
	}
	if proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("fabzone", "block-fab")] {
		t.Error("the fab0 deny targets a lifeline and must NOT render")
	}
}
