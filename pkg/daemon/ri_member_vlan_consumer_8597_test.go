package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 K84/K85: the CONSUMERS of the vlan-id keying #8321 established.
//
// #8321 finding 07 fixed the PRODUCER of `connectedByLogical` to name an
// 802.1q sub-interface for its VLAN ID. It did not touch the consumers, which
// kept deriving their lookup key with config.LinuxIfName() — the UNIT number.
// So the producer writes `ge-0-0-1.100` and the consumers look up
// `ge-0-0-1.10`, and every VRF-scoped lookup misses.
//
// Its own cells cannot see this: TestStaticNextHopUsesVlanIDNotUnitNumber8321
// configures NO routing instance, so it exercises only the unscoped `""` VRF
// where the producer's key is consumed directly and no consumer-side
// re-derivation happens. The defect lives on the routing-instance path.
//
// Three consumer sites shared the assumption — riMemberLinuxName (the VRF bind
// name, K85), collectPrefixesForInterface (K84), and the claimedByVRF stamp,
// which appears in NEITHER row and was found by censusing the family.

// vlanRIConfig builds a routing instance whose member is a tagged unit where
// the unit number (10) and the VLAN ID (100) DIFFER. That inequality is the
// whole discriminator: with unit == vlan-id both implementations agree and the
// cell would pass against the defect.
func vlanRIConfig() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/1": {
					Units: map[int]*config.InterfaceUnit{
						10: {VlanID: 100, Addresses: []string{"2001:db8:aa::8/64"}},
					},
				},
			},
		},
		RoutingInstances: []*config.RoutingInstanceConfig{
			{
				Name:       "tenant",
				Interfaces: []string{"ge-0/0/1.10"},
				Inet6StaticRoutes: []*config.StaticRoute{
					{
						Destination: "2001:db8:ffff::/48",
						NextHops:    []config.NextHopEntry{{Address: "2001:db8:aa::1"}},
					},
				},
			},
		},
	}
}

// K85 (and the VRF bind site in bindRoutingInstanceMembers, which is where the
// harm lands): the member must resolve to the device networkd actually
// created. Resolving to `ge-0-0-1.10` makes BindInterfaceToVRF fail against a
// device that does not exist, while the commit reports success — so the member
// silently stays in the main table.
func TestRIMemberResolvesTaggedUnitByVlanID8597K85(t *testing.T) {
	cfg := vlanRIConfig()
	got := riMemberLinuxName(cfg, cfg.TunnelNameMap(), "ge-0/0/1.10")
	if got == "ge-0-0-1.10" {
		t.Fatalf("riMemberLinuxName = %q — named for the UNIT (10), not the VLAN ID (100). "+
			"networkd created ge-0-0-1.100, so the VRF bind fails against a nonexistent "+
			"device and the member stays in the main table on a SUCCESSFUL commit", got)
	}
	if got != "ge-0-0-1.100" {
		t.Fatalf("riMemberLinuxName = %q, want ge-0-0-1.100", got)
	}
}

// K84: the VRF-scoped connected prefix must be found, so a link-local-adjacent
// static next-hop inside the instance resolves to an interface. Before the fix
// collectPrefixesForInterface looked up `ge-0-0-1.10`, found nothing, and the
// next-hop was left without interface scope.
func TestVRFScopedStaticNextHopResolvesForTaggedUnit8597K84(t *testing.T) {
	got := inferIPv6StaticNextHopInterfaces(vlanRIConfig(), nil)
	iface := got["vrf-tenant"]["2001:db8:aa::1"]
	if iface == "" {
		t.Fatal("#8597 K84: the VRF-scoped next-hop resolved to NO interface — " +
			"collectPrefixesForInterface looked up the unit-numbered key " +
			"(ge-0-0-1.10) while the producer keyed the prefix by VLAN ID " +
			"(ge-0-0-1.100), so the prefix was invisible inside the instance")
	}
	if iface != "ge-0-0-1.100" {
		t.Fatalf("VRF-scoped next-hop interface = %q, want ge-0-0-1.100", iface)
	}
}

// THE CONTROL, and it is what stops this from being a blanket
// unit-number->vlan-id substitution. A unit with NO vlan-id is not a tagged
// sub-interface and `base.<unit>` is the correct device there. Replacing the
// field outright would pass both cells above and break every untagged unit;
// this is the cell that catches that.
func TestUntaggedRIMemberStillUsesUnitNumber8597(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/2": {
					Units: map[int]*config.InterfaceUnit{
						7: {Addresses: []string{"2001:db8:bb::8/64"}},
						0: {Addresses: []string{"2001:db8:cc::8/64"}},
					},
				},
			},
		},
		RoutingInstances: []*config.RoutingInstanceConfig{
			{
				Name:       "tenant",
				Interfaces: []string{"ge-0/0/2.7"},
				Inet6StaticRoutes: []*config.StaticRoute{
					{
						Destination: "2001:db8:ffff::/48",
						NextHops:    []config.NextHopEntry{{Address: "2001:db8:bb::1"}},
					},
				},
			},
		},
	}
	if got := riMemberLinuxName(cfg, cfg.TunnelNameMap(), "ge-0/0/2.7"); got != "ge-0-0-2.7" {
		t.Fatalf("untagged unit 7 resolved to %q, want ge-0-0-2.7 — a unit with no "+
			"vlan-id is not a tagged sub-interface and must keep its unit-numbered "+
			"device name", got)
	}
	// Unit-0 collapse, previously performed by a `.0` suffix strip.
	if got := riMemberLinuxName(cfg, cfg.TunnelNameMap(), "ge-0/0/2.0"); got != "ge-0-0-2" {
		t.Fatalf("unit 0 resolved to %q, want ge-0-0-2 (unit-0 collapse)", got)
	}
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	if iface := got["vrf-tenant"]["2001:db8:bb::1"]; iface != "ge-0-0-2.7" {
		t.Fatalf("untagged VRF-scoped next-hop = %q, want ge-0-0-2.7", iface)
	}
}

// The producer and the consumers must agree BY CONSTRUCTION, not by two
// literals a future edit can drift apart. Asserting the agreement rather than
// the string is what survives someone changing the convention on purpose.
func TestProducerAndConsumerKeysAgree8597(t *testing.T) {
	cfg := vlanRIConfig()
	unit := cfg.Interfaces.Interfaces["ge-0/0/1"].Units[10]
	producer := logicalUnitDeviceKey(config.LinuxIfName("ge-0/0/1"), 10, unit)
	consumer := logicalUnitDeviceKeyForRef(cfg, "ge-0/0/1.10")
	if producer != consumer {
		t.Fatalf("producer key %q != consumer key %q — the two sides of the "+
			"connected-prefix map disagree, which is the #8321 residue itself", producer, consumer)
	}
}

// THE THIRD SITE — named in neither K84 nor K85, and the reason the census
// mattered. `claimedByVRF` records which interfaces a routing instance owns so
// their prefixes are REMOVED from the global (unscoped) candidate list. Keyed
// by the unit number it never matches a tagged unit's producer-keyed prefix,
// so a VRF-owned interface stays visible to the global table and a GLOBAL
// static next-hop resolves to an interface that belongs to a tenant VRF —
// cross-instance leakage, not merely a missing route.
//
// Mutation-found: reverting only this site left every other cell in this file
// green.
func TestVRFClaimedTaggedUnitIsRemovedFromGlobalCandidates8597(t *testing.T) {
	cfg := vlanRIConfig()
	// A GLOBAL inet6 static route whose next-hop sits inside the tagged unit's
	// prefix. The unit belongs to instance "tenant", so the global table must
	// NOT resolve it.
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
		{
			Destination: "2001:db8:eeee::/48",
			NextHops:    []config.NextHopEntry{{Address: "2001:db8:aa::1"}},
		},
	}
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	if iface := got[""]["2001:db8:aa::1"]; iface != "" {
		t.Fatalf("global next-hop resolved to %q, want no resolution: ge-0-0-1.100 is "+
			"claimed by instance \"tenant\", so its prefix must be filtered out of the "+
			"global candidate list. claimedByVRF keyed the unit number (ge-0-0-1.10) "+
			"and never matched the producer's vlan-keyed prefix, leaking a "+
			"VRF-owned interface into global resolution", iface)
	}
	// The instance itself must still resolve it — proving the filter removed the
	// prefix from the GLOBAL list only, and did not simply delete it.
	if iface := got["vrf-tenant"]["2001:db8:aa::1"]; iface != "ge-0-0-1.100" {
		t.Fatalf("VRF-scoped resolution = %q, want ge-0-0-1.100 — the filter must scope "+
			"the prefix, not drop it", iface)
	}
}
