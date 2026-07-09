package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #4792 RED-on-revert: zoneIfaces (and the resolveEgressIfaces zone
// fallback) previously stored only the FIRST interface bound to a zone
// (map[uint16]string, populateIfaceMaps did `zoneIfaces[zid] =
// zone.Interfaces[0]`). A zone bound to MULTIPLE interfaces (e.g. a trust
// zone spanning ge-0/0/0 and ge-0/0/2) silently lost visibility into any
// session ingressing/egressing on the 2nd+ interface: `show security flow
// session interface ge-0/0/2` (or the matching `clear`) matched nothing for
// those sessions even though they genuinely belong to that zone/interface.
//
// The fix widens zoneIfaces to map[uint16][]string (every interface bound
// to the zone) and matches when the session's interface is ANY of them.
func TestMatchesV4_MultiInterfaceZone_MatchesSecondInterface(t *testing.T) {
	// Zone 1 (trust) spans TWO interfaces: ge-0/0/0 and ge-0/0/2.
	zoneIfaces := map[uint16][]string{
		1: {"ge-0/0/0", "ge-0/0/2"},
		2: {"ge-0/0/1"},
	}

	t.Run("matches ingress on the zone's second interface", func(t *testing.T) {
		f := &sessionFilter{
			iface:      "ge-0/0/2",
			zoneIfaces: zoneIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		// No FIB egress info (FibIfindex 0) so only the ingress-zone match
		// can pass this session — proving the ingress-side fix specifically.
		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2}
		if !f.matchesV4(key, val) {
			t.Error("expected match on ge-0/0/2, the zone's SECOND interface " +
				"(#4792: a single-interface zoneIfaces map drops every " +
				"interface but the first)")
		}
	})

	t.Run("still matches ingress on the zone's first interface", func(t *testing.T) {
		f := &sessionFilter{
			iface:      "ge-0/0/0",
			zoneIfaces: zoneIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2}
		if !f.matchesV4(key, val) {
			t.Error("expected match on ge-0/0/0, the zone's first interface (no regression)")
		}
	})

	t.Run("no match for an interface outside the zone", func(t *testing.T) {
		f := &sessionFilter{
			iface:      "ge-0/0/9",
			zoneIfaces: zoneIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2}
		if f.matchesV4(key, val) {
			t.Error("expected no match for an interface not bound to either zone")
		}
	})

	t.Run("matches egress zone fallback on the second interface", func(t *testing.T) {
		f := &sessionFilter{
			iface:      "ge-0/0/2",
			zoneIfaces: zoneIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		// Ingress zone 2 does not carry ge-0/0/2; only the egress zone (1,
		// via the zoneIfaces fallback when FIB lookup is unavailable) does.
		val := dataplane.SessionValue{IngressZone: 2, EgressZone: 1}
		if !f.matchesV4(key, val) {
			t.Error("expected match via egress-zone fallback on ge-0/0/2, the " +
				"zone's second interface (#4792)")
		}
	})
}

// TestMatchesV6_MultiInterfaceZone_MatchesSecondInterface mirrors the V4
// case for the IPv6 session path (matchesV6 has the identical bug).
func TestMatchesV6_MultiInterfaceZone_MatchesSecondInterface(t *testing.T) {
	zoneIfaces := map[uint16][]string{
		1: {"ge-0/0/0", "ge-0/0/2"},
	}
	f := &sessionFilter{
		iface:      "ge-0/0/2",
		zoneIfaces: zoneIfaces,
	}
	key := dataplane.SessionKeyV6{Protocol: 6}
	val := dataplane.SessionValueV6{IngressZone: 1, EgressZone: 1}
	if !f.matchesV6(key, val) {
		t.Error("expected v6 match on ge-0/0/2, the zone's second interface (#4792)")
	}
}
