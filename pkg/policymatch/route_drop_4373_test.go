package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRouteDropBeforePolicyStamped is the #4373 (E4/H2/H7) regression: a
// TRANSIT query whose DESTINATION is a class the forwarding path drops at route
// lookup BEFORE the policy engine runs (multicast / limited broadcast /
// unspecified / loopback) must carry the route-drop advisory on the Result, so
// no match-policies surface over-promises forwarding for a destination the
// dataplane never routes to policy. The advisory is additive — it does NOT
// change the permit/deny verdict — and rides EVERY verdict path (a positive
// match AND the default-policy fall-through).
//
// RED-on-revert: drop the Match() route-drop stamping (or the routeDropClass
// helper) and RouteDropBeforePolicy is false / RouteDropClass is "" /
// RouteDropNote is "" for the multicast, broadcast, unspecified, and loopback
// destinations below — the verdict is then indistinguishable from a normal
// forwarded flow.
func TestRouteDropBeforePolicyStamped(t *testing.T) {
	// trust -> untrust permits everything; the verdict is a positive permit so
	// the advisory must ride a MATCHED result, not only a default one.
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-any", config.PolicyMatch{})),
		},
	}, config.ApplicationsConfig{})

	cases := []struct {
		name      string
		dst       net.IP
		wantClass string
	}{
		{"ipv4-multicast", net.ParseIP("224.0.0.5"), "multicast"},
		{"ipv6-multicast", net.ParseIP("ff02::1"), "multicast"},
		{"ipv4-broadcast", net.ParseIP("255.255.255.255"), "broadcast"},
		{"ipv4-unspecified", net.ParseIP("0.0.0.0"), "unspecified"},
		{"ipv6-unspecified", net.ParseIP("::"), "unspecified"},
		{"ipv4-loopback", net.ParseIP("127.0.0.1"), "loopback"},
		{"ipv6-loopback", net.ParseIP("::1"), "loopback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", DstIP: tc.dst})
			// The verdict itself is unchanged: the rule still matches permit.
			if !res.Matched || res.Action != config.PolicyPermit {
				t.Fatalf("verdict changed: got Matched=%v Action=%v, want matched permit", res.Matched, res.Action)
			}
			if !res.RouteDropBeforePolicy {
				t.Fatalf("RouteDropBeforePolicy = false, want true for %s dst %s", tc.wantClass, tc.dst)
			}
			if res.RouteDropClass != tc.wantClass {
				t.Fatalf("RouteDropClass = %q, want %q", res.RouteDropClass, tc.wantClass)
			}
			note := res.RouteDropNote()
			if !strings.HasPrefix(note, RouteDropNotePrefix) {
				t.Fatalf("RouteDropNote %q missing SSOT prefix %q", note, RouteDropNotePrefix)
			}
			if !strings.Contains(note, tc.wantClass) {
				t.Fatalf("RouteDropNote %q does not name class %q", note, tc.wantClass)
			}
			if !strings.Contains(note, "route lookup") {
				t.Fatalf("RouteDropNote %q must state the packet is dropped at route lookup", note)
			}
		})
	}
}

// TestRouteDropAdvisoryOnDefaultVerdict proves the advisory also rides the
// default-policy fall-through (no matching policy): a multicast destination in
// an empty policy set still reports the route-drop caveat next to the default
// deny, so the operator does not read the default verdict as a real forward
// either.
func TestRouteDropAdvisoryOnDefaultVerdict(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{DefaultPolicy: config.PolicyDeny}, config.ApplicationsConfig{})
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", DstIP: net.ParseIP("239.1.2.3")})
	if res.Matched {
		t.Fatalf("expected default (no match), got matched %+v", res)
	}
	if !res.RouteDropBeforePolicy || res.RouteDropClass != "multicast" {
		t.Fatalf("default verdict missing multicast route-drop advisory: %+v", res)
	}
	if res.RouteDropNote() == "" {
		t.Fatalf("default verdict RouteDropNote is empty, want the SSOT advisory")
	}
}

// TestRouteDropNotAppliedToUnicastOrHost pins the two exemptions: an ordinary
// unicast transit destination reaches the policy engine (no advisory), and a
// host-bound (junos-host) query takes the local-delivery gate rather than the
// transit route lookup, so it is NEVER stamped even for a multicast dst (which
// cannot be host-bound in practice, but the exemption must be structural). A
// nil destination — the "unspecified destination" simulator wildcard — must NOT
// be classified as the 0.0.0.0 unspecified address.
func TestRouteDropNotAppliedToUnicastOrHost(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-any", config.PolicyMatch{})),
		},
	}, config.ApplicationsConfig{})

	// Ordinary unicast dst: reaches policy, no advisory.
	uni := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", DstIP: net.ParseIP("10.0.2.7")})
	if uni.RouteDropBeforePolicy || uni.RouteDropClass != "" || uni.RouteDropNote() != "" {
		t.Fatalf("unicast dst wrongly flagged as route-drop: %+v", uni)
	}

	// nil dst (operator omitted the destination): the unspecified-address
	// classifier must NOT fire — omitted != 0.0.0.0.
	nilDst := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"})
	if nilDst.RouteDropBeforePolicy {
		t.Fatalf("nil dst wrongly classified as route-drop: %+v", nilDst)
	}

	// Host-bound query with a multicast dst: exempt (host path, not transit
	// route lookup).
	host := Match(cfg, Query{FromZone: "trust", ToZone: JunosHostZone, DstIP: net.ParseIP("224.0.0.5")})
	if host.RouteDropBeforePolicy {
		t.Fatalf("host-bound query wrongly stamped with transit route-drop: %+v", host)
	}
}
