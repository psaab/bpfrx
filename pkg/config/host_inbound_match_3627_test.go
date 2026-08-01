package config

import (
	"fmt"
	"strconv"
	"testing"
)

// TestHostInboundServiceMatchTuples pins the structured token->tuple SSOT
// (#3627 B1a) for representative system-services: the proto/port/icmp truth the
// nft builder renders from and the match-policies host-inbound classifier
// matches against. Fail-on-revert: change a port here (or drop a tuple) and both
// the render golden and the classifier tests move with it — this test names the
// canonical value so a reviewer sees the intended tuple, not just a diff.
func TestHostInboundServiceMatchTuples(t *testing.T) {
	u8 := func(v uint8) *uint8 { return &v }
	single := func(p uint16) []PortRange { return []PortRange{{Lo: p, Hi: p}} }

	cases := []struct {
		token  string
		family string
		want   []L4Match
	}{
		{"ssh", "ip", []L4Match{{Proto: HostInboundProtoTCP, Ports: single(22)}}},
		{"ssh", "ip6", []L4Match{{Proto: HostInboundProtoTCP, Ports: single(22)}}},
		{"https", "ip", []L4Match{{Proto: HostInboundProtoTCP, Ports: single(443)}}},
		{"dns", "ip", []L4Match{
			{Proto: HostInboundProtoUDP, Ports: single(53)},
			{Proto: HostInboundProtoTCP, Ports: single(53)},
		}},
		// ping: echo-request only, family-specific ICMP type (v4 8 / v6 128).
		{"ping", "ip", []L4Match{{Proto: HostInboundProtoICMP, ICMPType: u8(8)}}},
		{"ping", "ip6", []L4Match{{Proto: HostInboundProtoICMPv6, ICMPType: u8(128)}}},
		// dhcp is IPv4-only (family gate).
		{"dhcp", "ip", []L4Match{{Proto: HostInboundProtoUDP, Ports: []PortRange{{67, 67}, {68, 68}}}}},
		{"dhcp", "ip6", nil},
		{"dhcpv6", "ip", nil},
		{"dhcpv6", "ip6", []L4Match{{Proto: HostInboundProtoUDP, Ports: []PortRange{{546, 546}, {547, 547}}}}},
		// traceroute is a contiguous UDP range.
		{"traceroute", "ip", []L4Match{{Proto: HostInboundProtoUDP, Ports: []PortRange{{33434, 33523}}}}},
		// gre is a bare IP protocol number.
		{"gre", "ip", []L4Match{{Proto: 47}}},
		// ident-reset carries the Reject marker (resets, does NOT admit).
		{"ident-reset", "ip", []L4Match{{Proto: HostInboundProtoTCP, Ports: single(113), Reject: true}}},
		// the `any-service` full-admit and unknown tokens are not per-tuple
		// matches. #3226: `all` IS one now — it expands to the named-service
		// union, asserted separately below.
		{"any-service", "ip", nil},
		{"sssh", "ip", nil},
	}
	for _, c := range cases {
		got := HostInboundServiceMatch(c.token, c.family)
		if !equalL4(got, c.want) {
			t.Errorf("HostInboundServiceMatch(%q,%q) = %s, want %s", c.token, c.family, showL4(got), showL4(c.want))
		}
	}

	// #3226: `any-service` is the ONLY full-admit token. `all` expands to the
	// named-service union (HostInboundAllExpansionServices) — it is a per-tuple
	// match set, so treating it as a full admit would restore the packet-wide
	// over-admit the issue closed.
	if !HostInboundFullAdmitService("any-service") {
		t.Errorf("any-service must be a full-admit service")
	}
	if HostInboundFullAdmitService("all") {
		t.Errorf("all must NOT be a full-admit service (#3226 — it expands to the named system-service union)")
	}
	// What `system-services all` actually OPENS, pinned against a hard-coded
	// literal.
	//
	// This replaces an assertion that rebuilt the expected value by iterating
	// HostInboundAllExpansionServices() and concatenating
	// HostInboundServiceMatch(tok, fam) — which is character-for-character what
	// production's `all` branch does, so it compared the implementation with
	// itself and would have passed through any change to either. (Its comment
	// claimed to be "derived independently"; it was not.)
	//
	// The oracle below is a human-maintained list of the atomic (proto, port)
	// openings `all` grants. It is independent of how the expansion is computed,
	// so it REDs on a token entering or leaving the union, on a port move, and on
	// a family-scoping change — none of which the old form could see. The
	// traceroute probe range is collapsed out and asserted separately, because 90
	// consecutive ports would swamp the literal without adding signal.
	const tracerouteLo, tracerouteHi = 33434, 33523
	wantOpenings := map[string][]string{
		// IPv4: dhcp/bootp (67,68) present, dhcpv6 absent, ping = ICMP echo type 8.
		"ip": {
			"1/type8", "17/123", "17/161", "17/162", "17/3503", "17/4500",
			"17/500", "17/5060", "17/53", "17/67", "17/68", "17/69", "17/8503",
			"6/21", "6/22", "6/23", "6/2900", "6/2901", "6/3220", "6/3221",
			"6/443", "6/5060", "6/513", "6/514", "6/53", "6/79", "6/80", "6/830",
			"reject:6/113",
		},
		// IPv6: dhcpv6 (546,547) present, dhcp/bootp absent, ping = ICMPv6 type 128.
		"ip6": {
			"17/123", "17/161", "17/162", "17/3503", "17/4500", "17/500",
			"17/5060", "17/53", "17/546", "17/547", "17/69", "17/8503",
			"58/type128", "6/21", "6/22", "6/23", "6/2900", "6/2901", "6/3220",
			"6/3221", "6/443", "6/5060", "6/513", "6/514", "6/53", "6/79",
			"6/80", "6/830", "reject:6/113",
		},
	}
	for _, fam := range []string{"ip", "ip6"} {
		got := map[string]bool{}
		for _, m := range HostInboundServiceMatch("all", fam) {
			for _, k := range hiOpeningKeys(m) {
				got[k] = true
			}
		}
		if len(got) == 0 {
			t.Fatalf("`all` opened NOTHING for family %q — contract would be vacuous", fam)
		}
		// Peel off the traceroute range and assert it exactly.
		for p := tracerouteLo; p <= tracerouteHi; p++ {
			k := fmt.Sprintf("17/%d", p)
			if !got[k] {
				t.Errorf("`all` (%s) is missing traceroute probe port udp/%d", fam, p)
			}
			delete(got, k)
		}
		for _, edge := range []int{tracerouteLo - 1, tracerouteHi + 1} {
			if got[fmt.Sprintf("17/%d", edge)] {
				t.Errorf("`all` (%s) opens udp/%d, outside the traceroute probe range %d-%d",
					fam, edge, tracerouteLo, tracerouteHi)
			}
		}
		want := map[string]bool{}
		for _, k := range wantOpenings[fam] {
			want[k] = true
		}
		for k := range want {
			if !got[k] {
				t.Errorf("`system-services all` (%s) no longer opens %s — a service left the "+
					"union, moved port, or changed family scoping", fam, k)
			}
		}
		for k := range got {
			if !want[k] {
				t.Errorf("`system-services all` (%s) now opens %s, which the pinned union does "+
					"NOT — a service entered the union or widened its ports (#3226)", fam, k)
			}
		}
	}
	// The expansion excludes the meta tokens and the xpf-only extensions.
	for _, tok := range HostInboundAllExpansionServices() {
		if tok == "all" || tok == "any-service" {
			t.Errorf("`all` expansion must not contain the meta token %q (recursion / semantics)", tok)
		}
		if HostInboundNonJunosSystemServices[tok] {
			t.Errorf("`all` expansion must not contain the xpf-only token %q (#3226)", tok)
		}
	}
	// gre is a recognized token that is nonetheless excluded — the exclusion set
	// is load-bearing, not decorative.
	if !KnownHostInboundSystemServices["gre"] {
		t.Errorf("gre must stay a recognized system-service (so the `all` exclusion is meaningful)")
	}
	if got := HostInboundServiceMatch("gre", "ip"); len(got) == 0 {
		t.Errorf("an EXPLICIT `system-services gre` must still match IP protocol 47")
	}
	if HostInboundFullAdmitService("ssh") {
		t.Errorf("ssh must NOT be a full-admit service")
	}
}

// TestHostInboundProtocolMatchTuples pins representative protocol tuples,
// including the family gating (ospf v4 / ospf3 v6, igmp/dvmrp v4-only), the L2
// no-op (isis), and the router-discovery two-ICMP-type v4 match. It also asserts
// `protocols all` expands to the routing set and admits a real IP protocol (bgp)
// while EXCLUDING the L2 protocol (isis) and every full system-service (ssh).
func TestHostInboundProtocolMatchTuples(t *testing.T) {
	u8 := func(v uint8) *uint8 { return &v }
	single := func(p uint16) []PortRange { return []PortRange{{Lo: p, Hi: p}} }

	cases := []struct {
		token  string
		family string
		want   []L4Match
	}{
		{"bgp", "ip", []L4Match{{Proto: HostInboundProtoTCP, Ports: single(179)}}},
		{"ospf", "ip", []L4Match{{Proto: 89}}},
		{"ospf", "ip6", nil},
		{"ospf3", "ip", nil},
		{"ospf3", "ip6", []L4Match{{Proto: 89}}},
		{"igmp", "ip", []L4Match{{Proto: 2}}},
		{"igmp", "ip6", nil},
		{"dvmrp", "ip", []L4Match{{Proto: 2}}},
		{"dvmrp", "ip6", nil},
		{"bfd", "ip", []L4Match{{Proto: HostInboundProtoUDP, Ports: []PortRange{{3784, 3784}, {3785, 3785}, {4784, 4784}}}}},
		{"isis", "ip", nil},
		{"isis", "ip6", nil},
		{"router-discovery", "ip", []L4Match{
			{Proto: HostInboundProtoICMP, ICMPType: u8(9)},
			{Proto: HostInboundProtoICMP, ICMPType: u8(10)},
		}},
		{"router-discovery", "ip6", nil},
	}
	for _, c := range cases {
		got := HostInboundProtocolMatch(c.token, c.family)
		if !equalL4(got, c.want) {
			t.Errorf("HostInboundProtocolMatch(%q,%q) = %s, want %s", c.token, c.family, showL4(got), showL4(c.want))
		}
	}

	// `protocols all` includes bgp (tcp/179) and excludes isis (L2). It must
	// never open a system-service like ssh.
	all := HostInboundProtocolMatch("all", "ip")
	if !containsL4(all, L4Match{Proto: HostInboundProtoTCP, Ports: single(179)}) {
		t.Errorf("protocols all (ip) must expand to include bgp tcp/179; got %s", showL4(all))
	}
	if containsL4(all, L4Match{Proto: HostInboundProtoTCP, Ports: single(22)}) {
		t.Errorf("protocols all must NOT open ssh tcp/22 (routing protocols only, #3199)")
	}
}

func equalL4(a, b []L4Match) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !l4Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func l4Equal(a, b L4Match) bool {
	if a.Proto != b.Proto || a.Reject != b.Reject {
		return false
	}
	if len(a.Ports) != len(b.Ports) {
		return false
	}
	for i := range a.Ports {
		if a.Ports[i] != b.Ports[i] {
			return false
		}
	}
	switch {
	case a.ICMPType == nil && b.ICMPType == nil:
		return true
	case a.ICMPType == nil || b.ICMPType == nil:
		return false
	default:
		return *a.ICMPType == *b.ICMPType
	}
}

func containsL4(set []L4Match, want L4Match) bool {
	for _, m := range set {
		if l4Equal(m, want) {
			return true
		}
	}
	return false
}

func showL4(ms []L4Match) string {
	if ms == nil {
		return "nil"
	}
	out := "["
	for i, m := range ms {
		if i > 0 {
			out += " "
		}
		out += l4String(m)
	}
	return out + "]"
}

func l4String(m L4Match) string {
	s := "proto=" + strconv.Itoa(int(m.Proto))
	for _, p := range m.Ports {
		if p.Lo == p.Hi {
			s += "/" + strconv.Itoa(int(p.Lo))
		} else {
			s += "/" + strconv.Itoa(int(p.Lo)) + "-" + strconv.Itoa(int(p.Hi))
		}
	}
	if m.ICMPType != nil {
		s += "/icmp" + strconv.Itoa(int(*m.ICMPType))
	}
	if m.Reject {
		s += "/reject"
	}
	return s
}
