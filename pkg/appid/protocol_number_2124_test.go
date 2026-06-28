package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2124 — ProtocolNumber is the single source of truth for resolving a protocol
// name/alias/numeric string to its IANA number. These tests pin the table the
// userspace policy capability gate relies on to fail closed, and prove the
// (0, true) / (0, false) distinction that preserves a deliberate "protocol 0".

func TestProtocolNumberNamedSet(t *testing.T) {
	cases := map[string]uint8{
		"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "icmp6": 58,
		"gre": 47, "ospf": 89, "ipip": 4,
		"esp": 50, "ah": 51, "sctp": 132, "vrrp": 112,
		"igmp": 2, "pim": 103, "egp": 8,
		// Junos predefined aliases.
		"junos-tcp-any": 6, "junos-udp-any": 17, "junos-icmp-all": 1,
		"junos-ping": 1, "junos-icmp6-all": 58, "junos-pingv6": 58,
		"junos-gre": 47, "junos-ospf": 89, "junos-ip-in-ip": 4, "junos-ipip": 4,
		// Case-insensitive.
		"ESP": 50, "Sctp": 132,
	}
	for name, want := range cases {
		got, ok := ProtocolNumber(name)
		if !ok || got != want {
			t.Errorf("ProtocolNumber(%q) = (%d, %v), want (%d, true)", name, got, ok, want)
		}
	}
}

func TestProtocolNumberNumericAndProtocolZero(t *testing.T) {
	if n, ok := ProtocolNumber("0"); !ok || n != 0 {
		t.Errorf("ProtocolNumber(\"0\") = (%d, %v), want (0, true) — protocol 0/HOPOPT must be representable", n, ok)
	}
	if n, ok := ProtocolNumber("255"); !ok || n != 255 {
		t.Errorf("ProtocolNumber(\"255\") = (%d, %v), want (255, true)", n, ok)
	}
	if n, ok := ProtocolNumber("132"); !ok || n != 132 {
		t.Errorf("ProtocolNumber(\"132\") = (%d, %v), want (132, true)", n, ok)
	}
}

func TestProtocolNumberUnrepresentable(t *testing.T) {
	for _, name := range []string{"", "256", "-1", "bogus", "definitely-not-a-proto", "__unsupported__", "0x50"} {
		if n, ok := ProtocolNumber(name); ok {
			t.Errorf("ProtocolNumber(%q) = (%d, true), want ok=false (unrepresentable)", name, n)
		}
	}
}

// TestProtocolNumberParityWithCatalog ensures the catalog's protocol byte
// (catalogProtocolNumber) is exactly the uint8 of ProtocolNumber, so the
// app-id catalog and the capability gate never diverge (#2124 F3).
func TestProtocolNumberParityWithCatalog(t *testing.T) {
	names := []string{
		"tcp", "udp", "icmp", "icmpv6", "gre", "ospf", "ipip",
		"esp", "ah", "sctp", "vrrp", "igmp", "pim", "egp",
		"junos-tcp-any", "junos-udp-any", "junos-icmp-all", "junos-icmp6-all",
		"junos-gre", "junos-ospf", "junos-ip-in-ip",
		"0", "1", "47", "132", "255", "256", "", "bogus",
	}
	for _, name := range names {
		want, _ := ProtocolNumber(name)
		if got := catalogProtocolNumber(name); got != want {
			t.Errorf("catalogProtocolNumber(%q) = %d, ProtocolNumber = %d (divergence)", name, got, want)
		}
	}
}

// TestFilterProtocolResolvableMatchesProtocolNumber is the #2175 drift guard
// for the firewall-filter commit-check gate. The compiler's
// validateFilterProtocolsStrict resolves `from protocol <token>` via
// config.filterProtocolResolvable, which INLINE-duplicates the acceptance set
// of ProtocolNumber's ok==true result because pkg/appid imports pkg/config (so
// the compiler cannot call ProtocolNumber directly without an import cycle —
// the same constraint behind ApplicationsToValidateStrict / #2185). This test
// pins the two together: for every token, config.FilterProtocolResolvable must
// equal the ok bool of ProtocolNumber. If a future change to ProtocolNumber's
// table silently diverges from the compiler copy, this fails — turning a silent
// commit-gate drift (commit accepts a token the dataplane SSOT then drops, or
// rejects one it accepts) into a test failure. It is a cross-check TEST, not a
// runtime coupling.
func TestFilterProtocolResolvableMatchesProtocolNumber(t *testing.T) {
	tokens := []string{
		// L4 subset + broader named set.
		"tcp", "udp", "icmp", "icmpv6", "icmp6", "gre", "ospf", "ipip",
		"esp", "ah", "sctp", "vrrp", "igmp", "pim", "egp",
		// Junos predefined aliases.
		"junos-tcp-any", "junos-udp-any", "junos-icmp-all", "junos-ping",
		"junos-icmp6-all", "junos-pingv6", "junos-gre", "junos-ospf",
		"junos-ip-in-ip", "junos-ipip",
		// Case-insensitivity + whitespace trim.
		"ESP", "Sctp", " tcp ",
		// Numeric, including the deliberate "0" (HOPOPT) and the 0..255 bounds.
		"0", "1", "47", "132", "255",
		// Unrepresentable: out of range, malformed, junk, empty, and a
		// junos-* alias that ProtocolNumber does NOT resolve (validateProtocol
		// blanket-accepts any junos-* prefix, but the filter gate must not).
		"256", "-1", "0x50", "bogus", "definitely-not-a-proto", "",
		"junos-foobar",
	}
	for _, tok := range tokens {
		_, want := ProtocolNumber(tok)
		if got := config.FilterProtocolResolvable(tok); got != want {
			t.Errorf("FilterProtocolResolvable(%q) = %v, ProtocolNumber ok = %v (divergence)",
				tok, got, want)
		}
	}
}

// TestProtocolIsPortBearingMatchesDataplaneExtraction is the #3373 drift guard
// for the application-spec commit gate. config.protocolIsPortBearing INLINE-
// mirrors the set of protocols THIS dataplane extracts L4 ports for — the
// authoritative SSOT is userspace-dp/src/ip_proto.rs `has_l4_ports`, which is
// TCP (6) | UDP (17) ONLY (and inspect.rs parse_flow_ports reads port bytes only
// for those two). It is replicated in pkg/config because pkg/appid imports
// pkg/config (the import-cycle constraint behind FilterProtocolResolvable).
//
// This guard deliberately pins to the PORT-EXTRACTION set, NOT to
// appid.ProtocolNumber (a name→number resolver that says nothing about whether
// the dataplane reads ports for a protocol — e.g. it resolves sctp/132, which
// the dataplane does NOT port-extract). ProtocolNumber is used here only as the
// alias→number resolver so the test can express "token whose number is 6 or 17";
// the MEMBERSHIP set {6,17} is the has_l4_ports SSOT. If ip_proto.rs
// has_l4_ports changes (e.g. SCTP port support is added) the compiler copy must
// move in lockstep with the expected set below or this fails — turning a silent
// commit-gate drift into a test failure. Cross-check TEST, not a runtime
// coupling.
//
// dataplaneExtractsPorts mirrors ip_proto.rs has_l4_ports (TCP|UDP). Keep in
// sync with that predicate.
func dataplaneExtractsPorts(num uint8) bool {
	return num == 6 || num == 17 // ip_proto.rs has_l4_ports: PROTO_TCP | PROTO_UDP
}

func TestProtocolIsPortBearingMatchesDataplaneExtraction(t *testing.T) {
	tokens := []string{
		"tcp", "udp", "junos-tcp-any", "junos-udp-any",
		"sctp", // HAS wire ports but NOT extracted by this dataplane → not port-bearing
		"icmp", "icmpv6", "icmp6", "gre", "ospf", "ipip", "esp", "ah",
		"vrrp", "igmp", "pim", "egp",
		"junos-icmp-all", "junos-ping", "junos-icmp6-all", "junos-pingv6",
		"junos-gre", "junos-ospf", "junos-ip-in-ip", "junos-ipip",
		"TCP", "Sctp", " udp ",
		"0", "1", "6", "17", "47", "132", "136", "255",
		"256", "-1", "0x50", "bogus", "", "junos-foobar",
	}
	for _, tok := range tokens {
		num, ok := ProtocolNumber(tok)
		want := ok && dataplaneExtractsPorts(num)
		if got := config.ProtocolIsPortBearing(tok); got != want {
			t.Errorf("ProtocolIsPortBearing(%q) = %v, want %v (ProtocolNumber=%d ok=%v, has_l4_ports=%v)",
				tok, got, want, num, ok, ok && dataplaneExtractsPorts(num))
		}
	}
}
