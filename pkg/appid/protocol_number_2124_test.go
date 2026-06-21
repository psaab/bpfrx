package appid

import "testing"

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
