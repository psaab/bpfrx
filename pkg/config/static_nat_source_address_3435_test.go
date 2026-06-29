package config

import "testing"

// TestStaticNATSourceAddressSingle anchors #3435: a static-NAT rule's `match
// source-address` is compiled onto both the singular SourceAddress (back-compat,
// e.g. the NAT64 "::/0" readers) and the full SourceAddresses list.
func TestStaticNATSourceAddressSingle(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set rs1 rule r1 match source-address 198.51.100.0/24",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	})
	if len(cfg.Security.NAT.Static) != 1 || len(cfg.Security.NAT.Static[0].Rules) != 1 {
		t.Fatalf("expected 1 static NAT rule-set with 1 rule, got %+v", cfg.Security.NAT.Static)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if got := rule.SourceAddresses; len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("SourceAddresses = %v, want [198.51.100.0/24]", got)
	}
	if rule.SourceAddress != "198.51.100.0/24" {
		t.Fatalf("SourceAddress (back-compat) = %q, want 198.51.100.0/24", rule.SourceAddress)
	}
}

// TestStaticNATSourceAddressBracketList is the M02 regression: a bracketed /
// repeated `match source-address` list must retain EVERY prefix. Before #3435
// the value was read with nodeVal, which kept only the first entry — so a
// multi-prefix source scope silently lost its tail. Reverting compileNATStatic
// to the scalar read makes this fail (len != 3).
func TestStaticNATSourceAddressBracketList(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set rs1 rule r1 match source-address [ 198.51.100.0/24 203.0.113.200/32 192.0.2.0/24 ]",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	})
	rule := cfg.Security.NAT.Static[0].Rules[0]
	want := []string{"198.51.100.0/24", "203.0.113.200/32", "192.0.2.0/24"}
	if len(rule.SourceAddresses) != len(want) {
		t.Fatalf("SourceAddresses = %v, want %v (M02 list-tail drop)", rule.SourceAddresses, want)
	}
	for i, w := range want {
		if rule.SourceAddresses[i] != w {
			t.Fatalf("SourceAddresses[%d] = %q, want %q", i, rule.SourceAddresses[i], w)
		}
	}
	// Singular field keeps the first element for back-compat.
	if rule.SourceAddress != want[0] {
		t.Fatalf("SourceAddress = %q, want %q", rule.SourceAddress, want[0])
	}
}
