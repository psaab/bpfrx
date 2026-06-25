package config

import (
	"strings"
	"testing"
)

// TestStaticNATMappedPortCompiles is the #2491 config half: a static-NAT rule
// with `match destination-port` + `then static-nat prefix <ip> mapped-port
// <port>` must compile both fields onto the StaticNATRule.
//
// Fail-on-revert: dropping the `destination-port` / `mapped-port` parse in
// compileNATStatic (or the staticNATMappedPortFromKeys helper) leaves both
// fields at 0 and this test goes RED.
func TestStaticNATMappedPortCompiles(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		"set security nat static rule-set rs1 rule r1 match destination-port 8080",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 80",
	})

	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static NAT rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rs := cfg.Security.NAT.Static[0]
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}
	rule := rs.Rules[0]
	if rule.Match != "203.0.113.1/32" {
		t.Fatalf("Match = %q, want 203.0.113.1/32", rule.Match)
	}
	if rule.Then != "10.0.0.5/32" {
		t.Fatalf("Then = %q, want 10.0.0.5/32", rule.Then)
	}
	if rule.MatchDestinationPort != 8080 {
		t.Fatalf("MatchDestinationPort = %d, want 8080", rule.MatchDestinationPort)
	}
	if rule.MappedPort != 80 {
		t.Fatalf("MappedPort = %d, want 80", rule.MappedPort)
	}
}

// TestStaticNATWholeAddressNoPort confirms the legacy whole-address 1:1 rule
// still compiles with zero ports (no port match, no port translation).
func TestStaticNATWholeAddressNoPort(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	})
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.MatchDestinationPort != 0 || rule.MappedPort != 0 {
		t.Fatalf("whole-address rule must carry 0 ports, got match=%d mapped=%d",
			rule.MatchDestinationPort, rule.MappedPort)
	}
}

// TestStaticNATMappedPortOutOfRangeRejected is the fail-closed half: an
// out-of-range mapped-port (the token rides inside the children:nil static-nat
// leaf, bypassing the schema value validator) is rejected at strict
// commit-check by validateNATHostMaskStrict.
func TestStaticNATMappedPortOutOfRangeRejected(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		"set security nat static rule-set rs1 rule r1 match destination-port 8080",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 70000",
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	// Strict commit-check (run inside CompileConfig) must reject the
	// out-of-range mapped-port. Reverting the range guard in
	// validateNATHostMaskStrict makes CompileConfig succeed → RED.
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected CompileConfig to reject mapped-port 70000")
	}
	if !strings.Contains(err.Error(), "mapped-port") {
		t.Fatalf("error must mention mapped-port, got %v", err)
	}
}

// TestStaticNATMappedPortWithoutMatchPortRejected: a mapped-port with no
// `match destination-port` has no inbound trigger and the reverse SNAT cannot
// recover the original port, so strict commit-check rejects it.
func TestStaticNATMappedPortWithoutMatchPortRejected(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 80",
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected CompileConfig to reject mapped-port without match destination-port")
	}
	if !strings.Contains(err.Error(), "requires a matching") {
		t.Fatalf("error must explain the missing match destination-port, got %v", err)
	}
}

// TestStaticNATMatchPortWithoutMappedPortRejected is the #2769 config half: a
// `match destination-port` WITHOUT a `then static-nat mapped-port` is a
// port-scoped 1:1 that historically broadened the reverse SNAT to the whole
// host. Strict commit-check now rejects the half-config (mirror of the
// mapped-port-without-match-port rejection) so the operator must drop the port
// match (whole-address 1:1) or add a mapped-port (port forward).
//
// Fail-on-revert: removing the `rule.MatchDestinationPort != 0 &&
// rule.MappedPort == 0` guard in validateNATHostMaskStrict makes CompileConfig
// succeed → RED.
func TestStaticNATMatchPortWithoutMappedPortRejected(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		"set security nat static rule-set rs1 rule r1 match destination-port 8080",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected CompileConfig to reject match destination-port without mapped-port")
	}
	if !strings.Contains(err.Error(), "requires a matching") {
		t.Fatalf("error must explain the missing mapped-port, got %v", err)
	}
}
