package config

import (
	"strings"
	"testing"
)

// #2396 (a)/(3) + Copilot fold: a DNAT `match protocol <token>` reaches the
// dataplane verbatim (no validation before this gate), and the Rust DNAT table
// drops a token ip_proto::proto_number cannot resolve — a silent translation
// loss. validateDestinationNATProtocolStrict hard-rejects an unresolvable token
// at commit; the resolver normalizes (trim + lower-case) to match the Rust SSOT.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree).

// dnatProtoSet builds a minimal DNAT rule-set whose rule matches the given
// protocol token (plus a valid destination + pool so only protocol is at test).
func dnatProtoSet(protoToken string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10",
		"set security nat destination rule-set rs1 rule r1 match protocol " + protoToken,
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
}

func TestDNATProtocolKnownNamesCompile(t *testing.T) {
	for _, tok := range []string{"tcp", "udp", "icmp", "icmp6", "icmpv6", "gre", "47", "0"} {
		tree := buildTree(t, dnatProtoSet(tok))
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("match protocol %q must compile, got: %v", tok, err)
		}
	}
}

func TestDNATProtocolMixedCaseAndWhitespaceCompile(t *testing.T) {
	// Normalization: a mixed-case or padded token resolves the same as the
	// canonical lower-case token (matches Rust proto_number). The parser may
	// trim surrounding whitespace, so the load-bearing case here is mixed-case.
	for _, tok := range []string{"GRE", "Icmp", "TCP", "ICMP6"} {
		tree := buildTree(t, dnatProtoSet(tok))
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("match protocol %q must compile after normalization, got: %v", tok, err)
		}
	}
}

func TestDNATProtocolUnresolvableRejected(t *testing.T) {
	// A typo must be rejected at commit, not silently dropped at the dataplane.
	tree := buildTree(t, dnatProtoSet("grre"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("an unresolvable DNAT match protocol must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "destination-nat") ||
		!strings.Contains(msg, "r1") ||
		!strings.Contains(msg, "grre") {
		t.Fatalf("error must name the rule-set/rule + the unresolvable token, got: %v", err)
	}
}

func TestDNATProtocolUnresolvableLenientWarns(t *testing.T) {
	// Tolerant load / peer-sync must NOT brick — downgrade to a warning.
	cfg, err := CompileConfigLenient(buildTree(t, dnatProtoSet("grre")))
	if err != nil {
		t.Fatalf("lenient load must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "destination-nat protocol") {
		t.Fatalf("lenient load must emit a destination-nat protocol warning, warnings=%v", cfg.Warnings)
	}
}

// TestDNATProtocolResolvableMatchesRustSSOT pins the DNAT match-protocol gate's
// acceptance set. The set is a deliberately-TIGHTER SSOT than the Rust
// ip_proto::proto_number resolver, NOT a 1:1 mirror of it: it accepts bare
// protocol names + a 0-255 number (normalized), and excludes both (a) junos-*
// aliases (the DNAT path does not pre-resolve them, so accepting one would
// re-introduce the #2396 silent drop) and (b) "ipv6"/41, which proto_number
// resolves since #3393 but DNAT match-protocol intentionally rejects (IPv6
// encapsulation is not a meaningful DNAT destination-rule selector here). Empty
// ("" = any) is the IP-only wildcard and is resolvable.
func TestDNATProtocolResolvableMatchesRustSSOT(t *testing.T) {
	accept := []string{
		"", "tcp", "udp", "icmp", "icmp6", "icmpv6", "gre", "ospf", "ipip",
		"egp", "igmp", "pim", "ah", "esp", "sctp", "vrrp",
		"0", "47", "255",
		// Normalization.
		"GRE", " icmp ", "Tcp",
	}
	for _, tok := range accept {
		if !DNATProtocolResolvable(tok) {
			t.Errorf("DNATProtocolResolvable(%q) = false, want true", tok)
		}
	}
	reject := []string{
		"grre", "bogus", "256", "-1",
		// junos-* aliases are NOT resolved on the raw DNAT match-protocol path
		// (proto_number rejects them), so the gate must reject them too.
		"junos-gre", "junos-icmp-all", "junos-tcp-any",
		// "ipv6"/41 IS resolvable by proto_number (#3393) but is intentionally
		// rejected by the DNAT match-protocol gate — the deliberate divergence.
		"ipv6",
	}
	for _, tok := range reject {
		if DNATProtocolResolvable(tok) {
			t.Errorf("DNATProtocolResolvable(%q) = true, want false", tok)
		}
	}
}
