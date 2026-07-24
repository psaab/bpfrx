package config

import (
	"strings"
	"testing"
)

// TestStaticNATMappedPortMalformedRejected is the C179-038 residual half: a
// NON-NUMERIC `then static-nat prefix <ip> mapped-port <token>` with NO
// `match destination-port` was silently swallowed. The token rides inside the
// children:nil static-nat leaf (bypassing the schema value validator), so
// staticNATMappedPortFromKeys mapped it to MappedPort==0 (== "no port
// translation"), the `MatchDestinationPort != 0 && MappedPort == 0` guard did
// not fire (no match-port), and the rule compiled clean — even though a
// WELL-FORMED value in the same position IS rejected
// (TestStaticNATMappedPortWithoutMatchPortRejected). A garbage token was thus
// treated more leniently than a valid one.
//
// Fail-on-revert: remove the `rule.MappedPortRaw != ""` guard in
// validateNATHostMaskStrict (or revert staticNATMappedPortFromKeys to drop the
// malformed-raw return) → MappedPortRaw is never surfaced → CompileConfig
// succeeds → this test goes RED on a clean assertion.
func TestStaticNATMappedPortMalformedRejected(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		// Deliberately NO `match destination-port` — this is the residual path.
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port notaport",
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
		t.Fatalf("expected CompileConfig to reject a non-numeric mapped-port")
	}
	if !strings.Contains(err.Error(), "mapped-port") {
		t.Fatalf("error must mention mapped-port, got %v", err)
	}
	if !strings.Contains(err.Error(), "notaport") {
		t.Fatalf("error must name the malformed token, got %v", err)
	}
}

// TestStaticNATMappedPortMalformedLenientWarns confirms the lenient load /
// peer-sync path (#1960 no-brick) downgrades the malformed mapped-port to a
// warning rather than a hard error, and — critically — the compiled rule still
// carries MappedPort==0 so the dataplane installs a plain 1:1 (no bogus port),
// matching the pre-fix fail-closed behaviour.
func TestStaticNATMappedPortMalformedLenientWarns(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port notaport",
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
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not hard-error, got %v", err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static NAT rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.MappedPort != 0 {
		t.Fatalf("lenient path must keep MappedPort==0 (no bogus port), got %d", rule.MappedPort)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "mapped-port") && strings.Contains(w, "notaport") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a lenient warning naming the malformed mapped-port, got %v", cfg.Warnings)
	}
}
