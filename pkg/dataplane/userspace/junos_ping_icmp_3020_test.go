package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3020 — junos-ping / junos-pingv6 must compile to a policy application term
// carrying an ICMP/ICMPv6 type constraint (echo-request: type 8 / 128), while
// the all-ICMP aliases stay UNCONSTRAINED (nil type) so they keep matching
// every ICMP message. Before #3020 every ICMP predefined app expanded to the
// same protocol-only term, making junos-ping identical to junos-icmp-all.

func icmpAppCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	return cfg
}

func TestJunosPingExpandsToEchoRequestTypeConstraint(t *testing.T) {
	cfg := icmpAppCfg()
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"junos-ping"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications(junos-ping) ok=false, want true")
	}
	if len(terms) != 1 {
		t.Fatalf("len(terms) = %d, want 1", len(terms))
	}
	if terms[0].Protocol != "icmp" {
		t.Fatalf("junos-ping Protocol = %q, want \"icmp\"", terms[0].Protocol)
	}
	if terms[0].ICMPType == nil {
		t.Fatal("junos-ping ICMPType = nil, want 8 (echo-request) — would match all ICMP like junos-icmp-all")
	}
	if *terms[0].ICMPType != 8 {
		t.Fatalf("junos-ping ICMPType = %d, want 8", *terms[0].ICMPType)
	}
	if terms[0].ICMPCode != nil {
		t.Fatalf("junos-ping ICMPCode = %d, want nil (any code of the type)", *terms[0].ICMPCode)
	}
}

func TestJunosPingV6ExpandsToEchoRequestTypeConstraint(t *testing.T) {
	cfg := icmpAppCfg()
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"junos-pingv6"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications(junos-pingv6) ok=false, want true")
	}
	if len(terms) != 1 {
		t.Fatalf("len(terms) = %d, want 1", len(terms))
	}
	if terms[0].Protocol != "icmpv6" {
		t.Fatalf("junos-pingv6 Protocol = %q, want \"icmpv6\"", terms[0].Protocol)
	}
	if terms[0].ICMPType == nil || *terms[0].ICMPType != 128 {
		t.Fatalf("junos-pingv6 ICMPType = %v, want 128 (echo-request)", terms[0].ICMPType)
	}
}

func TestJunosIcmpAllStaysUnconstrained(t *testing.T) {
	cfg := icmpAppCfg()
	for _, name := range []string{"junos-icmp-all", "junos-icmp6-all"} {
		terms, ok := expandUserspacePolicyApplications(cfg, []string{name})
		if !ok {
			t.Fatalf("expandUserspacePolicyApplications(%s) ok=false, want true", name)
		}
		if len(terms) != 1 {
			t.Fatalf("%s: len(terms) = %d, want 1", name, len(terms))
		}
		if terms[0].ICMPType != nil {
			t.Fatalf("%s: ICMPType = %d, want nil (match all ICMP)", name, *terms[0].ICMPType)
		}
		if terms[0].ICMPCode != nil {
			t.Fatalf("%s: ICMPCode = %d, want nil", name, *terms[0].ICMPCode)
		}
	}
}
