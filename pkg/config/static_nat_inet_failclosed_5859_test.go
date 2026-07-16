package config

import (
	"strings"
	"testing"
)

// #5859: the Junos static-NAT NAT64 keyword `then static-nat inet` compiled
// clean but the userspace snapshot emitted the literal string "inet" into the
// same-family static_nat address slot; the Rust parse of "inet" failed and the
// rule was SILENTLY SKIPPED — a strict-valid config claimed NAT64 translation
// but installed nothing (a security-relevant NAT rule that is inert). No
// dataplane lowering of `static-nat inet` exists; the supported IPv6->IPv4 path
// is the native `security nat nat64` rule-set. The fix fails CLOSED: strict
// commit hard-rejects the keyword (naming the native alternative), the tolerant
// load / peer-sync path downgrades to a surfaced warning, and the snapshot
// builder drops the rule so the sentinel never reaches the dataplane.

func inetRuleSetLines() []string {
	return []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 64:ff9b::/96",
		"set security nat static rule-set rs1 rule r1 then static-nat inet",
	}
}

// TestStaticNATInetTargetRejectedStrict is the strict half: `then static-nat
// inet` must be REJECTED at strict commit-check (CompileConfig), with an error
// that names the rule-set and rule and points at the native nat64 rule-set.
//
// Fail-on-revert: removing the validateStaticNATInetTargetStrict gate (or its
// call site in runUniformGates) makes CompileConfig succeed -> RED.
func TestStaticNATInetTargetRejectedStrict(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range inetRuleSetLines() {
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
		t.Fatal("expected CompileConfig to REJECT `then static-nat inet` (#5859)")
	}
	msg := err.Error()
	if !strings.Contains(msg, "rs1") || !strings.Contains(msg, "r1") {
		t.Fatalf("error must name the rule-set and rule, got: %v", err)
	}
	if !strings.Contains(msg, "inet") || !strings.Contains(msg, "nat64") {
		t.Fatalf("error must mention `inet` and direct to the native `nat64` rule-set, got: %v", err)
	}
}

// TestStaticNATInetTargetLenientWarns is the tolerant-path half: the lenient
// load / peer-sync compile (CompileConfigLenient) must NOT brick (#1960
// no-brick) but MUST record a surfaced warning — the rule must not silently
// become inert with no signal.
//
// Fail-on-revert: removing the lenientFirewallRefs downgrade at the call site
// makes CompileConfigLenient return an error (or, if the gate is removed
// entirely, no warning) -> RED.
func TestStaticNATInetTargetLenientWarns(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range inetRuleSetLines() {
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
		t.Fatalf("lenient path must NOT fail on `then static-nat inet` (no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "inet") && strings.Contains(w, "tolerant path") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path must SURFACE a downgrade warning for `static-nat inet`; warnings: %v", cfg.Warnings)
	}
}

// TestNativeNAT64RuleSetUnaffected is the regression guard: the SUPPORTED
// IPv6->IPv4 path — a native `security nat nat64` rule-set — must still compile
// clean and produce NAT64 state. The #5859 reject targets ONLY the static-NAT
// `then static-nat inet` keyword (cfg.Security.NAT.Static), never the native
// rule-set (cfg.Security.NAT.NAT64).
func TestNativeNAT64RuleSetUnaffected(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set rs64 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs64 source-pool p64",
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
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("native `security nat nat64` rule-set must still compile clean: %v", err)
	}
	if len(cfg.Security.NAT.NAT64) != 1 {
		t.Fatalf("expected 1 native NAT64 rule-set, got %d", len(cfg.Security.NAT.NAT64))
	}
	if cfg.Security.NAT.NAT64[0].Prefix != "64:ff9b::/96" {
		t.Fatalf("native NAT64 rule-set prefix = %q, want 64:ff9b::/96", cfg.Security.NAT.NAT64[0].Prefix)
	}
}
