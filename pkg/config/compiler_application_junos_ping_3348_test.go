package config

import (
	"strings"
	"testing"
)

// #3348: a USER-DEFINED application that sets `protocol junos-ping` (or
// junos-pingv6) was lowered to bare ICMP with no type constraint, so the
// projected policy term matched EVERY ICMP type (unreachable / redirect /
// timestamp / ...) — silently widening any policy that referenced it, and
// broader than the predefined junos-ping object which carries ICMPType=8
// (#3020). The compiler must now attach the echo-request type (8 / 128) to a
// custom app whose protocol is the ping alias, AND support explicit
// icmp-type/icmp-code grammar on a custom application.
//
// Trees are built from flat `set` commands via flatTreeFromSets — the only
// correct way to exercise the flat-set AST shape (see
// compiler_application_specs_test.go).

func refApp(name string, props ...string) []string {
	sets := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application " + name,
		"set security policies from-zone trust to-zone untrust policy p then permit",
	}
	for _, p := range props {
		sets = append(sets, "set applications application "+name+" "+p)
	}
	return sets
}

// Core fail-on-revert: `protocol junos-ping` must lower to ICMP type 8. Revert
// the compiler change (alias default removed) and app.ICMPType stays nil, so
// this assertion goes RED.
func TestApplicationJunosPing_AttachesEchoType(t *testing.T) {
	cases := []struct {
		proto    string
		wantType uint8
	}{
		{"junos-ping", 8},
		{"junos-pingv6", 128},
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("ping-app", "protocol "+c.proto)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept protocol %s: %v", c.proto, err)
			}
			app := cfg.Applications.Applications["ping-app"]
			if app == nil {
				t.Fatalf("application ping-app missing from compiled config")
			}
			if app.ICMPType == nil {
				t.Fatalf("protocol %s must attach an ICMP echo type; got nil (matches ALL ICMP — the #3348 widening)", c.proto)
			}
			if *app.ICMPType != c.wantType {
				t.Fatalf("protocol %s must lower to ICMP type %d, got %d", c.proto, c.wantType, *app.ICMPType)
			}
			if app.ICMPCode != nil {
				t.Fatalf("protocol %s must not pin a code, got %d", c.proto, *app.ICMPCode)
			}
		})
	}
}

// The all-ICMP aliases stay UNCONSTRAINED (nil type) — they intentionally match
// every ICMP type and must not gain the echo constraint.
func TestApplicationJunosIcmpAll_StaysUnconstrained(t *testing.T) {
	for _, proto := range []string{"junos-icmp-all", "junos-icmp6-all"} {
		t.Run(proto, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("all-icmp", "protocol "+proto)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept protocol %s: %v", proto, err)
			}
			if app := cfg.Applications.Applications["all-icmp"]; app == nil || app.ICMPType != nil {
				t.Fatalf("protocol %s must stay unconstrained (ICMPType nil), got %+v", proto, app)
			}
		})
	}
}

// Inline term: `term t protocol junos-ping` must attach the echo type to the
// generated term application too.
func TestApplicationJunosPing_InlineTerm_AttachesEchoType(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("ping-term", "term t protocol junos-ping")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept inline term protocol junos-ping: %v", err)
	}
	app := cfg.Applications.Applications["ping-term-t"]
	if app == nil {
		t.Fatalf("inline-term application ping-term-t missing; have %v", appNames(cfg))
	}
	if app.ICMPType == nil || *app.ICMPType != 8 {
		t.Fatalf("inline term protocol junos-ping must lower to ICMP type 8, got %v", app.ICMPType)
	}
}

// Explicit grammar: `protocol icmp icmp-type 8 icmp-code 0` must wire through to
// the typed fields. Fail-on-revert: without the icmp-type/icmp-code schema
// leaves the set command is rejected at commit (unknown leaf), and without the
// compiler cases the fields stay nil.
func TestApplicationExplicitICMPTypeCode(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("echo", "protocol icmp", "icmp-type 8", "icmp-code 0")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept icmp-type/icmp-code grammar: %v", err)
	}
	app := cfg.Applications.Applications["echo"]
	if app == nil || app.ICMPType == nil || *app.ICMPType != 8 {
		t.Fatalf("explicit icmp-type 8 must set ICMPType=8, got %+v", app)
	}
	if app.ICMPCode == nil || *app.ICMPCode != 0 {
		t.Fatalf("explicit icmp-code 0 must set ICMPCode=0, got %v", app.ICMPCode)
	}
}

// An explicit icmp-type wins over the junos-ping alias default.
func TestApplicationExplicitICMPTypeOverridesAlias(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("ovr", "protocol junos-ping", "icmp-type 13")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept explicit icmp-type override: %v", err)
	}
	app := cfg.Applications.Applications["ovr"]
	if app == nil || app.ICMPType == nil || *app.ICMPType != 13 {
		t.Fatalf("explicit icmp-type 13 must override the junos-ping echo default, got %+v", app)
	}
}

// Strict guard: icmp-type on a non-ICMP protocol is a never-match term — reject
// at commit (#3348, mirroring the #3373 port-on-non-port-protocol gate).
func TestApplicationICMPTypeOnNonICMPProtocol_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("bad", "protocol tcp", "icmp-type 8")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT icmp-type on protocol tcp")
	} else if !strings.Contains(err.Error(), "icmp-type") {
		t.Fatalf("error should mention icmp-type, got: %v", err)
	}
}

// Strict guard: an icmp-code without an icmp-type is an ambiguous half
// constraint — reject at commit.
func TestApplicationICMPCodeWithoutType_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("bad2", "protocol icmp", "icmp-code 3")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT icmp-code without icmp-type")
	} else if !strings.Contains(err.Error(), "icmp-code") {
		t.Fatalf("error should mention icmp-code, got: %v", err)
	}
}

func appNames(cfg *Config) []string {
	var n []string
	for name := range cfg.Applications.Applications {
		n = append(n, name)
	}
	return n
}
