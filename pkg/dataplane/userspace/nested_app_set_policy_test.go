package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestNestedApplicationSetPolicyMatch is the dataplane half of the #2068
// repro. A policy matching the parent application-set must emit an app-match
// term for every application reachable through the set, INCLUDING those that
// are only reachable via a nested `application-set <child>` member.
//
// Pre-fix, compileApplications dropped the nested-set member from the parent,
// so app2 (tcp/443, reachable only through `child`) produced NO
// PolicyApplicationSnapshot term — the rule under-matched and app2 traffic
// was never matched by the policy.
//
// The config is built from flat-set commands and run through CompileConfig so
// the test exercises the real AST->typed-struct path (compileApplications),
// not a hand-built struct. A hand-built config.Config would bypass the buggy
// compiler and make this assertion tautological.
func TestNestedApplicationSetPolicyMatch(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set applications application app1 protocol tcp",
		"set applications application app1 destination-port 80",
		"set applications application app2 protocol tcp",
		"set applications application app2 destination-port 443",
		"set applications application-set child application app2",
		"set applications application-set parent application app1",
		"set applications application-set parent application-set child",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow-parent match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow-parent match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow-parent match application parent",
		"set security policies from-zone trust to-zone untrust policy allow-parent then permit",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	snaps := buildPolicySnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 policy rule snapshot, got %d", len(snaps))
	}
	terms := snaps[0].ApplicationTerms

	// Collect emitted (protocol, destination-port) app-match terms.
	gotApp1 := false
	gotApp2 := false
	for _, term := range terms {
		if term.Protocol == "tcp" && term.DestinationPort == "80" {
			gotApp1 = true
		}
		if term.Protocol == "tcp" && term.DestinationPort == "443" {
			gotApp2 = true
		}
	}
	if !gotApp1 {
		t.Errorf("policy app-match terms %+v missing app1 (tcp/80)", terms)
	}
	// The crux: the nested-set member's app-match rule must be emitted.
	// FAILS pre-fix (parent dropped `child`, so app2 produced no term).
	if !gotApp2 {
		t.Errorf("policy app-match terms %+v missing app2 (tcp/443) reachable only via nested set", terms)
	}
}
