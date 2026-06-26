package config

import (
	"strings"
	"testing"
)

// buildPolicyTree compiles a set-command list into a ConfigTree for the
// #3043 terminal-action tests.
func buildPolicyTree(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestPolicyNoTerminalActionFailsCommit is the #3043 fail-on-revert anchor:
// a security policy whose `then` stanza names NO terminal action
// (permit/deny/reject) — here a log-only audit placeholder — silently
// compiled with Action == PolicyPermit (the PolicyAction zero value) and
// PERMITTED all matching traffic. The strict commit path must hard-reject it.
// Without validatePolicyTerminalActionStrict this CompileConfig succeeds
// (RED).
func TestPolicyNoTerminalActionFailsCommit(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy audit match source-address any",
		"set security policies from-zone trust to-zone untrust policy audit match destination-address any",
		"set security policies from-zone trust to-zone untrust policy audit match application any",
		"set security policies from-zone trust to-zone untrust policy audit then log session-init",
	}
	tree := buildPolicyTree(t, cmds)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a policy with no terminal action; " +
			"expected a hard reject (silent fail-OPEN permit)")
	} else if !strings.Contains(err.Error(), "no terminal action") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestGlobalPolicyNoTerminalActionFailsCommit covers the global-policy arm of
// the #3043 gate (a global policy with no terminal action).
func TestGlobalPolicyNoTerminalActionFailsCommit(t *testing.T) {
	cmds := []string{
		"set security policies global policy g match source-address any",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g then count",
	}
	tree := buildPolicyTree(t, cmds)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a global policy with no terminal action")
	} else if !strings.Contains(err.Error(), "global policy") ||
		!strings.Contains(err.Error(), "no terminal action") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPolicyConflictingTerminalActionsFailsCommit asserts the #3043 gate also
// rejects a policy that names MORE than one terminal action (e.g. a
// group-merged permit + deny), which historically resolved last-wins by parse
// order rather than failing the commit.
func TestPolicyConflictingTerminalActionsFailsCommit(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy oops match source-address any",
		"set security policies from-zone trust to-zone untrust policy oops match destination-address any",
		"set security policies from-zone trust to-zone untrust policy oops match application any",
		"set security policies from-zone trust to-zone untrust policy oops then permit",
		"set security policies from-zone trust to-zone untrust policy oops then deny",
	}
	tree := buildPolicyTree(t, cmds)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a policy with conflicting terminal actions")
	} else if !strings.Contains(err.Error(), "conflicting terminal actions") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPolicyNoTerminalActionLenientDefaultsDeny is the second #3043
// fail-on-revert anchor: on the tolerant load / HA-sync path the actionless
// policy must NOT hard-fail (an already-persisted config must still boot —
// #1960) but it must default to DENY, never permit. Without the compilePolicy
// fail-closed default this policy's Action is PolicyPermit (RED).
func TestPolicyNoTerminalActionLenientDefaultsDeny(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy audit match source-address any",
		"set security policies from-zone trust to-zone untrust policy audit match destination-address any",
		"set security policies from-zone trust to-zone untrust policy audit match application any",
		"set security policies from-zone trust to-zone untrust policy audit then log session-init",
	}
	tree := buildPolicyTree(t, cmds)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on an actionless policy "+
			"(must downgrade to a warning so a persisted config still boots): %v", err)
	}
	var pol *Policy
	for _, zpp := range cfg.Security.Policies {
		for _, p := range zpp.Policies {
			if p.Name == "audit" {
				pol = p
			}
		}
	}
	if pol == nil {
		t.Fatal("audit policy missing from compiled config")
	}
	if pol.Action != PolicyDeny {
		t.Errorf("actionless policy defaulted to %s on lenient load; want deny "+
			"(fail-closed, NOT the PolicyPermit zero value)", policyActionName(pol.Action))
	}
	foundWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy terminal action") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Errorf("expected a 'policy terminal action' warning on the lenient path, got %v", cfg.Warnings)
	}
}

// TestPolicyExactlyOneTerminalActionCommits is the positive control: a
// well-formed policy with exactly one terminal action commits cleanly and
// keeps that action.
func TestPolicyExactlyOneTerminalActionCommits(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy block match source-address any",
		"set security policies from-zone trust to-zone untrust policy block match destination-address any",
		"set security policies from-zone trust to-zone untrust policy block match application any",
		"set security policies from-zone trust to-zone untrust policy block then deny",
		"set security policies from-zone trust to-zone untrust policy block then log session-init",
	}
	tree := buildPolicyTree(t, cmds)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a well-formed single-action policy: %v", err)
	}
	var pol *Policy
	for _, zpp := range cfg.Security.Policies {
		for _, p := range zpp.Policies {
			if p.Name == "block" {
				pol = p
			}
		}
	}
	if pol == nil {
		t.Fatal("block policy missing from compiled config")
	}
	if pol.Action != PolicyDeny {
		t.Errorf("block policy action = %s, want deny", policyActionName(pol.Action))
	}
}
