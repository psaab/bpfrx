package config

import (
	"strings"
	"testing"
)

// TestPolicyBareLogFailsCommit is the #3060 fail-on-revert anchor: a security
// policy whose `then log` names neither session-init nor session-close compiles
// to a non-nil PolicyLog with both flags false. The policy then REPORTS logging
// enabled over REST/gRPC/CLI yet emits NO session records (audit looks active
// while producing nothing). Junos requires at least one of
// session-init/session-close, so the strict commit path must hard-reject it.
// Reverting validatePolicyLogActionStrict to `return nil` makes this CompileConfig
// succeed (RED).
func TestPolicyBareLogFailsCommit(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy audit match source-address any",
		"set security policies from-zone trust to-zone untrust policy audit match destination-address any",
		"set security policies from-zone trust to-zone untrust policy audit match application any",
		"set security policies from-zone trust to-zone untrust policy audit then permit",
		"set security policies from-zone trust to-zone untrust policy audit then log",
	}
	tree := buildPolicyTree(t, cmds)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a policy with a bare `then log`; " +
			"expected a hard reject (reports logging enabled but emits nothing)")
	} else if !strings.Contains(err.Error(), "session-init") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestGlobalPolicyBareLogFailsCommit covers the global-policy arm of the #3060
// gate (a global policy with a bare `then log`).
func TestGlobalPolicyBareLogFailsCommit(t *testing.T) {
	cmds := []string{
		"set security policies global policy g match source-address any",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g then permit",
		"set security policies global policy g then log",
	}
	tree := buildPolicyTree(t, cmds)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a global policy with a bare `then log`")
	} else if !strings.Contains(err.Error(), "global policy") ||
		!strings.Contains(err.Error(), "session-init") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPolicyLogSessionInitCommits asserts the #3060 gate accepts a `then log`
// that names session-init (the documented minimum). session-close and both
// together are also accepted.
func TestPolicyLogSessionInitCommits(t *testing.T) {
	for _, variant := range [][]string{
		{"set security policies from-zone trust to-zone untrust policy audit then log session-init"},
		{"set security policies from-zone trust to-zone untrust policy audit then log session-close"},
		{
			"set security policies from-zone trust to-zone untrust policy audit then log session-init",
			"set security policies from-zone trust to-zone untrust policy audit then log session-close",
		},
	} {
		cmds := append([]string{
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy audit match source-address any",
			"set security policies from-zone trust to-zone untrust policy audit match destination-address any",
			"set security policies from-zone trust to-zone untrust policy audit match application any",
			"set security policies from-zone trust to-zone untrust policy audit then permit",
		}, variant...)
		tree := buildPolicyTree(t, cmds)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a valid `then log` variant %v: %v", variant, err)
		}
	}
}

// TestPolicyBareLogLenientWarns asserts the #3060 tolerant path: an
// already-persisted / peer-synced config carrying a bare `then log` must NOT
// brick the boot (#1960 no-brick doctrine). CompileConfigLenient downgrades the
// hard reject to a cfg.Warnings entry and still compiles.
func TestPolicyBareLogLenientWarns(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy audit match source-address any",
		"set security policies from-zone trust to-zone untrust policy audit match destination-address any",
		"set security policies from-zone trust to-zone untrust policy audit match application any",
		"set security policies from-zone trust to-zone untrust policy audit then permit",
		"set security policies from-zone trust to-zone untrust policy audit then log",
	}
	tree := buildPolicyTree(t, cmds)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a bare-log config (should warn, not brick): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy log action") && strings.Contains(w, "session-init") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a 'policy log action' downgrade warning; got %v", cfg.Warnings)
	}
}
