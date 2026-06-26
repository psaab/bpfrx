package config

import (
	"strings"
	"testing"
)

// compiler_policy_missing_match_3044_test.go is the fail-on-revert guard for
// the #3044 required-match gate (validatePolicyRequiredMatchStrict): a
// security policy whose `match` clause omits one of the three Junos-mandatory
// dimensions — source-address, destination-address, application — or omits
// the `match` block entirely must be HARD-REJECTED at commit (strict) and
// downgraded to a warning on the tolerant load / peer-sync path (lenient).
//
// Before this gate compilePolicy filled each match slice only when the leaf
// was present and the userspace dataplane treated an empty slice as
// match-ANY, so a partial policy silently widened to traffic the operator
// never intended (a fail-open for permit, an over-broad block for deny).
// Reverting the validator (make validatePolicyRequiredMatchStrict return nil,
// nil or drop its dispatch in compiler.go) turns the reject subtests GREEN on
// the BAD config — exactly the regression these tests catch.

func buildMissingMatchTree(t *testing.T, cmds []string) *ConfigTree {
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

// TestPolicyMissingMatchCriterionFailsCommit asserts that a policy missing any
// one of the three required match dimensions — or the whole match block — is
// rejected at strict commit, naming the missing dimension. Covers zone-pair
// and global scopes.
func TestPolicyMissingMatchCriterionFailsCommit(t *testing.T) {
	cases := []struct {
		name    string
		cmds    []string
		wantSub string
	}{
		{
			name: "zone-pair missing destination-address",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			wantSub: `"destination-address"`,
		},
		{
			name: "zone-pair missing source-address",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			wantSub: `"source-address"`,
		},
		{
			name: "zone-pair missing application",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			wantSub: `"application"`,
		},
		{
			name: "zone-pair no match block at all",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			wantSub: `"source-address", "destination-address", "application"`,
		},
		{
			name: "global missing application",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g then permit",
			},
			wantSub: `"application"`,
		},
		{
			name: "source-address-excluded does not satisfy source-address",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match source-address-excluded",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			wantSub: `"source-address"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildMissingMatchTree(t, tc.cmds)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected strict commit to reject a policy missing a required match criterion, got nil error")
			}
			if !strings.Contains(err.Error(), "missing required criterion") {
				t.Fatalf("error %q does not flag the missing criterion", err.Error())
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not name the expected missing dimension(s) %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestPolicyCompleteMatchCommits asserts that a policy specifying all three
// required dimensions (with explicit `any` wildcards) commits cleanly — the
// gate must NOT fire on a complete policy, for both zone-pair and global.
func TestPolicyCompleteMatchCommits(t *testing.T) {
	tree := buildMissingMatchTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies global policy g match source-address 10.0.0.0/8",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application junos-http",
		"set security policies global policy g then deny",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a complete policy: %v", err)
	}
}

// TestPolicyMissingMatchLenientDowngradesToWarning asserts the tolerant load /
// peer-sync path downgrades the missing-match reject to a warning instead of
// failing the compile, so an already-persisted or peer-synced config an older
// binary silently accepted still BOOTS (#3044 / #1960 no-brick).
func TestPolicyMissingMatchLenientDowngradesToWarning(t *testing.T) {
	tree := buildMissingMatchTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a policy missing match criteria: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3044") && strings.Contains(w, "missing required criterion") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded missing-match warning, got warnings: %v", cfg.Warnings)
	}
}
