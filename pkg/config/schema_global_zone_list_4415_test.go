package config

import (
	"strings"
	"testing"
)

// #4415 L12: a scoped global policy models exactly ONE from-zone and ONE
// to-zone (config.PolicyMatch.FromZone / .ToZone are single strings, set by
// the compiler from only the first value token). A Junos zone LIST
// (`match from-zone [ a b ]`) collapses via the #2419 lexer onto one leaf's
// Keys (["from-zone","a","b"]); the compiler kept only "a" and SILENTLY
// DROPPED "b", narrowing the policy's scope without any operator-visible
// signal — a security-relevant miscompile. Tagging the leaves `scalar: true`
// makes SchemaValidate REJECT the list at commit (the #3332 fail-closed
// trailing-token guard) instead of dropping a zone. Modeling a real
// multi-zone scope is the deferred #4415 M03 work; until then rejection is
// the correct behavior.
//
// RED on revert: dropping `scalar: true` from the global from-zone/to-zone
// leaves in schema_security.go makes SchemaValidate return nil for the list
// form, so the wantReject assertions below fail.

func buildGlobalZone4415Tree(t *testing.T, cmds ...string) *ConfigTree {
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

func TestGlobalPolicyZoneListRejected4415(t *testing.T) {
	base := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
	}

	cases := []struct {
		name       string
		matchLine  string
		wantReject bool
		wantToken  string
	}{
		{
			name:       "from-zone list rejected",
			matchLine:  "set security policies global policy p match from-zone [ trust dmz ]",
			wantReject: true,
			wantToken:  "dmz",
		},
		{
			name:       "to-zone list rejected",
			matchLine:  "set security policies global policy p match to-zone [ untrust dmz ]",
			wantReject: true,
			wantToken:  "dmz",
		},
		{
			name:       "single from-zone accepted",
			matchLine:  "set security policies global policy p match from-zone trust",
			wantReject: false,
		},
		{
			name:       "single to-zone accepted",
			matchLine:  "set security policies global policy p match to-zone untrust",
			wantReject: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append(append([]string(nil), base...), tc.matchLine,
				"set security policies global policy p match application any",
				"set security policies global policy p then deny",
			)
			tree := buildGlobalZone4415Tree(t, cmds...)
			cfg, _ := CompileConfigLenient(tree)
			err := SchemaValidate(tree, cfg)
			if tc.wantReject {
				if err == nil {
					t.Fatalf("SchemaValidate accepted a zone LIST; want rejection (the second zone would be silently dropped)")
				}
				if tc.wantToken != "" && !strings.Contains(err.Error(), tc.wantToken) {
					t.Errorf("SchemaValidate error = %q; want it to name the dropped token %q", err.Error(), tc.wantToken)
				}
			} else if err != nil {
				t.Fatalf("SchemaValidate rejected a valid single-zone scope: %v", err)
			}
		})
	}
}
