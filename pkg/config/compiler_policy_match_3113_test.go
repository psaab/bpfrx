package config

import (
	"strings"
	"testing"
)

// Tests for #3113: a security policy whose `match` clause carries a leaf
// the compiler does not enforce (e.g. `dynamic-application`,
// `url-category`, `source-identity`) had that criterion SILENTLY DROPPED
// and the policy widened into a broad L3/L4 permit/deny — a fail-open. The
// interim fix REJECTS the unsupported leaf at commit (strict CompileConfig)
// and WARNS on the tolerant load/peer-sync path (CompileConfigLenient).
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never
// NewParser (the parser merges newline-separated set lines into one giant
// node).

func buildPolicyMatchTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestPolicyMatchUnsupportedLeafRejectedAtCommit proves an unsupported
// `match` leaf is hard-rejected at commit for both zone-pair and global
// policies. Reverting validatePolicyMatchLeavesStrict to `return nil, nil`
// turns every one of these cases GREEN (no error) and so RED.
func TestPolicyMatchUnsupportedLeafRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the commit error
	}{
		{
			name: "zone-pair dynamic-application",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy appid match dynamic-application junos:FTP",
				"set security policies from-zone trust to-zone untrust policy appid then permit",
			},
			want: `from-zone trust to-zone untrust policy "appid" match "dynamic-application"`,
		},
		{
			name: "zone-pair url-category",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy urlcat match url-category Enhanced_Search_Engines",
				"set security policies from-zone trust to-zone untrust policy urlcat then permit",
			},
			want: `from-zone trust to-zone untrust policy "urlcat" match "url-category"`,
		},
		{
			name: "zone-pair source-identity",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy ident match source-identity authenticated-user",
				"set security policies from-zone trust to-zone untrust policy ident then permit",
			},
			want: `from-zone trust to-zone untrust policy "ident" match "source-identity"`,
		},
		{
			name: "global dynamic-application",
			cmds: []string{
				"set security policies global policy gappid match dynamic-application junos:HTTP",
				"set security policies global policy gappid then permit",
			},
			want: `global policy "gappid" match "dynamic-application"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildPolicyMatchTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted unsupported policy match leaf; want commit rejection (#3113)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3113") {
				t.Fatalf("CompileConfig error = %q, want #3113 reference", err.Error())
			}
		})
	}
}

// TestPolicyMatchSupportedLeavesStillCommit proves every supported `match`
// leaf (source-address, destination-address, the excluded flags, and
// application) still commits cleanly, for both zone-pair and global
// policies.
func TestPolicyMatchSupportedLeavesStillCommit(t *testing.T) {
	t.Run("zone-pair all supported leaves", func(t *testing.T) {
		tree := buildPolicyMatchTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p1 match source-address 10.0.0.0/8",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address 192.168.0.0/16",
			"set security policies from-zone trust to-zone untrust policy p1 match source-address-excluded",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address-excluded",
			"set security policies from-zone trust to-zone untrust policy p1 match application junos-http",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a policy with only supported match leaves: %v", err)
		}
	})
	t.Run("global supported leaves", func(t *testing.T) {
		tree := buildPolicyMatchTree(t,
			"set security policies global policy g1 match source-address any",
			"set security policies global policy g1 match destination-address any",
			"set security policies global policy g1 match application any",
			"set security policies global policy g1 then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a global policy with only supported match leaves: %v", err)
		}
	})
}

// TestPolicyMatchUnsupportedLeafLenientWarns proves the tolerant
// load/peer-sync path (CompileConfigLenient) does NOT fail on an
// unsupported match leaf — it compiles and records a warning so an
// already-persisted config still boots (#1960 fail-closed-on-load).
func TestPolicyMatchUnsupportedLeafLenientWarns(t *testing.T) {
	tree := buildPolicyMatchTree(t,
		"set security policies from-zone trust to-zone untrust policy appid match dynamic-application junos:FTP",
		"set security policies from-zone trust to-zone untrust policy appid then permit",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on unsupported policy match leaf; want warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3113") && strings.Contains(w, "dynamic-application") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a #3113 policy match warning", cfg.Warnings)
	}
}
