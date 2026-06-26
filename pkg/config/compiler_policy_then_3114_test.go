package config

import (
	"strings"
	"testing"
)

// Tests for #3114: a security policy whose `then permit` arm carries a
// child the compiler does not enforce (e.g. `application-services`,
// `firewall-authentication`, `tunnel ipsec-vpn`) had that modifier
// SILENTLY DROPPED — turning a permit-only-with-inspection rule into an
// unconditional permit, a fail-open. The interim fix REJECTS the
// unsupported then-permit child at commit (strict CompileConfig) and WARNS
// on the tolerant load/peer-sync path (CompileConfigLenient).
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never
// NewParser (the parser merges newline-separated set lines into one giant
// node).

func buildPolicyThenTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestPolicyThenPermitUnsupportedChildRejectedAtCommit proves an
// unsupported `then permit <child>` modifier is hard-rejected at commit for
// both zone-pair and global policies. Reverting validatePolicyThenPermit-
// Strict to `return nil, nil` turns every one of these cases GREEN (no
// error) and so RED.
func TestPolicyThenPermitUnsupportedChildRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the commit error
	}{
		{
			name: "zone-pair application-services utm-policy",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web then permit application-services utm-policy strict-web",
			},
			want: `from-zone trust to-zone untrust policy "web" then permit "application-services"`,
		},
		{
			name: "zone-pair firewall-authentication",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy authpol then permit firewall-authentication pass-through",
			},
			want: `from-zone trust to-zone untrust policy "authpol" then permit "firewall-authentication"`,
		},
		{
			name: "zone-pair tunnel ipsec-vpn",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy vpnpol then permit tunnel ipsec-vpn vpn1",
			},
			want: `from-zone trust to-zone untrust policy "vpnpol" then permit "tunnel"`,
		},
		{
			name: "global application-services",
			cmds: []string{
				"set security policies global policy gweb then permit application-services idp",
			},
			want: `global policy "gweb" then permit "application-services"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildPolicyThenTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted unsupported then-permit child; want commit rejection (#3114)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3114") {
				t.Fatalf("CompileConfig error = %q, want #3114 reference", err.Error())
			}
		})
	}
}

// TestPolicyThenPermitBareStillCommits proves a plain `then permit` (no
// children) and the other supported terminal/modifier actions still commit
// cleanly, for both zone-pair and global policies — the gate only fires on
// an unsupported child UNDER `then permit`.
func TestPolicyThenPermitBareStillCommits(t *testing.T) {
	t.Run("zone-pair bare permit with log/count", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match application any",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
			"set security policies from-zone trust to-zone untrust policy p1 then log session-init",
			"set security policies from-zone trust to-zone untrust policy p1 then count",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a policy with a bare then permit: %v", err)
		}
	})
	t.Run("zone-pair then deny / then reject still commit", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy d1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy d1 then deny",
			"set security policies from-zone trust to-zone untrust policy r1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy r1 then reject",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected then deny / then reject: %v", err)
		}
	})
	t.Run("global bare permit", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security policies global policy g1 match source-address any",
			"set security policies global policy g1 then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a global policy with a bare then permit: %v", err)
		}
	})
}

// TestPolicyThenPermitUnsupportedChildLenientWarns proves the tolerant
// load/peer-sync path (CompileConfigLenient) does NOT fail on an
// unsupported then-permit child — it compiles and records a warning so an
// already-persisted config still boots (#1960 fail-closed-on-load).
func TestPolicyThenPermitUnsupportedChildLenientWarns(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security policies from-zone trust to-zone untrust policy web then permit application-services utm-policy strict-web",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on unsupported then-permit child; want warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3114") && strings.Contains(w, "application-services") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a #3114 then-permit warning", cfg.Warnings)
	}
}
