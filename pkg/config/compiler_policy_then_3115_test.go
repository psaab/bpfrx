package config

import (
	"strings"
	"testing"
)

// Tests for #3115 (codex-review-066 finding 066-03): a security policy whose
// `then reject` arm carries a child the compiler does not enforce — a reject
// `profile <name>` (custom reject response) or a packet-type reject like
// `tcp-reset` — had that modifier SILENTLY DROPPED: compilePolicy's `then`
// switch `reject` arm sets pol.Action = PolicyReject and never inspects
// t.Children, so the configured custom reject response is inert and the
// operator cannot tell from commit. Sibling of #3114 (then-permit). The
// interim fix REJECTS the unsupported then-reject child at commit (strict
// CompileConfig) and WARNS on the tolerant load/peer-sync path
// (CompileConfigLenient).
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath (via the shared
// buildPolicyThenTree helper in compiler_policy_then_3114_test.go), never
// NewParser.

// TestPolicyThenRejectUnsupportedChildRejectedAtCommit proves an unsupported
// `then reject <child>` modifier is hard-rejected at commit for both
// zone-pair and global policies. Reverting validatePolicyThenRejectStrict to
// `return nil, nil` turns every one of these cases GREEN (no error) — so the
// test goes RED, the fail-on-revert proof.
func TestPolicyThenRejectUnsupportedChildRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the commit error
	}{
		{
			name: "zone-pair reject profile",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web then reject profile blocked-web",
			},
			want: `from-zone trust to-zone untrust policy "web" then reject "profile"`,
		},
		{
			name: "zone-pair reject tcp-reset packet-type",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy rstpol then reject tcp-reset",
			},
			want: `from-zone trust to-zone untrust policy "rstpol" then reject "tcp-reset"`,
		},
		{
			name: "global reject profile",
			cmds: []string{
				"set security policies global policy greject then reject profile blocked-web",
			},
			want: `global policy "greject" then reject "profile"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildPolicyThenTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted unsupported then-reject child; want commit rejection (#3115)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3115") {
				t.Fatalf("CompileConfig error = %q, want #3115 reference", err.Error())
			}
		})
	}
}

// TestPolicyThenRejectBareStillCommits proves a plain `then reject` (no
// children) commits cleanly for both zone-pair and global policies — the gate
// only fires on an unsupported child UNDER `then reject`.
func TestPolicyThenRejectBareStillCommits(t *testing.T) {
	t.Run("zone-pair bare reject with log/count", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy r1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy r1 match destination-address any",
			"set security policies from-zone trust to-zone untrust policy r1 match application any",
			"set security policies from-zone trust to-zone untrust policy r1 then reject",
			"set security policies from-zone trust to-zone untrust policy r1 then log session-init",
			"set security policies from-zone trust to-zone untrust policy r1 then count",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a policy with a bare then reject: %v", err)
		}
	})
	t.Run("global bare reject", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security policies global policy g1 match source-address any",
			"set security policies global policy g1 match destination-address any",
			"set security policies global policy g1 match application any",
			"set security policies global policy g1 then reject",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a global policy with a bare then reject: %v", err)
		}
	})
}

// TestPolicyThenRejectUnsupportedChildLenientWarns proves the tolerant
// load/peer-sync path (CompileConfigLenient) does NOT fail on an unsupported
// then-reject child — it compiles and records a warning so an already-
// persisted config still boots (#1960 fail-closed-on-load).
func TestPolicyThenRejectUnsupportedChildLenientWarns(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security policies from-zone trust to-zone untrust policy web then reject profile blocked-web",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on unsupported then-reject child; want warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3115") && strings.Contains(w, "profile") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a #3115 then-reject warning", cfg.Warnings)
	}
}
