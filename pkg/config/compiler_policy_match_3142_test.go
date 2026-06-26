package config

import (
	"strings"
	"testing"
)

// Tests for #3142 (codex-review-067 finding 067-01): the #3113
// unsupported-match-leaf gate only inspected DIRECT children of `match`.
// Because `match application` is a multi:true leaf, the flat-set absorber
// collapses every trailing non-sibling token (e.g. `dynamic-application
// junos:FTP`, `url-category Enhanced_Search_Engines`) ONTO the application
// leaf's own node (Keys[1:] + child sub-nodes — the #2419 collapse). The
// direct-child scan never saw the tail, so the unsupported criterion ESCAPED
// the gate and the policy silently armed as a broad application match — the
// same fail-open #3113 closes, reached via the multi-value-leaf path.
//
// The fix extends validatePolicyMatchLeavesStrict to also scan the collapsed
// tail of a supported multi-value leaf for KNOWN unsupported match-leaf
// keywords (dynamic-application/url-category/source-identity) and reject them
// exactly as a direct child. Legitimate application VALUES (real app names)
// are never one of those keywords, so they are not over-rejected.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath — bracketed
// lists (`[ a b ]`) require the lexer's bracket stripping, which
// strings.Fields does not do.
func build3142Tree(t *testing.T, cmds ...string) *ConfigTree {
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

// TestPolicyMatchMultiValueTailEscapeRejected is the fail-on-revert anchor:
// an unsupported match-leaf keyword collapsed onto the application leaf's
// tail must be hard-rejected at commit. Reverting the multi-value tail check
// in validatePolicyMatchLeavesStrict turns every one of these cases GREEN
// (no error) and so RED.
func TestPolicyMatchMultiValueTailEscapeRejected(t *testing.T) {
	// zoneDefs makes the zone-pair escape policies OTHERWISE valid: both
	// zones are defined and both address criteria are present, so neither the
	// undefined-zone gate nor the #3044 missing-criterion gate fires — the
	// ONLY thing that can reject these is the #3142 multi-value tail check.
	// Reverting that check makes the config COMMIT (the genuine fail-open
	// escape), turning these RED.
	zoneDefs := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
	}
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the commit error
	}{
		{
			name: "zone-pair application any dynamic-application",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any dynamic-application junos:FTP",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match "dynamic-application"`,
		},
		{
			name: "zone-pair application junos-http dynamic-application",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application junos-http dynamic-application junos:FTP",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match "dynamic-application"`,
		},
		{
			name: "zone-pair application any url-category",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any url-category Enhanced_Search_Engines",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match "url-category"`,
		},
		{
			name: "global application any dynamic-application",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any dynamic-application junos:HTTP",
				"set security policies global policy g then permit",
			},
			want: `global policy "g" match "dynamic-application"`,
		},
		{
			name: "global application any source-identity",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any source-identity authenticated-user",
				"set security policies global policy g then permit",
			},
			want: `global policy "g" match "source-identity"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Defining trust/untrust is harmless for the global cases.
			tree := build3142Tree(t, append(append([]string{}, zoneDefs...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a multi-value-leaf match escape; want commit rejection (#3142)")
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

// TestPolicyMatchApplicationValuesNotOverRejected proves the guard does NOT
// over-reject legitimate application values that collapse onto the same
// multi-value leaf. A bracketed app list and multi-token app sequences are
// real values, not unsupported match-leaf keywords, and must still commit.
func TestPolicyMatchApplicationValuesNotOverRejected(t *testing.T) {
	t.Run("zone-pair bracketed application list", func(t *testing.T) {
		tree := build3142Tree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application [ junos-http junos-https ]",
			"set security policies from-zone trust to-zone untrust policy p then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig over-rejected a legit bracketed application list: %v", err)
		}
	})
	t.Run("global bracketed application list", func(t *testing.T) {
		tree := build3142Tree(t,
			"set security policies global policy g match source-address any",
			"set security policies global policy g match destination-address any",
			"set security policies global policy g match application [ junos-http junos-https junos-dns-udp ]",
			"set security policies global policy g then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig over-rejected a legit global bracketed application list: %v", err)
		}
	})
	t.Run("application any alone", func(t *testing.T) {
		tree := build3142Tree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application any",
			"set security policies from-zone trust to-zone untrust policy p then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig over-rejected application any: %v", err)
		}
	})
}

// TestPolicyMatchMultiValueTailEscapeLenientWarns proves the tolerant
// load/peer-sync path (CompileConfigLenient) does NOT fail on the tail
// escape — it compiles and records a warning naming the keyword, so an
// already-persisted config still boots (#1960 fail-closed-on-load).
func TestPolicyMatchMultiValueTailEscapeLenientWarns(t *testing.T) {
	tree := build3142Tree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any dynamic-application junos:FTP",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on a multi-value tail escape; want warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3113") && strings.Contains(w, "dynamic-application") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a #3113 tail-escape warning", cfg.Warnings)
	}
}
