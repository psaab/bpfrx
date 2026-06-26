package config

import (
	"strings"
	"testing"
)

// Tests for #3079: a NAT rule-set whose `from`/`to` clause scopes traffic
// by `interface` or `routing-instance` (instead of the only enforced
// `zone`) had its scope silently discarded and applied globally. The
// interim fix REJECTS those scopes at commit (strict CompileConfig) and
// WARNS on the tolerant load/peer-sync path (CompileConfigLenient).
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never
// NewParser (the parser merges newline-separated set lines into one giant
// node).

func buildNATScopeTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestNATRuleSetScopeRejectedAtCommit proves that an interface- or
// routing-instance-scoped from/to clause is hard-rejected at commit for
// source, destination, AND static NAT, in both the `from` and `to`
// directions. Reverting validateNATRuleSetScopeAST to `return nil, nil`
// turns every one of these cases GREEN (no error) and so RED.
func TestNATRuleSetScopeRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string // substring expected in the commit error
	}{
		{
			name: "source from interface",
			cmd:  "set security nat source rule-set RS from interface ge-0/0/0.0",
			want: `security nat source rule-set "RS" from interface "ge-0/0/0.0"`,
		},
		{
			name: "source from routing-instance",
			cmd:  "set security nat source rule-set RS from routing-instance blue",
			want: `security nat source rule-set "RS" from routing-instance "blue"`,
		},
		{
			name: "source to interface",
			cmd:  "set security nat source rule-set RS to interface ge-0/0/1.0",
			want: `security nat source rule-set "RS" to interface "ge-0/0/1.0"`,
		},
		{
			name: "source to routing-instance",
			cmd:  "set security nat source rule-set RS to routing-instance red",
			want: `security nat source rule-set "RS" to routing-instance "red"`,
		},
		{
			name: "destination from interface",
			cmd:  "set security nat destination rule-set RD from interface ge-0/0/0.0",
			want: `security nat destination rule-set "RD" from interface "ge-0/0/0.0"`,
		},
		{
			name: "destination from routing-instance",
			cmd:  "set security nat destination rule-set RD from routing-instance blue",
			want: `security nat destination rule-set "RD" from routing-instance "blue"`,
		},
		{
			name: "static from interface",
			cmd:  "set security nat static rule-set RT from interface ge-0/0/0.0",
			want: `security nat static rule-set "RT" from interface "ge-0/0/0.0"`,
		},
		{
			name: "static from routing-instance",
			cmd:  "set security nat static rule-set RT from routing-instance blue",
			want: `security nat static rule-set "RT" from routing-instance "blue"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildNATScopeTree(t, tc.cmd)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted unsupported NAT scope %q; want commit rejection (#3079)", tc.cmd)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3079") {
				t.Fatalf("CompileConfig error = %q, want #3079 reference", err.Error())
			}
		})
	}
}

// TestNATRuleSetZoneScopeStillCommits proves the supported `from zone` /
// `to zone` scope, and a rule-set with NO from/to clause (the legitimate
// global case), still commit cleanly.
func TestNATRuleSetZoneScopeStillCommits(t *testing.T) {
	t.Run("from/to zone", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS to zone untrust",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a zone-scoped NAT rule-set: %v", err)
		}
	})
	t.Run("global (no from/to)", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a global (no from/to) NAT rule-set: %v", err)
		}
	})
}

// TestNATRuleSetScopeLenientWarns proves the tolerant load/peer-sync path
// (CompileConfigLenient) does NOT fail on an unsupported scope — it
// compiles and records a warning so an already-persisted config still
// boots (#1960 fail-closed-on-load).
func TestNATRuleSetScopeLenientWarns(t *testing.T) {
	tree := buildNATScopeTree(t,
		"set security nat source rule-set RS from interface ge-0/0/0.0",
		"set security nat source rule-set RS rule R1 then source-nat interface",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on unsupported NAT scope; want warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3079") && strings.Contains(w, "interface") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a #3079 NAT scope warning", cfg.Warnings)
	}
}
