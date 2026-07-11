package config

import (
	"testing"
)

// lenient_permit_widening_5575_test.go is the config-layer fail-on-revert guard
// for #5575: a policy the TOLERANT compile path (CompileConfigLenient) accepts
// only by DOWNGRADING a #3044 missing-match / #3113 unsupported-match-leaf /
// #3114 unsupported-then-permit reject to a WARNING must carry
// Policy.LenientContentDropped == true, so the userspace snapshot builder can
// poison the rule with the __unsupported__ sentinel instead of silently
// widening the dropped dimension to match-ANY (a permit-widening fail-open on
// the persisted-load / HA-sync path).
//
// Reverting compilePolicy's flag-set (or the shared predicate helpers) leaves
// the flag false on a leniently-loaded partial/invalid policy → the snapshot
// builder compiles the empty dimension to match-any → the widened permit ships.
// The lenient-flag subtests here flip RED on that revert; the clean subtests
// pin that an INTENTIONAL wildcard (explicit `any`) is NOT flagged (the
// empty-vs-dropped distinction).

func lenientCompilePolicy5575(t *testing.T, cmds []string) *Config {
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
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a tolerated policy: %v", err)
	}
	return cfg
}

// firstPolicy5575 returns the single compiled policy (zone-pair or global) so a
// subtest can assert its LenientContentDropped flag without threading scope.
func firstPolicy5575(t *testing.T, cfg *Config) *Policy {
	t.Helper()
	for _, zpp := range cfg.Security.Policies {
		for _, p := range zpp.Policies {
			return p
		}
	}
	for _, p := range cfg.Security.GlobalPolicies {
		return p
	}
	t.Fatal("no compiled policy found")
	return nil
}

func TestLenientContentDroppedFlagsWidenedPolicies5575(t *testing.T) {
	zones := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
	}
	zp := "set security policies from-zone trust to-zone untrust policy p "
	cases := []struct {
		name string
		cmds []string
		want bool
	}{
		{
			// #3044 missing destination-address + application on a PERMIT: the
			// #5575 core permit-widening repro. Pre-fix apps=[]/dst=[] → match-any.
			name: "permit missing destination+application",
			cmds: append(append([]string{}, zones...),
				zp+"match source-address any",
				zp+"then permit",
			),
			want: true,
		},
		{
			// #3113 unsupported match leaf (dynamic-application) on an otherwise
			// complete PERMIT: the leaf is dropped, widening the L3/L4 match.
			name: "permit with unsupported match leaf",
			cmds: append(append([]string{}, zones...),
				zp+"match source-address any",
				zp+"match destination-address any",
				zp+"match application any",
				zp+"match dynamic-application junos:FTP",
				zp+"then permit",
			),
			want: true,
		},
		{
			// #3114 unsupported then-permit modifier (application-services): the
			// service chain is dropped, turning permit-with-inspection into an
			// unconditional permit.
			name: "permit with unsupported then-permit modifier",
			cmds: append(append([]string{}, zones...),
				zp+"match source-address any",
				zp+"match destination-address any",
				zp+"match application any",
				zp+"then permit application-services utm-policy strict",
			),
			want: true,
		},
		{
			// Deny cases must be flagged too (action-agnostic): the sentinel
			// whole-snapshot reject prevents a malformed deny from silently
			// falling through to a broader default-permit.
			name: "deny missing destination+application",
			cmds: append(append([]string{}, zones...),
				zp+"match source-address any",
				zp+"then deny",
			),
			want: true,
		},
		{
			// Intentional wildcard: all three dimensions present as explicit
			// `any`. This is a LEGITIMATE match-any permit and must NOT be
			// flagged — the empty-vs-dropped distinction. A revert that keys the
			// poison on "empty dimension" instead of "dropped constraint" would
			// wrongly flag this and RED here.
			name: "complete permit with explicit any not flagged",
			cmds: append(append([]string{}, zones...),
				zp+"match source-address any",
				zp+"match destination-address any",
				zp+"match application any",
				zp+"then permit",
			),
			want: false,
		},
		{
			// Fully-constrained permit: no dropped content, not flagged.
			name: "complete constrained permit not flagged",
			cmds: append(append([]string{}, zones...),
				zp+"match source-address 10.0.0.0/8",
				zp+"match destination-address any",
				zp+"match application junos-http",
				zp+"then permit",
			),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lenientCompilePolicy5575(t, tc.cmds)
			pol := firstPolicy5575(t, cfg)
			if pol.LenientContentDropped != tc.want {
				t.Fatalf("policy %q LenientContentDropped = %v, want %v", pol.Name, pol.LenientContentDropped, tc.want)
			}
		})
	}
}

// TestLenientContentDroppedGlobalPolicy5575 covers the global-policy scope,
// including that the global-only from-zone/to-zone match context is NOT
// mistaken for an unsupported match leaf (it is legitimate under global).
func TestLenientContentDroppedGlobalPolicy5575(t *testing.T) {
	t.Run("global missing application flagged", func(t *testing.T) {
		cfg := lenientCompilePolicy5575(t, []string{
			"set security policies global policy g match source-address any",
			"set security policies global policy g match destination-address any",
			"set security policies global policy g then permit",
		})
		pol := firstPolicy5575(t, cfg)
		if !pol.LenientContentDropped {
			t.Fatalf("global policy missing application must be flagged; LenientContentDropped=false")
		}
	})
	t.Run("global with from-zone/to-zone scope not flagged", func(t *testing.T) {
		cfg := lenientCompilePolicy5575(t, []string{
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies global policy g match source-address any",
			"set security policies global policy g match destination-address any",
			"set security policies global policy g match application any",
			"set security policies global policy g match from-zone trust",
			"set security policies global policy g match to-zone untrust",
			"set security policies global policy g then permit",
		})
		pol := firstPolicy5575(t, cfg)
		if pol.LenientContentDropped {
			t.Fatalf("a global policy with a legitimate from-zone/to-zone scope must NOT be flagged as content-dropped")
		}
	})
}

// TestStrictStillRejectsWidenedPolicies5575 confirms the lenient flag is a
// tolerant-path artifact only: the strict commit path still HARD-REJECTS the
// same widened policies (so LenientContentDropped can never be set on a
// clean strict-committed policy — the snapshot stays byte-identical).
func TestStrictStillRejectsWidenedPolicies5575(t *testing.T) {
	strictRejects := func(t *testing.T, cmds []string) {
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
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("strict commit accepted a policy the lenient path flags as content-dropped; want a hard reject")
		}
	}
	zp := "set security policies from-zone trust to-zone untrust policy p "
	strictRejects(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		zp + "match source-address any",
		zp + "then permit",
	})
}
