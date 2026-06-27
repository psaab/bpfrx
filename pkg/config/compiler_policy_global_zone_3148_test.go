package config

import (
	"strings"
	"testing"
)

// Tests for #3148: a Junos global policy can carry optional from-zone/to-zone
// match context so one global policy applies to a chosen zone pair (or one
// wildcard side) instead of every zone pair. The compiler must parse
// `set security policies global policy <p> match from-zone <z>` /
// `... match to-zone <z>` into Policy.Match.FromZone / .ToZone; an absent
// context leaves both empty (all zones — the historical behaviour).
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath (see #3142).

func build3148Tree(t *testing.T, cmds ...string) *ConfigTree {
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

// TestGlobalPolicyZoneContextCompiles is the Go-side fail-on-revert anchor:
// reverting the from-zone/to-zone match cases in compilePolicy leaves
// FromZone/ToZone empty, turning the non-empty assertions RED.
func TestGlobalPolicyZoneContextCompiles(t *testing.T) {
	tree := build3148Tree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies global policy scoped match from-zone trust",
		"set security policies global policy scoped match to-zone untrust",
		"set security policies global policy scoped match source-address any",
		"set security policies global policy scoped match destination-address any",
		"set security policies global policy scoped match application any",
		"set security policies global policy scoped then permit",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("GlobalPolicies = %d, want 1", len(cfg.Security.GlobalPolicies))
	}
	pol := cfg.Security.GlobalPolicies[0]
	if pol.Match.FromZone != "trust" {
		t.Errorf("global policy Match.FromZone = %q, want %q", pol.Match.FromZone, "trust")
	}
	if pol.Match.ToZone != "untrust" {
		t.Errorf("global policy Match.ToZone = %q, want %q", pol.Match.ToZone, "untrust")
	}
}

// TestGlobalPolicyNoZoneContextStaysAllZones proves the no-context form keeps
// the historical all-zones semantics (FromZone/ToZone empty) — no regression.
func TestGlobalPolicyNoZoneContextStaysAllZones(t *testing.T) {
	tree := build3148Tree(t,
		"set security policies global policy g match source-address any",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g then permit",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("GlobalPolicies = %d, want 1", len(cfg.Security.GlobalPolicies))
	}
	pol := cfg.Security.GlobalPolicies[0]
	if pol.Match.FromZone != "" || pol.Match.ToZone != "" {
		t.Errorf("global policy with no zone context: FromZone=%q ToZone=%q, want both empty",
			pol.Match.FromZone, pol.Match.ToZone)
	}
}

// TestGlobalPolicyZoneContextStrictCommit (#3148) exercises the strict commit
// gate: defined match zones COMMIT; a zone-pair policy may NOT carry from-zone/
// to-zone under match (still rejected); and an undefined global match zone is
// hard-rejected at commit but downgraded to a warning on the tolerant load
// path.
func TestGlobalPolicyZoneContextStrictCommit(t *testing.T) {
	zoneDefs := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
	}
	matchBody := func(p string) []string {
		return []string{
			"set security policies global policy " + p + " match source-address any",
			"set security policies global policy " + p + " match destination-address any",
			"set security policies global policy " + p + " match application any",
			"set security policies global policy " + p + " then permit",
		}
	}

	// Defined match zones commit cleanly under the strict path.
	t.Run("defined_zones_commit", func(t *testing.T) {
		cmds := append([]string{}, zoneDefs...)
		cmds = append(cmds,
			"set security policies global policy scoped match from-zone trust",
			"set security policies global policy scoped match to-zone untrust")
		cmds = append(cmds, matchBody("scoped")...)
		tree := build3148Tree(t, cmds...)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig hard-failed on a global policy with DEFINED match zones: %v", err)
		}
	})

	// Explicit `any` is the Junos all-zones default — it commits clean (it is a
	// reserved special token, not an undefined zone) and the dataplane resolves
	// it to GlobalZoneScope::Any (build_global_zone_scope short-circuit), so the
	// commit gate and the dataplane agree.
	t.Run("explicit_any_commits", func(t *testing.T) {
		cmds := append([]string{}, zoneDefs...)
		cmds = append(cmds,
			"set security policies global policy anyfrom match from-zone any",
			"set security policies global policy anyfrom match to-zone untrust")
		cmds = append(cmds, matchBody("anyfrom")...)
		tree := build3148Tree(t, cmds...)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig hard-failed on a global policy with explicit `match from-zone any`: %v", err)
		}
		if len(cfg.Security.GlobalPolicies) != 1 || cfg.Security.GlobalPolicies[0].Match.FromZone != "any" {
			t.Fatalf("explicit `any` not preserved verbatim: %+v", cfg.Security.GlobalPolicies)
		}
	})

	// `junos-host` cannot be honored as a global match context (a zone-scoped
	// global policy is not evaluated on the host-bound path), so it is
	// hard-rejected at commit so the commit gate and the dataplane agree —
	// rather than committing into a silent never-match. Fail-on-revert: drop the
	// junos-host reject in validatePolicyZoneReferencesStrict and this commits.
	t.Run("junos_host_zone_rejected", func(t *testing.T) {
		for _, leaf := range []string{"from-zone", "to-zone"} {
			cmds := append([]string{}, zoneDefs...)
			cmds = append(cmds,
				"set security policies global policy hostctx match "+leaf+" junos-host")
			cmds = append(cmds, matchBody("hostctx")...)
			tree := build3148Tree(t, cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a global policy match %s junos-host; want a hard reject", leaf)
			}
			if !strings.Contains(err.Error(), "junos-host") || !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("match %s junos-host error = %v, want an unsupported-junos-host reject", leaf, err)
			}
		}
	})

	// An undefined match zone is hard-rejected at commit (fail-on-revert: drop
	// the GlobalPolicies loop in validatePolicyZoneReferencesStrict and this
	// goes GREEN, so RED).
	t.Run("undefined_zone_rejected", func(t *testing.T) {
		cmds := append([]string{}, zoneDefs...)
		cmds = append(cmds,
			"set security policies global policy bad match from-zone nonexistent",
			"set security policies global policy bad match to-zone untrust")
		cmds = append(cmds, matchBody("bad")...)
		tree := build3148Tree(t, cmds...)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig accepted a global policy match referencing an undefined zone; want a hard reject")
		}
		if !strings.Contains(err.Error(), "global policy") || !strings.Contains(err.Error(), "nonexistent") {
			t.Fatalf("error = %v, want it to name the global policy + undefined zone", err)
		}
	})

	// The tolerant load path downgrades the undefined-zone reject to a warning
	// so an already-persisted config still boots.
	t.Run("undefined_zone_lenient_warns", func(t *testing.T) {
		cmds := append([]string{}, zoneDefs...)
		cmds = append(cmds,
			"set security policies global policy bad match from-zone nonexistent")
		cmds = append(cmds, matchBody("bad")...)
		tree := build3148Tree(t, cmds...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient hard-failed; want warn-and-boot: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "nonexistent") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("warnings = %v, want a downgraded undefined-zone warning", cfg.Warnings)
		}
	})

	// A zone-pair policy may NOT carry from-zone/to-zone under match (those are
	// global-only context); the #3113 unsupported-leaf gate still rejects them.
	t.Run("zone_pair_match_zone_rejected", func(t *testing.T) {
		cmds := append([]string{}, zoneDefs...)
		cmds = append(cmds,
			"set security policies from-zone trust to-zone untrust policy p match from-zone trust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application any",
			"set security policies from-zone trust to-zone untrust policy p then permit")
		tree := build3148Tree(t, cmds...)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("CompileConfig accepted match from-zone under a zone-pair policy; want a #3113 reject")
		}
	})
}
