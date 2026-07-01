package config

import "testing"

// Tests for #3680: GlobalPolicyAppliesToZone (the #3658 zone-detail tier
// predicate) must treat an EXPLICIT `match from-zone any` / `match to-zone any`
// global exactly like an omitted (empty) scope — both are the all-zones
// wildcard. Before the fix it only recognised the empty string, so an explicit
// "any" global (idiomatic Junos) was hidden from every affected zone's
// zone-detail summary even though the compiler preserves "any" verbatim and the
// Rust runtime enforces it as all-zones.
//
// IsWildcardZone is the shared source of truth (L01): reverting it (or the
// GlobalPolicyAppliesToZone callers) to the old "" -only test turns the
// explicit-"any" assertions RED.

func TestIsWildcardZone(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{"any", true},
		{"trust", false},
		{"untrust", false},
		{"junos-host", false},
		{"Any", false}, // case-sensitive: only the reserved lowercase token
	} {
		if got := IsWildcardZone(tc.in); got != tc.want {
			t.Errorf("IsWildcardZone(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestGlobalPolicyAppliesToZoneExplicitAny is the core #3680 fail-on-revert
// guard. It compiles globals written with the EXPLICIT `any` token (not omitted
// scope) and asserts GlobalPolicyAppliesToZone selects the right zones.
func TestGlobalPolicyAppliesToZoneExplicitAny(t *testing.T) {
	tree := build3148Tree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
		// Explicit `from-zone any to-zone untrust`: applies to every SOURCE
		// zone plus destination untrust.
		"set security policies global policy any-to-untrust match from-zone any",
		"set security policies global policy any-to-untrust match to-zone untrust",
		"set security policies global policy any-to-untrust match source-address any",
		"set security policies global policy any-to-untrust match destination-address any",
		"set security policies global policy any-to-untrust match application any",
		"set security policies global policy any-to-untrust then deny",
		// Explicit `from-zone trust to-zone any`: applies to source trust plus
		// every DESTINATION zone.
		"set security policies global policy trust-to-any match from-zone trust",
		"set security policies global policy trust-to-any match to-zone any",
		"set security policies global policy trust-to-any match source-address any",
		"set security policies global policy trust-to-any match destination-address any",
		"set security policies global policy trust-to-any match application any",
		"set security policies global policy trust-to-any then deny",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 2 {
		t.Fatalf("GlobalPolicies = %d, want 2", len(cfg.Security.GlobalPolicies))
	}
	byName := map[string]PolicyMatch{}
	for _, p := range cfg.Security.GlobalPolicies {
		byName[p.Name] = p.Match
	}
	// Confirm the compiler preserved the explicit "any" verbatim (the whole
	// premise of #3680 — the helper must cope with the stored "any").
	if byName["any-to-untrust"].FromZone != "any" {
		t.Fatalf("compiler did not preserve explicit from-zone any: %q", byName["any-to-untrust"].FromZone)
	}
	if byName["trust-to-any"].ToZone != "any" {
		t.Fatalf("compiler did not preserve explicit to-zone any: %q", byName["trust-to-any"].ToZone)
	}

	// from-zone any / to-zone untrust: `any` on the source axis places EVERY
	// zone on the source side, so it applies to trust, untrust and dmz. This is
	// the exact case the pre-fix helper missed (asSource was false because
	// "any" != "" and "any" != zone).
	for _, z := range []string{"trust", "untrust", "dmz"} {
		if !GlobalPolicyAppliesToZone(byName["any-to-untrust"], z) {
			t.Errorf("GlobalPolicyAppliesToZone(from-zone any/to-zone untrust, %q) = false, want true (explicit-any hidden — #3680)", z)
		}
	}

	// from-zone trust / to-zone any: `any` on the destination axis places every
	// zone on the destination side, so it applies to trust, untrust and dmz.
	for _, z := range []string{"trust", "untrust", "dmz"} {
		if !GlobalPolicyAppliesToZone(byName["trust-to-any"], z) {
			t.Errorf("GlobalPolicyAppliesToZone(from-zone trust/to-zone any, %q) = false, want true (explicit-any hidden — #3680)", z)
		}
	}
}

// TestGlobalPolicyAppliesToZoneScopedNoOverInclusion proves the fix does not
// over-include: a fully scoped global (concrete from AND to zone, no wildcard)
// applies ONLY to its two named zones, never to an unrelated third zone.
func TestGlobalPolicyAppliesToZoneScopedNoOverInclusion(t *testing.T) {
	tree := build3148Tree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
		"set security policies global policy trust-untrust match from-zone trust",
		"set security policies global policy trust-untrust match to-zone untrust",
		"set security policies global policy trust-untrust match source-address any",
		"set security policies global policy trust-untrust match destination-address any",
		"set security policies global policy trust-untrust match application any",
		"set security policies global policy trust-untrust then deny",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("GlobalPolicies = %d, want 1", len(cfg.Security.GlobalPolicies))
	}
	m := cfg.Security.GlobalPolicies[0].Match
	if !GlobalPolicyAppliesToZone(m, "trust") {
		t.Error("scoped trust->untrust global should apply to trust")
	}
	if !GlobalPolicyAppliesToZone(m, "untrust") {
		t.Error("scoped trust->untrust global should apply to untrust")
	}
	if GlobalPolicyAppliesToZone(m, "dmz") {
		t.Error("scoped trust->untrust global must NOT apply to unrelated zone dmz (over-inclusion)")
	}
}
