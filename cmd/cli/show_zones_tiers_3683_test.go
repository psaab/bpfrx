package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3683: two remote-CLI (ctl binary) display residuals after the local /
// gRPC-text zone and policy surfaces were upgraded (#3658 tiers, #3331 scope
// labels).
//
//   - M01: the remote `show security zones` per-zone summary built its policy
//     refs ONLY from zone-pair groups whose group-level zones matched the zone.
//     The global group is exposed with group zones "*"/"*" and the synthetic
//     default-policy row (#3363) is not a zone-pair group, so NEITHER appeared
//     in the per-zone summary — an operator scraping the ctl binary could miss
//     an applicable global or default-policy rule.
//   - M02: the remote FILTERED policy view hand-rolled an all-zones global scope
//     as "*" instead of the canonical "any" the normalizer (matchScopeZone) and
//     Junos / local / gRPC surfaces use.
//
// These tests are the fail-on-revert guards.

// tieredZonesResp models GetZones with a single "trust" zone.
func tieredZonesResp() *pb.GetZonesResponse {
	return &pb.GetZonesResponse{
		Zones: []*pb.ZoneInfo{
			{Name: "trust", Interfaces: []string{"ge-0-0-0"}},
		},
	}
}

// tieredPoliciesResp models GetPolicies output carrying all three tiers the
// runtime evaluates: a zone-pair set (trust->untrust), the global group "*"/"*"
// with (a) an unscoped all-zones global, (b) a scoped global that DOES touch
// trust (trust->dmz), and (c) a scoped global that does NOT touch trust
// (dmz->untrust), plus the synthetic default-policy row ("-"/"-").
func tieredPoliciesResp() *pb.GetPoliciesResponse {
	return &pb.GetPoliciesResponse{
		Policies: []*pb.PolicyInfo{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Rules:    []*pb.PolicyRule{{Name: "allow-web", Action: "permit"}},
			},
			{
				FromZone: "*",
				ToZone:   "*",
				Rules: []*pb.PolicyRule{
					{Name: "open-global", Action: "permit"},
					{Name: "scoped-td", Action: "deny", MatchFromZone: "trust", MatchToZone: "dmz"},
					{Name: "scoped-du", Action: "deny", MatchFromZone: "dmz", MatchToZone: "untrust"},
				},
			},
			{
				FromZone: "-",
				ToZone:   "-",
				Rules:    []*pb.PolicyRule{{Name: "default-policy", Action: "deny"}},
			},
		},
	}
}

// TestShowZonesRendersGlobalAndDefaultTiers (M01): the remote `show security
// zones` per-zone summary must list all three tiers the runtime evaluates —
// zone-pair, applicable global (per-rule scope-filtered), and the
// default-policy catch-all.
//
// FAIL-ON-REVERT: restoring the zone-pair-only refs (the pre-#3683
// `pi.FromZone == z.Name || pi.ToZone == z.Name` compact "Policies:" line) drops
// the global group ("*"/"*") and the synthetic default row ("-"/"-") entirely,
// so the [global] and [default] assertions go RED.
func TestShowZonesRendersGlobalAndDefaultTiers(t *testing.T) {
	fake := &fakeBpfrxClient{
		getZonesResp:    tieredZonesResp(),
		getPoliciesResp: tieredPoliciesResp(),
	}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showZones(""); err != nil {
			t.Fatalf("showZones: %v", err)
		}
	})

	// Tier 1: the zone-pair rule referencing trust.
	if !strings.Contains(out, "[zone-pair] trust -> untrust: allow-web (permit)") {
		t.Fatalf("remote zone summary dropped the zone-pair tier:\n%s", out)
	}
	// Tier 2: the unscoped (all-zones) global — HIDDEN before #3683 because the
	// global group's "*"/"*" zones matched no zone. Rendered under "any -> any".
	if !strings.Contains(out, "[global] any -> any: open-global (permit)") {
		t.Fatalf("remote zone summary hid the unscoped global tier (M01 regression):\n%s", out)
	}
	// Tier 2 (scoped, applicable): trust->dmz places trust on the source axis.
	if !strings.Contains(out, "[global] trust -> dmz: scoped-td (deny)") {
		t.Fatalf("remote zone summary dropped a scoped global that touches trust:\n%s", out)
	}
	// Tier 2 (scoped, NON-applicable): dmz->untrust never involves trust, so it
	// must be filtered out per-rule (config.GlobalPolicyAppliesToZone).
	if strings.Contains(out, "scoped-du") {
		t.Fatalf("remote zone summary leaked an off-zone scoped global (dmz->untrust):\n%s", out)
	}
	// Tier 3: the default-policy catch-all — HIDDEN before #3683 because the
	// synthetic "-"/"-" row is not a zone-pair group.
	if !strings.Contains(out, "[default] default-policy: deny") {
		t.Fatalf("remote zone summary hid the default-policy tier (M01 regression):\n%s", out)
	}
}

// TestShowZonesNoTransitPoliciesShowsDefaultOnly (M01/M05): a zone with no
// zone-pair and no applicable global policy still surfaces the default-policy
// catch-all under an explicit "(no zone-pair or global policies...)" line,
// instead of an empty summary that hides whether unmatched transit is
// denied/permitted.
func TestShowZonesNoTransitPoliciesShowsDefaultOnly(t *testing.T) {
	fake := &fakeBpfrxClient{
		getZonesResp: &pb.GetZonesResponse{
			Zones: []*pb.ZoneInfo{{Name: "isolated", Interfaces: []string{"ge-0-0-9"}}},
		},
		getPoliciesResp: &pb.GetPoliciesResponse{
			Policies: []*pb.PolicyInfo{
				// A scoped global bound to an unrelated pair (dmz->untrust) —
				// must not be attributed to "isolated".
				{
					FromZone: "*",
					ToZone:   "*",
					Rules: []*pb.PolicyRule{
						{Name: "scoped-du", Action: "deny", MatchFromZone: "dmz", MatchToZone: "untrust"},
					},
				},
				{
					FromZone: "-",
					ToZone:   "-",
					Rules:    []*pb.PolicyRule{{Name: "default-policy", Action: "permit"}},
				},
			},
		},
	}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showZones(""); err != nil {
			t.Fatalf("showZones: %v", err)
		}
	})

	if !strings.Contains(out, "(no zone-pair or global policies affecting this zone)") {
		t.Fatalf("expected the explicit no-transit-policies line:\n%s", out)
	}
	if !strings.Contains(out, "[default] default-policy: permit") {
		t.Fatalf("expected the always-present default tier under permit-all:\n%s", out)
	}
	if strings.Contains(out, "scoped-du") {
		t.Fatalf("off-zone scoped global leaked into an unrelated zone's summary:\n%s", out)
	}
}

// TestShowPoliciesFilteredUnscopedGlobalRendersAny (M02): an all-zones
// (unscoped) global rule must render its scope as "any", not the hand-rolled
// internal wildcard "*", in the filtered policy view.
//
// FAIL-ON-REVERT: restoring the literal `gf, gt := "*", "*"` fallback prints
// "From zone: *, To zone: *" for the unscoped global, so the "any" assertion
// goes RED (and the "*" assertion catches the regression directly).
func TestShowPoliciesFilteredUnscopedGlobalRendersAny(t *testing.T) {
	fake := &fakeBpfrxClient{getPoliciesResp: &pb.GetPoliciesResponse{
		Policies: []*pb.PolicyInfo{
			{
				FromZone: "*",
				ToZone:   "*",
				Rules: []*pb.PolicyRule{
					{Name: "open-global", Action: "permit"},
				},
			},
		},
	}}
	c := &ctl{client: fake}

	// No from/to filter: the unscoped global is selected and its header must use
	// the canonical "any" scope.
	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("", "", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})

	if !strings.Contains(out, "From zone: any, To zone: any") {
		t.Fatalf("unscoped global header not normalized to \"any\" (M02 regression):\n%s", out)
	}
	if strings.Contains(out, "From zone: *, To zone: *") {
		t.Fatalf("unscoped global still renders the hand-rolled \"*\" wildcard (M02 regression):\n%s", out)
	}
	if !strings.Contains(out, "Rule: open-global") {
		t.Fatalf("filtered view dropped the unscoped global rule:\n%s", out)
	}
}
