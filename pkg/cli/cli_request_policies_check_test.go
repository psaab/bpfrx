package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestAnalyzePolicyShadowing pins the fable-167 C-1c shadow/redundancy pass.
func TestAnalyzePolicyShadowing(t *testing.T) {
	pol := func(name string, action config.PolicyAction, src, dst, apps []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      src,
				DestinationAddresses: dst,
				Applications:         apps,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				// permit-any shadows every later rule in this pair.
				pol("permit-all", config.PolicyPermit, []string{"any"}, []string{"any"}, []string{"any"}),
				// SHADOWED with a different action (dangerous).
				pol("block-web", config.PolicyDeny, []string{"any"}, []string{"web-srv"}, []string{"http"}),
			},
		},
		{
			FromZone: "trust", ToZone: "dmz",
			Policies: []*config.Policy{
				pol("allow-http", config.PolicyPermit, []string{"any"}, []string{"any"}, []string{"http"}),
				// REDUNDANT: identical match+action to allow-http.
				pol("allow-http-dup", config.PolicyPermit, []string{"any"}, []string{"any"}, []string{"http"}),
				// NOT shadowed: distinct application not covered by allow-http.
				pol("allow-dns", config.PolicyPermit, []string{"any"}, []string{"any"}, []string{"dns"}),
			},
		},
	}

	findings := analyzePolicyShadowing(cfg)
	joined := strings.Join(findings, "\n")

	if !strings.Contains(joined, "block-web") || !strings.Contains(joined, "SHADOWED") {
		t.Fatalf("expected block-web reported SHADOWED, got:\n%s", joined)
	}
	if !strings.Contains(joined, "allow-http-dup") || !strings.Contains(joined, "REDUNDANT") {
		t.Fatalf("expected allow-http-dup reported REDUNDANT, got:\n%s", joined)
	}
	if strings.Contains(joined, "allow-dns") {
		t.Fatalf("allow-dns is not shadowed (distinct application) but was reported:\n%s", joined)
	}
}

// TestAnalyzePolicyShadowingExcludedLaterIsNotShadowed pins the fable-167 C-1c
// review MINOR fix: a later policy whose match sense is INVERTED
// (source/destination-address-excluded) is NOT reported as shadowed even when
// the named sets are identical — the two match sets are disjoint (in-set vs
// complement), so the later rule is fully reachable. RED on revert: without
// the b-excluded guard the lint reports it SHADOWED/UNREACHABLE (false
// positive).
func TestAnalyzePolicyShadowingExcludedLaterIsNotShadowed(t *testing.T) {
	src := func(name string, action config.PolicyAction, srcExcluded bool) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:       []string{"A"},
				DestinationAddresses:  []string{"any"},
				Applications:          []string{"any"},
				SourceAddressExcluded: srcExcluded,
			},
		}
	}
	dst := func(name string, action config.PolicyAction, dstExcluded bool) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:            []string{"any"},
				DestinationAddresses:       []string{"B"},
				Applications:               []string{"any"},
				DestinationAddressExcluded: dstExcluded,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				// earlier permit src∈{A}; later deny src∉{A} — DISJOINT.
				src("permit-A", config.PolicyPermit, false),
				src("deny-not-A", config.PolicyDeny, true),
			},
		},
		{
			FromZone: "trust", ToZone: "dmz",
			Policies: []*config.Policy{
				// earlier permit dst∈{B}; later deny dst∉{B} — DISJOINT.
				dst("permit-B", config.PolicyPermit, false),
				dst("deny-not-B", config.PolicyDeny, true),
			},
		},
	}
	if findings := analyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("an excluded-sense later policy is reachable, must not shadow, got: %v", findings)
	}
}

// TestAnalyzePolicyShadowingGenuineStillReported guards that the b-excluded
// fix did not suppress a genuine shadow: earlier permit-any shadows a later
// deny [A] (both plain, no exclusion).
func TestAnalyzePolicyShadowingGenuineStillReported(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				{Name: "permit-any", Action: config.PolicyPermit, Match: config.PolicyMatch{
					SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
				}},
				{Name: "deny-A", Action: config.PolicyDeny, Match: config.PolicyMatch{
					SourceAddresses: []string{"A"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
				}},
			},
		},
	}
	findings := analyzePolicyShadowing(cfg)
	if len(findings) != 1 || !strings.Contains(findings[0], "deny-A") || !strings.Contains(findings[0], "SHADOWED") {
		t.Fatalf("expected genuine shadow of deny-A still reported, got: %v", findings)
	}
}

// TestAnalyzePolicyShadowingScheduledEarlierIsNotShadower pins that a
// schedule-gated earlier policy (not always active) is NOT treated as a
// shadower — avoids false positives.
func TestAnalyzePolicyShadowingScheduledEarlierIsNotShadower(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				{
					Name:          "business-hours",
					Action:        config.PolicyPermit,
					SchedulerName: "work-week",
					Match: config.PolicyMatch{
						SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
					},
				},
				{
					Name:   "after-hours-block",
					Action: config.PolicyDeny,
					Match: config.PolicyMatch{
						SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
					},
				},
			},
		},
	}
	if findings := analyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("scheduled earlier policy must not shadow, got: %v", findings)
	}
}

// TestAnalyzePolicyShadowingGlobal pins codex-182 A10-b00-C01: the shadow pass
// must also analyze the ordered global policy list (`security policies
// global`), which it previously omitted entirely. An earlier global `permit
// any` shadows a later global `deny web`. RED on revert (drop the
// analyzePolicyListShadowing call over GlobalPolicies): the finding disappears.
func TestAnalyzePolicyShadowingGlobal(t *testing.T) {
	gpol := func(name string, action config.PolicyAction, apps []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         apps,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{
		gpol("g-permit-all", config.PolicyPermit, []string{"any"}),
		// SHADOWED: a superset permit-any precedes this deny in the same tier.
		gpol("g-block-web", config.PolicyDeny, []string{"http"}),
	}
	findings := analyzePolicyShadowing(cfg)
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, "g-block-web") || !strings.Contains(joined, "SHADOWED") {
		t.Fatalf("expected global g-block-web reported SHADOWED, got:\n%s", joined)
	}
	if !strings.Contains(joined, "[global]") {
		t.Fatalf("expected the finding tagged with the [global] scope, got:\n%s", joined)
	}
}

// TestAnalyzePolicyShadowingGlobalDisjointScopeNotShadowed guards the
// globalScopeCovers gate: two global policies narrowed to DIFFERENT from-zone
// contexts (#3148/#4626) never shadow each other even when their
// address/application match sets nest. RED on revert (drop the extraSuperset
// gate for the global list): the lint falsely reports the later global
// SHADOWED.
func TestAnalyzePolicyShadowingGlobalDisjointScopeNotShadowed(t *testing.T) {
	scoped := func(name string, action config.PolicyAction, fromZones []string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				FromZones:            fromZones,
			},
		}
	}
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{
		// earlier permit-any scoped to from-zone trust ONLY.
		scoped("g-permit-trust", config.PolicyPermit, []string{"trust"}),
		// later deny scoped to from-zone untrust — a DIFFERENT context, so the
		// earlier trust-only permit cannot make it unreachable.
		scoped("g-deny-untrust", config.PolicyDeny, []string{"untrust"}),
	}
	if findings := analyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("globals with disjoint from-zone scopes must not shadow, got: %v", findings)
	}

	// Control: a later global with NO from-zone scope (all zones) is BROADER
	// than the earlier trust-only permit, so it is likewise not shadowed.
	cfg.Security.GlobalPolicies = []*config.Policy{
		scoped("g-permit-trust", config.PolicyPermit, []string{"trust"}),
		scoped("g-deny-all", config.PolicyDeny, nil),
	}
	if findings := analyzePolicyShadowing(cfg); len(findings) != 0 {
		t.Fatalf("an all-zones global is broader than a trust-only earlier, must not shadow, got: %v", findings)
	}

	// Control (positive): when the earlier global covers ALL zones it DOES
	// shadow a later trust-only global of a different action.
	cfg.Security.GlobalPolicies = []*config.Policy{
		scoped("g-permit-all", config.PolicyPermit, nil),
		scoped("g-deny-trust", config.PolicyDeny, []string{"trust"}),
	}
	findings := analyzePolicyShadowing(cfg)
	if len(findings) != 1 || !strings.Contains(findings[0], "g-deny-trust") || !strings.Contains(findings[0], "SHADOWED") {
		t.Fatalf("an all-zones earlier global must shadow a trust-only later global, got: %v", findings)
	}
}
