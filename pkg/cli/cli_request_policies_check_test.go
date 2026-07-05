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
