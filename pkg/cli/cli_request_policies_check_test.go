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
