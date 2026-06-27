package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGlobalPolicyEmitsZoneContext (#3148) proves the snapshot builder keeps a
// global policy's structural zones on the junos-global sentinel (so the Rust
// classifier keeps it in the global tier) while carrying its optional
// from-zone/to-zone match context out-of-band in MatchFromZone/MatchToZone.
//
// Fail-on-revert: dropping the MatchFromZone/MatchToZone wiring in
// buildOneRuleSnapshot leaves both empty, turning the assertions RED — the
// dataplane would then evaluate the global policy against every zone pair
// (all-zones), the exact #3148 bug.
func TestGlobalPolicyEmitsZoneContext(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			GlobalPolicies: []*config.Policy{
				{
					Name: "scoped",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
						FromZone:             "trust",
						ToZone:               "untrust",
					},
					Action: config.PolicyPermit,
				},
				{
					Name: "all-zones",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
					},
					Action: config.PolicyDeny,
				},
			},
		},
	}
	snaps, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(snaps))
	}

	scoped := snaps[0]
	if scoped.FromZone != "junos-global" || scoped.ToZone != "junos-global" {
		t.Fatalf("scoped global rule structural zones = %q->%q, want junos-global on both",
			scoped.FromZone, scoped.ToZone)
	}
	if scoped.MatchFromZone != "trust" || scoped.MatchToZone != "untrust" {
		t.Fatalf("scoped global rule zone context = %q->%q, want trust->untrust",
			scoped.MatchFromZone, scoped.MatchToZone)
	}

	allZones := snaps[1]
	if allZones.MatchFromZone != "" || allZones.MatchToZone != "" {
		t.Fatalf("all-zones global rule must carry no zone context, got %q->%q",
			allZones.MatchFromZone, allZones.MatchToZone)
	}
}
