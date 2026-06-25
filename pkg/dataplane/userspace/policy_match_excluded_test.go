package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestPolicySnapshotCarriesExcludedFlags verifies the
// source/destination-address-excluded modifiers (#2008 H2) propagate
// from the typed PolicyMatch onto the wire PolicyRuleSnapshot, so the
// dataplane can invert the match sense. Before the fix the snapshot
// had no such fields and the flag was lost at the Go->Rust boundary.
func TestPolicySnapshotCarriesExcludedFlags(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name: "excl",
							Match: config.PolicyMatch{
								SourceAddresses:            []string{"10.0.0.0/8"},
								DestinationAddresses:       []string{"192.168.0.0/16"},
								SourceAddressExcluded:      true,
								DestinationAddressExcluded: true,
							},
							Action: config.PolicyPermit,
						},
						{
							Name: "plain",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"any"},
								DestinationAddresses: []string{"any"},
							},
							Action: config.PolicyPermit,
						},
					},
				},
			},
		},
	}
	snaps, _ := buildPolicySnapshots(cfg)
	if len(snaps) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(snaps))
	}
	var excl, plain *PolicyRuleSnapshot
	for i := range snaps {
		switch snaps[i].Name {
		case "excl":
			excl = &snaps[i]
		case "plain":
			plain = &snaps[i]
		}
	}
	if excl == nil || plain == nil {
		t.Fatalf("missing expected rules: excl=%v plain=%v", excl, plain)
	}
	if !excl.SourceAddressExcluded {
		t.Errorf("excl.SourceAddressExcluded = false, want true")
	}
	if !excl.DestinationAddressExcluded {
		t.Errorf("excl.DestinationAddressExcluded = false, want true")
	}
	if plain.SourceAddressExcluded || plain.DestinationAddressExcluded {
		t.Errorf("plain rule must not carry excluded flags: src=%v dst=%v",
			plain.SourceAddressExcluded, plain.DestinationAddressExcluded)
	}
}
