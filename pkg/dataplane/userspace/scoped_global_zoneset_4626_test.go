package userspace

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4626 M03: a multi-zone scoped global lowers to an ADDITIVE wire snapshot —
// the singular match_from_zone/match_to_zone keeps the FIRST zone (rolling-
// upgrade backward compat with an old helper) while the plural
// match_from_zones/match_to_zones carries the FULL set. Both round-trip, and an
// old snapshot that carries only the singular field falls back to it.
func TestScopedGlobalMultiZoneWireAdditive(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			GlobalPolicies: []*config.Policy{
				{
					Name: "g-multi",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
						FromZones:            []string{"dmz", "trust"},
						ToZones:              []string{"untrust"},
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
	if len(snaps) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(snaps))
	}
	s := snaps[0]

	// Singular = first element for old-helper degradation.
	if s.MatchFromZone != "dmz" || s.MatchToZone != "untrust" {
		t.Errorf("singular wire = %q->%q, want dmz->untrust (first element)", s.MatchFromZone, s.MatchToZone)
	}
	// Plural = full set.
	if !reflect.DeepEqual(s.MatchFromZones, []string{"dmz", "trust"}) {
		t.Errorf("plural MatchFromZones = %q, want [dmz trust]", s.MatchFromZones)
	}
	if !reflect.DeepEqual(s.MatchToZones, []string{"untrust"}) {
		t.Errorf("plural MatchToZones = %q, want [untrust]", s.MatchToZones)
	}

	// JSON round-trip preserves both.
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rt PolicyRuleSnapshot
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(rt.MatchFromZones, s.MatchFromZones) || rt.MatchFromZone != s.MatchFromZone {
		t.Errorf("round-trip drift: from %q/%q -> %q/%q", s.MatchFromZone, s.MatchFromZones, rt.MatchFromZone, rt.MatchFromZones)
	}
	if !reflect.DeepEqual(rt.effectiveMatchFromZones(), []string{"dmz", "trust"}) {
		t.Errorf("effectiveMatchFromZones = %q, want [dmz trust]", rt.effectiveMatchFromZones())
	}

	// Old snapshot: singular only, plural absent → effective resolution falls
	// back to the singular (a safe single-zone degradation).
	var old PolicyRuleSnapshot
	if err := json.Unmarshal([]byte(`{"match_from_zone":"trust","match_to_zone":"untrust"}`), &old); err != nil {
		t.Fatalf("unmarshal old: %v", err)
	}
	if len(old.MatchFromZones) != 0 {
		t.Errorf("old snapshot MatchFromZones = %q, want empty (plural absent)", old.MatchFromZones)
	}
	if got := old.effectiveMatchFromZones(); len(got) != 1 || got[0] != "trust" {
		t.Errorf("old snapshot effectiveMatchFromZones = %q, want [trust]", got)
	}
}
