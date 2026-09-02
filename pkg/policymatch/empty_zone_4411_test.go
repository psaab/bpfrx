package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMatchEmptyZoneFallsToDefault locks #4411 A6 (avo-review-002): a
// `test security match-policies` query that OMITS the from-zone or to-zone
// selector passes an EMPTY-STRING zone name to Match. An empty string is not a
// configured zone, so zoneKnown reports false and the query must fall straight
// through to the configured default-policy — the simulator analogue of
// policy.rs's `from_id != 0 && to_id != 0` transit guard resolving an unknown
// (id 0) zone. The danger this locks against is an empty selector being
// (mis)read as a wildcard-any and MATCHING a `from-zone any to-zone any` rule,
// which would report a PERMIT the dataplane never grants.
//
// undefined_zone_3355_test.go already covers NON-EMPTY undefined zones
// ("bogus"/"nowhere") and the empty-Zones config; this pins the distinct
// EMPTY-STRING selector input class (an omitted zone), which no test exercised.
//
// FAIL-ON-REVERT: dropping the `!zoneKnown(...)` guard in Match (or making
// zoneKnown treat "" as known/any) routes every empty-zone case into the Tier 3
// both-any permit -> Matched=true permit, reddening the want-default-deny rows.
func TestMatchEmptyZoneFallsToDefault(t *testing.T) {
	permitAny := &config.Policy{
		Name:   "wide-open",
		Action: config.PolicyPermit,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
	}
	// A `from-zone any to-zone any` (Tier 3 both-any) permit is the trap: it
	// matches EVERY concrete zone pair, so an empty-zone query would match it too
	// if the guard were removed. DefaultPolicy is deny, so the guarded verdict is
	// distinguishable from the (wrong) permit.
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{FromZone: "any", ToZone: "any", Policies: []*config.Policy{permitAny}},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	cases := []struct {
		name     string
		from, to string
	}{
		{"both zones empty", "", ""},
		{"from-zone empty", "", "untrust"},
		{"to-zone empty", "trust", ""},
	}
	// #8318: an empty FROM zone is the unconditional unzoned-ingress deny; an
	// empty TO zone still falls through to default-policy, because the runtime
	// deliberately declines to deny on to_id == 0 ("would risk black-holing a
	// correctly-configured path"). Both are DENY under this deny-all fixture —
	// which is why one branch could stand in for both — so the rows now assert
	// WHICH.
	fromUnknown := func(from string) bool { return from == "" }
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Match(cfg, Query{FromZone: c.from, ToZone: c.to, Protocol: "tcp", DstPort: 80})
			if res.Matched {
				t.Fatalf("empty-zone query matched a both-any rule (#4411 A6); res = %+v", res)
			}
			if res.Action != config.PolicyDeny {
				t.Fatalf("want deny for an empty-zone query, got %+v", res)
			}
			if fromUnknown(c.from) {
				if !res.UnzonedIngress || res.DefaultUsed {
					t.Fatalf("an empty FROM zone must be the unzoned-ingress deny, "+
						"not a default-policy verdict, got %+v", res)
				}
			} else if !res.DefaultUsed || res.UnzonedIngress {
				t.Fatalf("an empty TO zone must still fall through to default-policy "+
					"(the runtime does not deny on to_id == 0), got %+v", res)
			}
		})
	}

	// Positive control: a fully-defined zone pair still matches the both-any
	// permit, so the guard rejects ONLY the empty-selector class, not real zones.
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("defined zone pair over-blocked by the empty-zone guard; res = %+v", res)
	}
}
