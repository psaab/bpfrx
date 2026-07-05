// #4161 (fable-review-164 M-3, paired L-9 test-gap): source-NAT rule-set
// precedence is Junos MOST-SPECIFIC-SCOPE-WINS, not config-order first-match.
// These tests pin the tier ordering (interface > zone > routing-instance >
// unscoped), the same-tier config-order tie-break, the from-vs-to MIN(tier)
// combination edge, and the single-scope identity case. The Rust matcher
// (userspace-dp/src/nat/source.rs) is first-match on slice order, so the Go
// snapshot builder STABLE-sorts the emitted snapshot by context tier and the
// FIRST matching rule becomes the most-specific one — meaning these
// emission-order assertions ARE the precedence assertions.
//
// RED-on-revert: reverting the sort.SliceStable in
// buildSourceNATSnapshotsWithFeeds turns
// TestSourceNATInterfaceScopedRuleDefinedAfterZoneStillWins and
// TestSourceNATScopeTierOrdering RED (config order would place the broader-
// scope rule-set first).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// snatRuleSet builds a source-NAT rule-set carrying the given scope with a
// single interface-mode rule. The Match is left match-any: these tests assert
// the emitted SNAPSHOT ORDER (the precedence contract the Rust first-match loop
// reads), not the per-flow match, so the match terms are irrelevant.
func snatRuleSet(name, fromZone, toZone, fromIf, toIf, fromRI, toRI string) *config.NATRuleSet {
	return &config.NATRuleSet{
		Name:                name,
		FromZone:            fromZone,
		ToZone:              toZone,
		FromInterface:       fromIf,
		ToInterface:         toIf,
		FromRoutingInstance: fromRI,
		ToRoutingInstance:   toRI,
		Rules: []*config.NATRule{{
			// Snapshot.Name carries the RULE name; name the sole rule after its
			// rule-set so the emitted-order assertions read cleanly.
			Name: name,
			Then: config.NATThen{Type: config.NATSource, Interface: true},
		}},
	}
}

func snatOrder(t *testing.T, sets ...*config.NATRuleSet) []string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.NAT.Source = sets
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != len(sets) {
		t.Fatalf("len(snaps) = %d, want %d", len(snaps), len(sets))
	}
	names := make([]string, len(snaps))
	for i, s := range snaps {
		names[i] = s.Name
	}
	return names
}

// TestSourceNATScopeTierValue pins the pure tier function: interface=0, zone=1,
// routing-instance=2, unscoped=3, and MIN(from,to) when both contexts are set.
func TestSourceNATScopeTierValue(t *testing.T) {
	cases := []struct {
		name string
		snap SourceNATRuleSnapshot
		want int
	}{
		{"interface-from", SourceNATRuleSnapshot{FromInterface: "ge-0/0/1.0"}, snatTierInterface},
		{"interface-to", SourceNATRuleSnapshot{ToInterface: "ge-0/0/2.0"}, snatTierInterface},
		{"zone-from", SourceNATRuleSnapshot{FromZone: "trust"}, snatTierZone},
		{"zone-to", SourceNATRuleSnapshot{ToZone: "untrust"}, snatTierZone},
		{"ri-from", SourceNATRuleSnapshot{FromRoutingInstance: "VR1"}, snatTierRoutingInstance},
		{"ri-to", SourceNATRuleSnapshot{ToRoutingInstance: "VR1"}, snatTierRoutingInstance},
		{"unscoped", SourceNATRuleSnapshot{}, snatTierUnscoped},
		// from-vs-to = MIN: from zone (1) + to interface (0) => 0.
		{"from-zone-to-interface-min0", SourceNATRuleSnapshot{FromZone: "trust", ToInterface: "ge-0/0/2.0"}, snatTierInterface},
		// from routing-instance (2) + to zone (1) => 1.
		{"from-ri-to-zone-min1", SourceNATRuleSnapshot{FromRoutingInstance: "VR1", ToZone: "untrust"}, snatTierZone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sourceNATScopeTier(c.snap); got != c.want {
				t.Fatalf("sourceNATScopeTier(%+v) = %d, want %d", c.snap, got, c.want)
			}
		})
	}
}

// TestSourceNATInterfaceScopedRuleDefinedAfterZoneStillWins is the finding's
// own trace and the RED-on-revert guard: an interface-scoped rule-set defined
// textually AFTER a zone-scoped one still wins (emitted first) because
// interface is the more specific context. On revert of the tier-sort the
// zone-scoped set — first in config order — would be emitted first and win,
// bypassing the more-specific `source-nat off` exemption. This is the L-9 gap.
func TestSourceNATInterfaceScopedRuleDefinedAfterZoneStillWins(t *testing.T) {
	// RS-ZONE first, RS-IF second (config order) — both match ge-0/0/1 in zone
	// trust. Junos picks RS-IF (interface most specific).
	order := snatOrder(t,
		snatRuleSet("rs-zone", "trust", "", "", "", "", ""),
		snatRuleSet("rs-if", "", "", "ge-0/0/1.0", "", "", ""),
	)
	if order[0] != "rs-if" {
		t.Fatalf("interface-scoped rule must win over an earlier zone-scoped rule; emission order = %v, want rs-if first", order)
	}
}

// TestSourceNATScopeTierOrdering pins the full hierarchy
// interface > zone > routing-instance > unscoped. Rule-sets are declared in
// REVERSE specificity order (least specific first) to prove the sort — not
// config order — governs.
func TestSourceNATScopeTierOrdering(t *testing.T) {
	order := snatOrder(t,
		snatRuleSet("rs-unscoped", "", "", "", "", "", ""),
		snatRuleSet("rs-ri", "", "", "", "", "VR1", ""),
		snatRuleSet("rs-zone", "trust", "", "", "", "", ""),
		snatRuleSet("rs-if", "", "", "ge-0/0/1.0", "", "", ""),
	)
	want := []string{"rs-if", "rs-zone", "rs-ri", "rs-unscoped"}
	for i, w := range want {
		if order[i] != w {
			t.Fatalf("tier ordering = %v, want %v", order, want)
		}
	}
}

// TestSourceNATScopeSameTierKeepsConfigOrder proves the stable-sort tie-break:
// two equally-specific (both zone-scoped) rule-sets keep their config order,
// and their rules stay contiguous (no interleaving).
func TestSourceNATScopeSameTierKeepsConfigOrder(t *testing.T) {
	order := snatOrder(t,
		snatRuleSet("rs-a", "trust", "untrust-a", "", "", "", ""),
		snatRuleSet("rs-b", "trust", "untrust-b", "", "", "", ""),
	)
	if order[0] != "rs-a" || order[1] != "rs-b" {
		t.Fatalf("same-tier rule-sets must keep config order; got %v, want [rs-a rs-b]", order)
	}
}

// TestSourceNATScopeSameTierMultiRuleStaysContiguous proves a rule-set's own
// rules keep their within-set order and stay grouped after the sort, even when
// a more-specific rule-set is spliced ahead of it.
func TestSourceNATScopeSameTierMultiRuleStaysContiguous(t *testing.T) {
	zoneSet := &config.NATRuleSet{
		Name:     "rs-zone",
		FromZone: "trust",
		Rules: []*config.NATRule{
			{Name: "z-r1", Then: config.NATThen{Type: config.NATSource, Interface: true}},
			{Name: "z-r2", Then: config.NATThen{Type: config.NATSource, Interface: true}},
		},
	}
	ifSet := snatRuleSet("rs-if", "", "", "ge-0/0/1.0", "", "", "")
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{zoneSet, ifSet}
	snaps := buildSourceNATSnapshots(cfg, nil)
	got := make([]string, len(snaps))
	for i, s := range snaps {
		got[i] = s.Name
	}
	// interface rule-set (tier 0) first, then the zone rule-set's rules in
	// their original within-set order (tier 1).
	want := []string{"rs-if", "z-r1", "z-r2"}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("rule ordering = %v, want %v (within-set order + contiguity)", got, want)
		}
	}
}

// TestSourceNATScopeFromVsToMinTierWins pins the from-vs-to combination edge:
// a rule-set scoped `from zone trust` AND `to interface ge-0/0/2` is ranked by
// the MORE-specific of the two contexts (interface, tier 0), so it wins over a
// pure zone-scoped rule (tier 1) even when declared later.
func TestSourceNATScopeFromVsToMinTierWins(t *testing.T) {
	order := snatOrder(t,
		snatRuleSet("rs-zone-only", "trust", "", "", "", "", ""),
		snatRuleSet("rs-zone-and-egress-if", "trust", "", "", "ge-0/0/2.0", "", ""),
	)
	if order[0] != "rs-zone-and-egress-if" {
		t.Fatalf("from-vs-to MIN(tier): a to-interface context must rank a rule above a pure-zone rule; got %v, want rs-zone-and-egress-if first", order)
	}
}

// TestSourceNATScopeSingleScopeUnchanged proves the sort is an identity for a
// config whose rule-sets are all the same specificity (the common case): order
// is preserved bit-for-bit, so existing single-scope configs are unaffected.
func TestSourceNATScopeSingleScopeUnchanged(t *testing.T) {
	order := snatOrder(t,
		snatRuleSet("rs-1", "trust", "untrust", "", "", "", ""),
		snatRuleSet("rs-2", "dmz", "untrust", "", "", "", ""),
		snatRuleSet("rs-3", "trust", "dmz", "", "", "", ""),
	)
	want := []string{"rs-1", "rs-2", "rs-3"}
	for i, w := range want {
		if order[i] != w {
			t.Fatalf("single-tier config must be unchanged; got %v, want %v", order, want)
		}
	}
}
