package userspace

// #6894 r9 F1 / #4960: the snapshot builder's DROP set and
// config.NPTv6ScopeUnsupported must be the same set.
//
// pkg/dataplane.compileNPTv6 now reads that predicate to decide whether a
// malformed NPTv6 prefix is a hard error (the rule reaches
// Nptv6State::try_from_snapshots, which rejects the whole snapshot at publish
// -- after compileZones has mutated the host, which is #4960) or a
// warn-and-skip (the rule is dropped here and never reaches the helper, so
// today's apply succeeds without it).
//
// Both directions of disagreement are live faults and they are not symmetric:
//
//   - predicate says EXCLUDED, builder EMITS  -> compileNPTv6 warns and skips a
//     rule the helper will refuse. The #4960 half-applied shape is back.
//   - predicate says INCLUDED, builder DROPS  -> compileNPTv6 hard-errors on a
//     rule that installs nothing, failing an apply that succeeds today. On the
//     tolerant load / peer-sync path that is the #1960 no-brick posture broken.
//
// This test can only live here: pkg/dataplane/userspace imports pkg/dataplane,
// so the dataplane package cannot import the builder to check itself.
//
// One side is DERIVED -- the emitted set comes from running the real
// buildNptv6Snapshots, not from a second hand-written list -- so a disagreement
// in BELIEF shows up here, not merely a typo. Sharing the predicate makes the
// test tautological only if the builder keeps calling it; a builder that
// reintroduced its own inline copy would diverge and this would catch it.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestNptv6BuilderDropSetMatchesScopePredicate_4960(t *testing.T) {
	// Each case is ONE rule in its own rule-set, so a drop is attributable.
	// Every field the predicate reads gets a case, plus the two accept shapes
	// (unscoped and from-zone-only) without which "the builder drops
	// everything" would satisfy the whole table.
	cases := []struct {
		name string
		rs   *config.StaticNATRuleSet
	}{
		{"unscoped", &config.StaticNATRuleSet{}},
		{"from-zone-only", &config.StaticNATRuleSet{FromZone: "untrust"}},
		{"from-interface", &config.StaticNATRuleSet{FromInterface: "ge-0/0/1.0"}},
		{"from-routing-instance", &config.StaticNATRuleSet{FromRoutingInstance: "vrf-4960"}},
		{"source-addresses", &config.StaticNATRuleSet{}},
		{"source-address", &config.StaticNATRuleSet{}},
		{"match-destination-port", &config.StaticNATRuleSet{}},
		// The two scope dimensions TOGETHER: a predicate that answered on only
		// one of them would still agree with the builder on every single-field
		// case above.
		{"interface-and-source", &config.StaticNATRuleSet{FromInterface: "ge-0/0/1.0"}},
	}
	perRule := map[string]func(*config.StaticNATRule){
		"source-addresses":       func(r *config.StaticNATRule) { r.SourceAddresses = []string{"2001:db8:c::/64"} },
		"source-address":         func(r *config.StaticNATRule) { r.SourceAddress = "2001:db8:c::/64" },
		"match-destination-port": func(r *config.StaticNATRule) { r.MatchDestinationPort = 8080 },
		"interface-and-source":   func(r *config.StaticNATRule) { r.SourceAddress = "2001:db8:c::/64" },
	}

	cfg := &config.Config{}
	type probe struct {
		rs   *config.StaticNATRuleSet
		rule *config.StaticNATRule
	}
	probes := make(map[string]probe, len(cases))
	for _, tc := range cases {
		rule := &config.StaticNATRule{
			Name: tc.name, IsNPTv6: true,
			// Prefixes the helper ACCEPTS. The scope dimension must be the only
			// reason a rule is dropped, or the table would not be measuring it.
			// Distinct per case so the emitted set is attributable by name.
			Match: "2001:db8:48::/48", Then: "fd00:48::/48",
		}
		if f, ok := perRule[tc.name]; ok {
			f(rule)
		}
		tc.rs.Name = tc.name
		tc.rs.Rules = []*config.StaticNATRule{rule}
		cfg.Security.NAT.Static = append(cfg.Security.NAT.Static, tc.rs)
		probes[tc.name] = probe{rs: tc.rs, rule: rule}
	}

	emitted := map[string]bool{}
	for _, snap := range buildNptv6Snapshots(cfg) {
		emitted[snap.Name] = true
	}

	// FLOOR: an empty or all-emitting result would make the comparison below
	// vacuous in one direction or the other.
	if len(emitted) == 0 {
		t.Fatal("buildNptv6Snapshots emitted nothing at all — the fixture is " +
			"not reaching the builder, so this test cannot observe its drop set")
	}
	if len(emitted) == len(cases) {
		t.Fatalf("buildNptv6Snapshots emitted every one of the %d rules — the "+
			"fixture no longer carries a droppable scope, so agreement below is "+
			"vacuous", len(cases))
	}

	for name, p := range probes {
		wantDropped := config.NPTv6ScopeUnsupported(p.rs, p.rule)
		gotEmitted := emitted[name]
		if wantDropped == gotEmitted {
			t.Errorf("rule %q: config.NPTv6ScopeUnsupported=%v but "+
				"buildNptv6Snapshots emitted=%v — the predicate and the builder "+
				"disagree about whether this rule reaches "+
				"Nptv6State::try_from_snapshots.\n\n"+
				"pkg/dataplane.compileNPTv6 uses that predicate to decide whether "+
				"a malformed prefix on this rule is a HARD ERROR or a "+
				"warn-and-skip. If the predicate says EXCLUDED while the builder "+
				"EMITS, a bad prefix is skipped and the helper rejects the whole "+
				"snapshot AFTER compileZones mutated the host (#4960). If it says "+
				"INCLUDED while the builder DROPS, the compile fails an apply "+
				"that succeeds today (#5818 / #1960 no-brick).",
				name, wantDropped, gotEmitted)
		}
	}
}
