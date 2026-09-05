package config

import "testing"

const screenDef8794 = `security { screen { ids-option edge { icmp { ping-death; } } } `

// TestBracketedZoneGroupCreatesEveryZone8794 asserts the ABSOLUTE outcome of
// each spelling: every named zone exists and carries the shared body.
//
// #8794: `security-zone [ trust untrust ] { screen edge; }` created only
// `trust`. The later zone was not created AT ALL — not merely missing its
// body — because namedInstances takes Keys[1] and discards Keys[2:].
//
// SEVERITY, measured rather than inferred from the shape. This is fail-CLOSED
// and loud, not the fail-open the originating report traced. A policy naming
// the lost zone is hard-rejected at strict commit ("references undefined
// to-zone"), and the tolerant path accepts it with two warnings, one naming the
// zone. The Rust screen authority's ScreenVerdict::Pass for an unconfigured
// zone is real (screen/tests.rs calls it "the legit Pass case") but NOT
// reachable here: the lost zone has no interfaces, because a grouped body's
// interfaces land in the zone that survived, so no packet can carry that zone.
// The harm is ordering — commit the group before anything references it and the
// loss is silent until a later, unrelated commit fails confusingly.
//
// WHY NOT "grouped == longhand". Two spellings each producing ONE zone agree
// perfectly, so an equality cell is green on exactly this defect. Each spelling
// is asserted to produce BOTH zones AND the shared profile.
func TestBracketedZoneGroupCreatesEveryZone8794(t *testing.T) {
	want := map[string]string{"trust": "edge", "untrust": "edge"}

	check := func(t *testing.T, label, text string) {
		t.Helper()
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: fixture must parse: %v", label, perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Fatalf("%s: strict compile: %v", label, err)
		}
		for name, profile := range want {
			z := cfg.Security.Zones[name]
			if z == nil {
				t.Errorf("%s: zone %q was not created. A grouped statement names it and the "+
					"commit succeeded, so a policy referencing it will fail a LATER commit "+
					"pointing at the policy rather than at this statement (#8794)", label, name)
				continue
			}
			if z.ScreenProfile != profile {
				t.Errorf("%s: zone %q ScreenProfile=%q, want %q — the zone exists but did "+
					"not inherit the shared body (#8794)", label, name, z.ScreenProfile, profile)
			}
		}
	}

	t.Run("bracketed group", func(t *testing.T) {
		check(t, "bracketed group",
			screenDef8794+`zones { security-zone [ trust untrust ] { screen edge; } } }`)
	})
	// The lexer strips brackets, so this is the spelling ConfigTree.Format
	// emits and therefore what crosses the Format -> SyncApply boundary to a
	// peer. It must behave identically or a primary and its standby disagree.
	t.Run("bare group as Format emits it", func(t *testing.T) {
		check(t, "bare group",
			screenDef8794+`zones { security-zone trust untrust { screen edge; } } }`)
	})
	// CONTROL: the longhand always worked and must keep working.
	t.Run("control two explicit blocks", func(t *testing.T) {
		check(t, "control",
			screenDef8794+`zones { security-zone trust { screen edge; } security-zone untrust { screen edge; } } }`)
	})
	// A PACKED TAIL IS NOT A GROUP and must not be fanned out: it has surplus
	// keys and NO braced body. Sweeping it in would invent zones named after
	// PROPERTY tokens.
	//
	// TESTED AGAINST THE DISCRIMINATOR DIRECTLY, not through a compile. The
	// first version of this subtest fed `security-zone trust screen edge;`
	// through compileConfigWithOpts and asserted no `screen`/`edge` zone
	// appeared — and it was VACUOUS: the #8690 normalizer admits
	// ("security-zone","screen") and pre-splits that tail into
	// `Keys=[security-zone trust] children=1` before compileZones ever runs, so
	// the input never reached the discriminator. Mutation proved it: weakening
	// the guard to `len(Keys) >= 3` alone SURVIVED, because the shape it would
	// mishandle could not get there. Calling the function directly is the only
	// way to put the packed shape in front of it.
	t.Run("discriminator rejects a bodiless packed tail", func(t *testing.T) {
		group := &Node{
			Keys:     []string{"security-zone", "trust", "untrust"},
			Children: []*Node{{Keys: []string{"screen", "edge"}}},
		}
		packed := &Node{Keys: []string{"security-zone", "trust", "screen", "edge"}}

		got := zoneGroupInstances8794([]*Node{group})
		if len(got) != 2 {
			t.Errorf("a braced group yielded %d instance(s), want 2 (#8794)", len(got))
		}
		got = zoneGroupInstances8794([]*Node{packed})
		if len(got) != 1 {
			t.Errorf("a BODILESS packed tail yielded %d instance(s), want 1. Surplus keys "+
				"without a braced body are PROPERTY tokens, and fanning them out invents "+
				"zones named `screen` and `edge` (#8794)", len(got))
			for _, g := range got {
				t.Errorf("   invented instance: %q", g.name)
			}
		} else if got[0].name != "trust" {
			t.Errorf("bodiless packed tail resolved to name %q, want \"trust\"", got[0].name)
		}
	})
}
