package config

import (
	"encoding/json"
	"testing"
)

// #8850, second half. With the container-brace relaxation in place, the filter
// case became REACHABLE by the scope mechanism and was then refused:
//
//	before the relaxation   asked=[]                    no entry could reach it
//	after  the relaxation   asked=[[firewall family]]   asked, NOT admitted
//
// So `firewall family inet { filter f1 { ... } }` still compiled to ZERO
// filters. This admits the pair.
//
// It is a SEPARATE change from the relaxation on purpose: `family` is a
// compoundKey node whose identity-advance (#8763) runs immediately above the
// gate that was relaxed, so the two interact, and landing them together would
// have made a red unattributable.
//
// ASSERTED ON CONTENTS. The whole Firewall struct is compared, not a filter or
// term COUNT -- a count went green against the sibling-attachment bug that
// silently emptied a zone in the first half of this issue.
func TestElidedFirewallFamily8850(t *testing.T) {
	fw := func(t *testing.T, txt string) string {
		t.Helper()
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		j, err := json.Marshal(cfg.Firewall)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(j)
	}
	for _, tc := range []struct{ name, braced, elided string }{
		{"inet",
			"firewall { family inet { filter f1 { term t1 { from { protocol tcp; } then { discard; } } } } }",
			"firewall family inet { filter f1 { term t1 { from { protocol tcp; } then { discard; } } } }"},
		{"inet6",
			"firewall { family inet6 { filter f6 { term t1 { then { accept; } } } } }",
			"firewall family inet6 { filter f6 { term t1 { then { accept; } } } }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, e := fw(t, tc.braced), fw(t, tc.elided)
			if b != e {
				t.Errorf("elided `firewall family %s` compiles DIFFERENTLY from braced (#8850)\n"+
					"  braced: %s\n  elided: %s\n"+
					"An elided container brace must not change the compiled firewall. "+
					"Before this fix the elided spelling produced ZERO filters with no "+
					"error on either path -- a firewall loading with no filters and "+
					"reporting success.", tc.name, b, e)
			}
		})
	}

	// DEGENERACY CONTROL: the comparison above is satisfied if BOTH spellings
	// produce nothing. Assert the braced form actually carries a filter, or the
	// cell passes vacuously against a regression that empties both.
	t.Run("braced-actually-has-a-filter", func(t *testing.T) {
		tree, _ := NewParser("firewall { family inet { filter f1 { term t1 { then { discard; } } } } }").Parse()
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if len(cfg.Firewall.FiltersInet) == 0 {
			t.Fatal("the braced reference config compiles to ZERO filters, so the " +
				"braced-vs-elided comparison in this cell proves nothing")
		}
	})
}

// #8850 DEPTH COVERAGE. The same stanza behaves differently at different
// elision depths, and the gate this issue relaxed predicts exactly which:
//
//	host-inbound-traffic { system-services { ping; } }   braced, works
//	host-inbound-traffic system-services { ping; }       PARTIALLY elided --
//	                                                     packed tail AND braced
//	                                                     body -> was LOST
//	host-inbound-traffic system-services ping;           FULLY packed -- no
//	                                                     children -> always worked
//
// A cell testing only the fully-packed form PASSES BEFORE THE FIX, which is how
// an otherwise sound method concluded `host-inbound-traffic` was unaffected.
// Both depths are therefore asserted: the partially-elided form is the one that
// regressed, and the fully-packed form is the control that must keep working.
//
// Every braced arm is checked to PRODUCE SOMETHING first. A braced arm that
// compiles to nothing makes its elided partner agree with it vacuously, and
// which direction that reads as a finding depends only on how the assertion is
// phrased.
func TestElidedDepthCoverage8850(t *testing.T) {
	services := func(t *testing.T, hib string) []string {
		t.Helper()
		txt := "security { zones { security-zone z1 { " + hib + " } } }"
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", hib, errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", hib, err)
		}
		for _, z := range cfg.Security.Zones {
			if z.HostInboundTraffic == nil {
				return nil
			}
			return z.HostInboundTraffic.SystemServices
		}
		return nil
	}

	const bracedHIB = "host-inbound-traffic { system-services { ping; } }"
	want := services(t, bracedHIB)
	if len(want) == 0 {
		t.Fatalf("the braced reference produced NO system-services, so every " +
			"comparison below would pass vacuously. Fix the fixture before " +
			"trusting any elided arm.")
	}

	for _, tc := range []struct{ name, hib string }{
		{"partially-elided", "host-inbound-traffic system-services { ping; }"},
		{"fully-packed", "host-inbound-traffic system-services ping;"},
		{"body-braced-inner-packed", "host-inbound-traffic { system-services ping; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := services(t, tc.hib)
			if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) {
				t.Errorf("`%s` compiled system-services=%v, braced gave %v.\n"+
					"The elision depth must not change the compiled result. The "+
					"PARTIALLY elided form (packed tail + braced body) is the one "+
					"that regressed; the FULLY packed form always worked and is the "+
					"control, so a cell testing only it passes before the fix.",
					tc.hib, got, want)
			}
		})
	}

	// The same asymmetry on a second child of the same container, so the
	// coverage is not one keyword deep.
	protocols := func(t *testing.T, hib string) int {
		t.Helper()
		tree, _ := NewParser("security { zones { security-zone z1 { " + hib + " } } }").Parse()
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		for _, z := range cfg.Security.Zones {
			if z.HostInboundTraffic == nil {
				return 0
			}
			return len(z.HostInboundTraffic.Protocols)
		}
		return 0
	}
	b := protocols(t, "host-inbound-traffic { protocols { ospf; } }")
	if b == 0 {
		t.Fatal("braced protocols reference produced nothing; comparison would be vacuous")
	}
	if e := protocols(t, "host-inbound-traffic protocols { ospf; }"); e != b {
		t.Errorf("partially-elided `protocols` gave %d, braced gave %d", e, b)
	}
}
