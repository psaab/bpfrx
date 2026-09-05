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
