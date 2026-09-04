package config

import (
	"os"
	"strings"
	"testing"
)

// #8662. The compact/block census excluded every folded token that declares
// children, and excluded them SILENTLY — they landed in no skip bucket, so the
// census's own "this is a FLOOR" note did not account for them. Two shapes were
// verified by hand in #8662 and both sat in that hole.
//
// These cells are the positive control for the relaxed predicate. Without them
// a future tightening would shrink the census back and every downstream
// assertion would still pass, because a census that stops LOOKING at a site
// reports the same silence as one that finds it clean.

// The class must be non-empty AND must contain the member #8662 verified by
// hand. A count alone would be satisfied by any 97 sites.
func TestChildrenBearingFoldedTokensAreCensused8662(t *testing.T) {
	sites := collectCompactSites()
	withChildren := 0
	found := false
	for _, s := range sites {
		if len(s.node.children) > 0 {
			withChildren++
		}
		if strings.Join(s.container, " ") == "class-of-service schedulers xpfarg" && s.leaf == "transmit-rate" {
			found = true
			if len(s.node.children) == 0 {
				t.Error("transmit-rate no longer declares children; this cell's premise has changed " +
					"and the predicate relaxation it guards may no longer be doing anything")
			}
		}
	}
	if withChildren == 0 {
		t.Fatal("the census contains NO folded token that declares children — the `children == nil` " +
			"exclusion is back, and the class #8662 measured is invisible again (#8662)")
	}
	if !found {
		t.Error("`class-of-service schedulers xpfarg transmit-rate` is not censused. #8662 verified it " +
			"by hand: braced compiles transmit-rate to 125000000, elided to 0. If the census cannot " +
			"see it, the census cannot report on it either way")
	}
	t.Logf("#8662: %d censused sites whose folded token declares children", withChildren)
}

// The divergence itself, asserted on the compiled config rather than on the
// inventory file — so it stays true if the inventory is regenerated, and reds
// if someone "fixes" the reader without updating the inventory.
func TestVerifiedChildrenClassDivergences8662(t *testing.T) {
	braced := compileText(t, "class-of-service { schedulers be { transmit-rate 1g; } }")
	elided := compileText(t, "class-of-service { schedulers be transmit-rate 1g; }")
	if braced == nil || elided == nil {
		t.Fatal("both spellings must parse and compile")
	}
	bs, bok := braced.ClassOfService.Schedulers["be"]
	es, eok := elided.ClassOfService.Schedulers["be"]
	if !bok || !eok {
		t.Fatalf("both spellings must produce the scheduler; braced=%v elided=%v", bok, eok)
	}
	// The POSITIVE half: the braced spelling must actually carry the rate, or
	// the comparison below is between two zeroes and proves nothing.
	if bs.TransmitRateBytes == 0 {
		t.Fatal("the braced spelling compiled transmit-rate to 0 — the fixture no longer " +
			"demonstrates the value being read, so the divergence assertion is vacuous")
	}
	if es.TransmitRateBytes == bs.TransmitRateBytes {
		t.Logf("compact/block now AGREE for schedulers transmit-rate (%d) — the reader was fixed. "+
			"Remove `class-of-service schedulers xpfarg transmit-rate` from %s and update the "+
			"#8662 note", bs.TransmitRateBytes, inventoryPath)
		t.Fail()
	}
}

// The gap this change deliberately does NOT close, pinned so it is not
// mistaken for covered. `security-zone <z> interfaces <if>` names its instance
// with a WILDCARD, not an `args` token, which is outside the census's site
// model — a model change, not a predicate relaxation.
func TestWildcardNamedInstanceFoldIsStillUncovered8662(t *testing.T) {
	braced := compileText(t, "security { zones { security-zone trust { interfaces ge-0/0/0.0; } } }")
	elided := compileText(t, "security { zones { security-zone trust interfaces ge-0/0/0.0; } }")
	if braced == nil || elided == nil {
		t.Fatal("both spellings must parse and compile")
	}
	bz, bok := braced.Security.Zones["trust"]
	ez, eok := elided.Security.Zones["trust"]
	if !bok || !eok {
		t.Fatalf("both spellings must produce the zone; braced=%v elided=%v", bok, eok)
	}
	if len(bz.Interfaces) == 0 {
		t.Fatal("the braced spelling produced no zone interfaces — fixture no longer demonstrates " +
			"the membership being read, so this cell proves nothing")
	}
	if len(ez.Interfaces) == len(bz.Interfaces) {
		t.Logf("the wildcard-named-instance fold now AGREES (%v) — this gap is closed; extend the "+
			"census site model and update the #8662 note", ez.Interfaces)
		t.Fail()
	}
	// Not censused today, and that is the point of this cell.
	for _, s := range collectCompactSites() {
		if strings.Join(s.container, " ") == "security zones security-zone xpfarg" && s.leaf == "interfaces" {
			t.Errorf("the census now covers the wildcard-named-instance fold; this cell's " +
				"'still uncovered' claim is stale and the #8662 note needs updating")
		}
	}
	if os.Getenv("XPF_GEN_2419") == "1" {
		t.Skip("regenerating")
	}
}
