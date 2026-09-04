package config

import (
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

// Asserted on the compiled config rather than on the inventory file — so it
// stays true if the inventory is regenerated, and reds if someone changes the
// reader without updating the inventory.
//
// #8690 family 3 flipped this cell's SIDE, exactly as the zone-member cell
// below was flipped by family 2, and for the same reason it is kept rather than
// deleted. It began as "braced compiles transmit-rate to 125000000, elided to
// 0" — a verified divergence. `class-of-service schedulers <n> transmit-rate`
// is now in the normalizer's scope, so the two spellings AGREE and the cell
// asserts that instead.
//
// It announced the transition itself: it failed with "compact/block now AGREE
// … the reader was fixed. Remove the line from the inventory and update the
// note" rather than going quietly vacuous. That is the property worth keeping —
// deleting it would stop the site being checked in EITHER direction, which is
// the stale-allowlist failure the #2419 inventory exists to prevent, and a
// future change that puts the divergence back would then be silent.
func TestVerifiedChildrenClassIsNormalized8662(t *testing.T) {
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
	if es.TransmitRateBytes != bs.TransmitRateBytes {
		t.Errorf("elided transmit-rate compiled to %d, braced to %d — the two spellings "+
			"must AGREE now that `class-of-service schedulers <n> transmit-rate` is in "+
			"the normalizer's scope (#8690 family 3). A brace-elided scheduler rate that "+
			"compiles to %d silently gives the queue no shaping on a commit reporting "+
			"success.", es.TransmitRateBytes, bs.TransmitRateBytes, es.TransmitRateBytes)
	}
}

// The zone member #8662 was filed on. It was censused by the wildcard-named
// site-model change, and #8690's policy-enforcement family then NORMALIZED it,
// so the two spellings now agree.
//
// This cell has changed sides twice and that is the point of it. It began as
// "still uncovered" (the census could not see the shape), became "censused and
// still diverging" (it could see it, and what it saw was wrong), and is now
// "normalized" — each transition announced by the cell failing with the reason,
// rather than by anyone remembering to look. The last transition caught a
// change I made myself an hour later.
//
// Keeping it as an EQUIVALENCE assertion rather than deleting it is deliberate:
// deleting it would stop the site being checked in either direction, which is
// the stale-allowlist failure the #2419 inventory exists to prevent.
func TestWildcardNamedInstanceFoldIsNormalized8662(t *testing.T) {
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
	// POSITIVE HALF: the braced spelling must carry the membership, or the
	// equality below is between two empty slices and passes on a compiler that
	// reads neither.
	if len(bz.Interfaces) == 0 {
		t.Fatal("the braced spelling produced no zone interfaces — the fixture no longer " +
			"demonstrates membership being read, so the assertion below is vacuous")
	}
	if len(ez.Interfaces) != len(bz.Interfaces) {
		t.Errorf("the brace-elided zone membership compiled to %v, not %v — the zone boots with "+
			"different members than the operator wrote, and the elided form walks past the "+
			"strict gate that rejects the braced one for an undefined interface (#8662/#8690)",
			ez.Interfaces, bz.Interfaces)
	}
	// And it must have LEFT the inventory, or the inventory is stale.
	for _, line := range mustReadInventorySites8662(t) {
		if line == "security zones security-zone xpfarg interfaces" {
			t.Error("the site still sits in the inventory although the two spellings now agree; " +
				"regenerate it, or the file claims a divergence that no longer exists")
		}
	}
}

func mustReadInventorySites8662(t *testing.T) []string {
	t.Helper()
	sites, _ := readInventory(t)
	if len(sites) == 0 {
		t.Fatal("inventory has no sites; this cell proves nothing")
	}
	return sites
}

// The wildcard-named shape must not be admitted so broadly that it condemns
// containers that ARE read correctly. This is the over-reach control, and its
// subject is a chassis-cluster site deliberately: that is the area where this
// issue's prescribed blanket rule broke the shipped HA config.
func TestWildcardNamedFoldDoesNotCondemnAReadContainer8662(t *testing.T) {
	const braced = "chassis { cluster { redundancy-group 1 { ip-monitoring { family inet { 10.0.0.1 weight 100; } } } } }"
	const elided = "chassis { cluster { redundancy-group 1 { ip-monitoring family inet 10.0.0.1 weight 100; } } }"
	b, e := compileText(t, braced), compileText(t, elided)
	if b == nil || e == nil {
		t.Skip("fixture does not compile in this tree; the census's own EQUIVALENT verdict covers this site")
	}
	if !cfgEqual(b, e) {
		t.Error("`chassis cluster redundancy-group <n> ip-monitoring family inet` was measured " +
			"EQUIVALENT across both spellings when the wildcard-named shape was admitted. If it " +
			"now diverges, either the compiler regressed or this fixture drifted — check which " +
			"before adding it to the inventory")
	}
}
