package config

import (
	"sort"
	"strings"
	"testing"
)

// recordScopeKeys8690 runs the pass over `text` with an ADMIT-ALL recorder
// injected, and returns every (container, head) key the pass consulted.
//
// This is the only method that has produced a correct attribution of sites to
// pairs. Three separate attempts to DERIVE the pair from a site's path each
// gave a different wrong answer: the container path carries the schema arg
// placeholder where production passes node.Keys[0], and a site's key chain is a
// property of the SPELLING rather than of the site. Asking the pass removes the
// derivation entirely -- there is no model left to drift.
//
// The predicate is INJECTED, not swapped into a package var. A mutable global
// would be reassignable by anything in the package, would poison every later
// test if a restore were forgotten, and would make t.Parallel() a data race --
// none of which announce themselves. An argument has no rule to remember.
func recordScopeKeys8690(text string, admitAll bool) map[[2]string]bool {
	seen := map[[2]string]bool{}
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 || tree == nil {
		return seen
	}
	normalizeCompactStanzasWithScope(tree, func(containerKeyword, head string) bool {
		seen[[2]string{containerKeyword, head}] = true
		if admitAll {
			return true
		}
		return compactNormalizeInScope(containerKeyword, head)
	})
	return seen
}

// TestSitesThatCannotBeSeparatedShareAClass8690 is the class-level form of a
// hazard that has so far been handled one instance at a time.
//
// Admission is decided per (container, head) PAIR; the register classifies per
// SITE. When one site's key set CONTAINS another's, admitting the first
// necessarily admits everything the second needs, so the second folds too --
// the two cannot be given different verdicts no matter what a per-site
// measurement says. `security ike policy <p> proposal-set` and `security ipsec
// policy <p> proposal-set` are the live instance: both key on
// ("policy","proposal-set"), the discriminator (ike/ipsec) sits one level ABOVE
// the container and is therefore outside the key, and both fold today. That
// pair was handled BY HAND in ipsec_ike_fold_8690_test.go, which is what makes
// this a handled-instance-not-class gap.
//
// WRITTEN WHILE EVERY GROUP STILL AGREES, deliberately. A guard that lands
// after a split has to grandfather it, and an exemption on day one is what the
// next reader trusts. This one is born green.
//
// WHAT IT DOES NOT CLAIM. It measures ONE spelling per site -- the census's
// synthesized packing. A site's chain depends on its packing, so two sites that
// look separable here can share a key at a shallower packing. That is a real
// limit and the reason this reports rather than proves separability: a red is a
// definite hazard, a green is "not at this packing".
func TestSitesThatCannotBeSeparatedShareAClass8690(t *testing.T) {
	reg := readPermanentExclusions8690(t)

	keysBySite := map[string]map[[2]string]bool{}
	allKeys := map[[2]string]bool{}
	for _, s := range collectCompactSites() {
		if len(s.container) == 0 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		parent := s.container[:len(s.container)-1]
		stanza := s.container[len(s.container)-1]
		v1, _, ok := synthPair(s.node)
		if !ok {
			continue
		}
		siteKey := strings.Join(s.container, " ") + " " + s.leaf
		if _, inReg := reg[siteKey]; !inReg {
			continue // only register sites carry a class to compare
		}
		text := nest(parent, contextFor(parent)+stanza+" "+s.leaf+" "+v1+";")
		keys := recordScopeKeys8690(text, true)
		if len(keys) > 0 {
			keysBySite[siteKey] = keys
		}
		for k := range keys {
			allKeys[k] = true
		}
	}
	if len(keysBySite) == 0 {
		t.Fatal("recorded no scope keys for any register site — the recorder is not " +
			"reaching the pass, so this cell proves nothing. A green here would be " +
			"vacuous (#8690)")
	}

	// WHY THE RECORDER IS ADMIT-ALL, and the limit that follows from it.
	//
	// The intent was that admit-all explores PAST a refusal, so a recorded
	// chain is not truncated at today's scope. Asserting that as a hard control
	// FAILED on the real code, which is how the assumption got checked:
	// admit-all observes exactly the same keys as the real predicate for every
	// site here. At the packing this census synthesizes, folding a node does
	// not expose a further packed node, so these chains are ONE LINK and there
	// is nothing past a refusal to reach.
	//
	// READ THAT AS A FACT ABOUT THE FIXTURES, NOT ABOUT THE PASS. The same
	// content written the way a config file writes it produces three links:
	//
	//	family inet { dhcp lease-time 600; }   touched=0  asked=[]
	//	family inet dhcp lease-time 600;       touched=3  asked=[family inet | inet dhcp | dhcp lease-time]
	//
	// (The braced form asking NOTHING is #8763, a traversal defect in the pass
	// rather than a property of packing, which is why those two lines differ by
	// more than link count.)
	//
	// That claim is ASSERTED, not left in prose:
	// TestRealSpellingsCascadeUnlikeTheCensusPacking8690 pins that a one-line
	// spelling consults more than one key. A second recorder pass used to run
	// here to compute the same fact and only LOG it — an unasserted traversal
	// with no claim attached — and it is gone; the assertion in that cell is
	// where the fact belongs.
	//
	// ── THE LIMIT THIS PUTS ON THE COMPARISON BELOW ──────────────────────────
	//
	// THE CONTAINMENT TEST DEGENERATES TO EQUALITY HERE, and the cell's name
	// promises more than that. Every key set this cell compares has exactly ONE
	// element, so there are no proper subset relations at all.
	//
	// The counts are deliberately NOT written here. A comment carrying "10
	// equal pairs, 0 proper subsets" is accurate for one head and wrong at the
	// next — the register moved from 68 sites to 66 while this note was being
	// written. The SHAPE is the claim, and the check below enforces it; the
	// numbers are logged where they can be read fresh.
	//
	// A one-element set contains another only by being equal to it, so
	// `subset()` never takes its general branch and what this cell tests is
	// "sites sharing THE SAME SINGLE KEY share a class". That is the live
	// ipsec/ike hazard and it is worth guarding — but it is not chain
	// containment, and a reader who sees `subset` will assume it is.
	//
	// The danger is the reading rather than the code. At REAL packings chains
	// are two to four links, which is where proper subsets would exist and
	// where this guard would matter most; it looks where chains are one link
	// long. A guard built to catch census artifacts is itself measuring at the
	// census packing — the fourth form of that error found today, and the first
	// found inside the countermeasure.
	//
	// So: a RED here is a definite hazard. A GREEN is "no hazard among sites
	// whose single census key matches", not "these sites are separable".
	// properSubsets below keeps that note from going stale.
	t.Logf("#8690 recorder: %d distinct key(s) observed across %d register site(s)",
		len(allKeys), len(keysBySite))

	subset := func(a, b map[[2]string]bool) bool {
		if len(a) > len(b) {
			return false
		}
		for k := range a {
			if !b[k] {
				return false
			}
		}
		return true
	}
	var sites []string
	for s := range keysBySite {
		sites = append(sites, s)
	}
	sort.Strings(sites)

	// Keep the note above honest. If key sets ever stop being single-element,
	// `subset()` starts doing what its name says and the degeneracy paragraph
	// becomes false — a comment describing a version of the code that no longer
	// exists, which is the defect class this file was built to record.
	//
	// This reds on an IMPROVEMENT, deliberately, and asks for a comment change
	// rather than a revert. Nothing here should be reverted to make it green.
	sizes, equalPairs, properSubsets, multiKey := keySetShape8690(keysBySite)
	t.Logf("#8690 key-set shape: sizes=%v, %d ordered pair(s) with EQUAL sets, "+
		"%d with a PROPER subset", sizes, equalPairs, properSubsets)
	if multiKey > 0 || properSubsets > 0 {
		t.Errorf("the degeneracy note above is now FALSE: %d site(s) have a key set "+
			"larger than one element and %d proper subset relation(s) exist. `subset()` "+
			"has started doing what its name says, which is an IMPROVEMENT — the guard "+
			"now covers chain containment rather than only shared single keys. UPDATE "+
			"THE NOTE to say so; do not revert anything to make this green (#8690)",
			multiKey, properSubsets)
	}

	var bad []string
	for _, a := range sites {
		for _, b := range sites {
			if a == b {
				continue
			}
			// keys(B) subset-of keys(A): admitting A admits everything B needs,
			// so B folds whenever A does and cannot hold a different verdict.
			if subset(keysBySite[b], keysBySite[a]) && reg[a].class != reg[b].class {
				bad = append(bad, "  "+a+" ["+reg[a].class+"]\n    forces "+
					b+" ["+reg[b].class+"]")
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("%d site pair(s) carry DIFFERENT classes that admission cannot separate:\n%s\n"+
			"Admission is per (container, head) pair; these classifications are per site. "+
			"For each pair above, every key the second site needs is already needed by the "+
			"first, so admitting the first folds the second too — whatever the second was "+
			"measured to require. A per-site verdict the mechanism cannot honour is not a "+
			"verdict.\n"+
			"Do NOT reclassify to make this green: that would record a measurement nobody "+
			"took. Either the pass needs a finer scoping key at the shared link, or one of "+
			"the two sites is misclassified and needs re-measuring (#8690).",
			len(bad), strings.Join(bad, "\n"))
	}
	t.Logf("#8690 pair homogeneity: %d register site(s) attributed to scope keys by "+
		"MEASUREMENT (admit-all recorder), no inseparable pair disagrees on class",
		len(keysBySite))
}

// TestRealSpellingsCascadeUnlikeTheCensusPacking8690 pins the claim the note in
// TestSitesThatCannotBeSeparatedShareAClass8690 makes about its own limits.
//
// That note says the census's one-link chains are a property of the FIXTURES,
// not of the pass, and that a real spelling cascades — which is why the
// admit-all recorder is load-bearing in general even though it observes nothing
// extra there. Written as a comment that claim is unfalsifiable, and a comment
// asserting a measurement is the defect class this file was built to record.
//
// DELIBERATELY NOT A PIN ON THE #8763 BUG. The braced spelling currently asks
// for NOTHING, which is that traversal defect; asserting that would encode a
// bug as an expectation and red when it is fixed. What is asserted here is the
// part that survives the fix: a one-line spelling consults MORE THAN ONE key,
// so chains do cascade and admit-all can reach past a refusal. Fixing #8763
// should make the braced form cascade too, and must not affect this cell.
func TestRealSpellingsCascadeUnlikeTheCensusPacking8690(t *testing.T) {
	const oneLine = "interfaces { ge-0/0/0 { unit 0 { family inet dhcp lease-time 600; } } }"
	keys := recordScopeKeys8690(oneLine, true)
	if len(keys) < 2 {
		t.Errorf("a one-line spelling consulted %d scope key(s), want >= 2. The note in "+
			"TestSitesThatCannotBeSeparatedShareAClass8690 tells readers that the "+
			"census's one-link chains are a fixture artifact and that real spellings "+
			"cascade — if this holds at 1, that note is now false and admit-all is not "+
			"load-bearing anywhere. Correct the note rather than deleting this cell "+
			"(#8690, #8763): keys=%v", len(keys), keys)
	}
	// And the census packing must still be the SHALLOWER of the two, or the
	// note's whole distinction has evaporated and the limit it states no
	// longer bounds anything.
	braced := recordScopeKeys8690(
		"interfaces { ge-0/0/0 { unit 0 { family inet { dhcp lease-time 600; } } } }", true)
	if len(braced) >= len(keys) {
		t.Logf("#8690/#8763: the braced spelling now consults %d key(s) vs the one-line "+
			"spelling's %d. If #8763 has landed this is expected and the note in the "+
			"cell above should drop its two-line table, which describes the pre-fix "+
			"behaviour", len(braced), len(keys))
	}
}

// keySetShape8690 summarises a site->keys map: the size distribution, and how
// many ordered pairs stand in an EQUAL or a PROPER-subset relation.
//
// Extracted from the cell so it can be exercised against a SYNTHETIC input.
// Inside the cell it only ever sees single-element sets, so every mutation of
// its subset arithmetic escaped — the arms that matter cannot fire on today's
// data. That is the same reason #8613 built its census machinery a synthetic
// struct to run against.
func keySetShape8690(keysBySite map[string]map[[2]string]bool) (sizes map[int]int, equalPairs, properSubsets, multiKey int) {
	sizes = map[int]int{}
	sub := func(a, b map[[2]string]bool) bool {
		if len(a) > len(b) {
			return false
		}
		for k := range a {
			if !b[k] {
				return false
			}
		}
		return true
	}
	for a, ka := range keysBySite {
		sizes[len(ka)]++
		if len(ka) > 1 {
			multiKey++
		}
		for b, kb := range keysBySite {
			if a == b || !sub(kb, ka) {
				continue
			}
			if len(kb) == len(ka) {
				equalPairs++
			} else {
				properSubsets++
			}
		}
	}
	return sizes, equalPairs, properSubsets, multiKey
}

// The freshness guard above fires only when key sets stop being single-element,
// which cannot happen at this packing — so nothing in the live cell can kill a
// mutation of its arithmetic. This exercises the same function against inputs
// that DO have the shapes it is meant to detect.
func TestKeySetShapeDetectsWhatTheNoteDenies8690(t *testing.T) {
	k := func(pairs ...[2]string) map[[2]string]bool {
		m := map[[2]string]bool{}
		for _, p := range pairs {
			m[p] = true
		}
		return m
	}
	a := [2]string{"family", "inet"}
	b := [2]string{"inet", "filter"}
	c := [2]string{"filter", "input"}

	t.Run("today's shape: all single, no relations but equality", func(t *testing.T) {
		sizes, eq, proper, multi := keySetShape8690(map[string]map[[2]string]bool{
			"s1": k(c), "s2": k(c), "s3": k(a),
		})
		if multi != 0 || proper != 0 {
			t.Errorf("single-element sets reported multiKey=%d proper=%d", multi, proper)
		}
		if eq != 2 {
			t.Errorf("equalPairs=%d, want 2 (s1<->s2 both directions)", eq)
		}
		if sizes[1] != 3 {
			t.Errorf("sizes=%v, want three single-element sets", sizes)
		}
	})

	t.Run("a chain: proper subset detected", func(t *testing.T) {
		_, _, proper, multi := keySetShape8690(map[string]map[[2]string]bool{
			"deep":    k(a, b, c),
			"shallow": k(c),
		})
		if proper != 1 {
			t.Errorf("properSubsets=%d, want 1 — {c} is strictly inside {a,b,c}, which "+
				"is the containment the cell's name promises and the case its live "+
				"data cannot produce", proper)
		}
		if multi != 1 {
			t.Errorf("multiKey=%d, want 1", multi)
		}
	})

	t.Run("disjoint sets are neither", func(t *testing.T) {
		_, eq, proper, _ := keySetShape8690(map[string]map[[2]string]bool{
			"x": k(a), "y": k(b),
		})
		if eq != 0 || proper != 0 {
			t.Errorf("disjoint single-element sets reported eq=%d proper=%d — the "+
				"relation would then hold between any two sites", eq, proper)
		}
	})
}
