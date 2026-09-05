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
	realKeys := map[[2]string]bool{}
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
		for k := range recordScopeKeys8690(text, false) {
			realKeys[k] = true
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

	// NON-VACUITY, and a MEASURED correction to why this recorder is admit-all.
	//
	// The intent was that admit-all explores PAST a refusal, so the recorded
	// chain would not be truncated at today's scope. Asserting that as a hard
	// control FAILED on the real code, which is how the assumption got checked:
	// admit-all observes exactly the same keys as the real predicate for every
	// site here. At the packing the census synthesizes, folding a node does not
	// expose a further packed node, so these chains are ONE LINK and there is
	// nothing past the refusal to reach.
	//
	// READ THAT AS A FACT ABOUT THE FIXTURES, NOT ABOUT THE PASS. It is easy to
	// take "these chains are one link" as a property of the normalizer, and it
	// is not -- it is a property of the packing this census synthesizes. The
	// same content written the way a config file writes it produces three
	// links, measured with an injected recorder (#8763):
	//
	//	family inet { dhcp lease-time 600; }   touched=0  asked=[]
	//	family inet dhcp lease-time 600;       touched=3  asked=[family inet | inet dhcp | dhcp lease-time]
	//
	// So admit-all IS load-bearing for a real spelling and observes nothing
	// extra only here. The first version of this note said "0 is expected"
	// without that qualifier, which would have told a future reader that
	// chains do not cascade -- a claim about production drawn from a probe
	// artifact, which is the exact error this file has recorded three lanes
	// making today.
	//
	// (That the braced spelling asks NOTHING is #8763, a traversal defect in
	// the pass, not a property of packing. It is why the two lines differ by
	// more than link count.)
	//
	// lane-8367's multi-link chains were
	// measured on MAXIMALLY-packed spellings; this fixture set is not that.
	//
	// The recorder stays admit-all because it is correct for the case where
	// chains do cascade, and costs nothing where they do not. But the claim
	// this cell can make is correspondingly narrower, so it is stated rather
	// than assumed: the comparison below is over the keys consulted AT THIS
	// PACKING. A pair that looks separable here can share a key at another one.
	//
	// What is still asserted is the part that would make the cell vacuous: the
	// recorder must observe something. A recorder wired to the wrong function,
	// or one never invoked, records nothing and every site trivially "agrees".
	widened := 0
	for k := range allKeys {
		if !realKeys[k] {
			widened++
		}
	}
	if len(allKeys) == 0 {
		t.Fatal("the recorder observed NO scope keys at all — it is not reaching the " +
			"pass, so every comparison below is between empty sets and passes for the " +
			"wrong reason (#8690)")
	}
	t.Logf("#8690 recorder: %d key(s) observed, %d reachable only with admit-all "+
		"(0 expected: the CENSUS FIXTURES are one link — a real spelling is not, "+
		"see the note above)",
		len(allKeys), widened)

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
