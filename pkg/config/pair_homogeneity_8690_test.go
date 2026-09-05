package config

import (
	"sort"
	"strings"
	"testing"
)

// withRecordedScopeKeys8690 runs fn with the scope predicate replaced by an
// ADMIT-ALL recorder, and returns every (container, head) key the pass
// consulted. It restores the real predicate before returning.
//
// This is the only method that has produced a correct attribution of sites to
// pairs. Three separate attempts to DERIVE the pair from a site's path each
// gave a different wrong answer: the container path carries the schema arg
// placeholder where production passes node.Keys[0], and a site's key chain is a
// property of the SPELLING rather than of the site. Asking the pass removes the
// derivation entirely -- there is no model left to drift.
//
// Admit-all is deliberate. With the real predicate the pass stops walking as
// soon as a link is refused, so it would report only the keys that happen to be
// admitted TODAY and the guard would go quiet exactly as the scope widened.
func withRecordedScopeKeys8690(fn func()) map[[2]string]bool {
	seen := map[[2]string]bool{}
	saved := compactNormalizeInScope
	defer func() { compactNormalizeInScope = saved }()
	compactNormalizeInScope = func(containerKeyword, head string) bool {
		seen[[2]string{containerKeyword, head}] = true
		return true
	}
	fn()
	return seen
}

// withRealScopeKeys8690 records the keys consulted under the REAL predicate. It
// exists only as the denominator for the admit-all recorder's non-vacuity
// control below.
func withRealScopeKeys8690(fn func()) map[[2]string]bool {
	seen := map[[2]string]bool{}
	saved := compactNormalizeInScope
	defer func() { compactNormalizeInScope = saved }()
	compactNormalizeInScope = func(containerKeyword, head string) bool {
		ok := compactNormalizeInScopeDefault(containerKeyword, head)
		seen[[2]string{containerKeyword, head}] = true
		return ok
	}
	fn()
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
		keys := withRecordedScopeKeys8690(func() {
			if tree, perrs := NewParser(text).Parse(); len(perrs) == 0 && tree != nil {
				normalizeCompactStanzas(tree)
			}
		})
		if len(keys) > 0 {
			keysBySite[siteKey] = keys
		}
		for k := range withRealScopeKeys8690(func() {
			if tree, perrs := NewParser(text).Parse(); len(perrs) == 0 && tree != nil {
				normalizeCompactStanzas(tree)
			}
		}) {
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
	// nothing past the refusal to reach. lane-8367's multi-link chains were
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
		"(0 is expected here — these chains are one link at the census packing)",
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
