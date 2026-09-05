package config

import (
	"sort"
	"strings"
	"testing"
)

// #8690: separating "the compiler does not read this leaf" from "the leaf needs
// an in-stanza sibling before anything reads it".
//
// #8735 split the 236 not-observable sites into three classes and I described
// the largest — 219 sites whose stanza registers and whose leaf adds nothing —
// as "the compiler does not read the leaf". THAT WAS STRONGER THAN THE
// INSTRUMENT. The classifier cannot distinguish it from a leaf that is read
// only once a required sibling is present, which is the case #6821 documents
// and which is structurally unreachable from the fixture side (supplying the
// sibling gives the node children, and normalizeCompactNodes guards on
// `len(node.Children) == 0`).
//
// This file is the experiment that separates them, with a positive control.
//
// THE MEASUREMENT, at the head this landed on:
//
//	sibling-wall                            6/219   3%
//	genuinely-unread                       41/219  19%
//	inconclusive: the siblings were unread too  135/219  62%
//	inconclusive: no sibling leaf declared     36/219  16%
//	inconclusive: sibling fixture did not compile 1/219   0%
//
// So of the 47 that are DETERMINABLE the split is 41:6 — but 79% is not
// determinable, and the honest headline is that number rather than the ratio.
//
// TWO FIXTURE HYPOTHESES WERE TESTED AND BOTH FAILED on the dominant class:
//
//   - container siblings as well as leaf siblings (the generator emitted only
//     `args == 1` children): moved 4 of 137;
//   - a parent-chain preamble, measured by hand on
//     `class-of-service interfaces <i> unit <u> scheduler-map` — declaring the
//     interface in `interfaces {}`, declaring the scheduler-map, and both:
//     still not observable in every combination.
//
// That is why this is reported as a WALL and not a backlog. The remaining work
// per site is not "add a fixture entry"; the two mechanisms that could add one
// have been tried and do not move it.

// stanzaNodeFor8690 walks setSchema along a container token path.
//
// A container ELEMENT packs a name with its instance args ("unit xpfarg"), so
// it must be split before lookup. Treating the whole element as a child name
// returned nil for 85% of the population on the first run — and an 85% "cannot
// resolve" rate reads exactly like a result until you ask whether it is
// plausible.
func stanzaNodeFor8690(container []string) *schemaNode {
	n := setSchema
	for _, elem := range container {
		for _, seg := range strings.Fields(elem) {
			if seg == "xpfarg" {
				continue
			}
			if seg == "xpfname" {
				if n.wildcard == nil {
					return nil
				}
				n = n.wildcard
				continue
			}
			ch, ok := n.children[seg]
			if !ok {
				if n.wildcard == nil {
					return nil
				}
				n = n.wildcard
				continue
			}
			n = ch
		}
	}
	return n
}

// siblingText8690 builds `<name> <value>;` statements for the OTHER children of
// the stanza, from the schema's own declarations. Nothing is invented: a child
// with no synthesizable pair is skipped, so an unsynthesizable sibling produces
// no fixture rather than a guessed one.
func siblingText8690(stanza *schemaNode, exclude string, max int) string {
	if stanza == nil {
		return ""
	}
	names := make([]string, 0, len(stanza.children))
	for name := range stanza.children {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	n := 0
	for _, name := range names {
		if name == exclude || n >= max {
			continue
		}
		ch := stanza.children[name]
		if ch == nil {
			continue
		}
		if ch.args == 1 {
			if v, _, ok := synthPair(ch); ok {
				b.WriteString(name + " " + v + "; ")
				n++
			}
			continue
		}
		if ch.args == 0 && len(ch.children) > 0 {
			if inner := siblingText8690(ch, "", 3); inner != "" {
				b.WriteString(name + " { " + inner + "} ")
				n++
			}
		}
	}
	return b.String()
}

// Verdict names. Each is a claim someone can go and falsify.
const (
	unreadSiblingWall = "sibling-wall"
	unreadGenuinely   = "genuinely-unread"
	// unreadSiblingsAlsoUnread exists ONLY when the positive control rejects a
	// sibling fixture that changed nothing, so its count is the control's own
	// liveness signal.
	unreadSiblingsAlsoUnread = "inconclusive: the siblings were unread too"
)

// classifyUnread8690 runs the experiment for one site.
func classifyUnread8690(t *testing.T, s compactSite) string {
	t.Helper()
	v1, v2, ok := synthPair(s.node)
	if !ok {
		return "inconclusive: no probe pair"
	}
	parent := s.container[:len(s.container)-1]
	stanza := s.container[len(s.container)-1]
	ctx := contextForStanza(parent, stanza)
	pre := preambleFor(parent, stanza)
	build := func(inner string) *Config {
		return compileText(t, pre+nest(parent, ctx+stanza+" { "+inner+" }"))
	}
	a1 := build(s.leaf + " " + v1 + ";")
	if a1 == nil {
		return "inconclusive: base did not compile"
	}
	sn := stanzaNodeFor8690(s.container)
	if sn == nil {
		return "inconclusive: stanza node unresolved"
	}
	// SELF-CHECK: the node walked to must be the one declaring the leaf under
	// test, or every sibling below belongs to a different stanza.
	//
	// DELETING THIS IS NOT OBSERVABLE at this head, and saying so is the point:
	// the walker resolves every site correctly today, so the arm never fires
	// and a mutation removing it kills nothing. What actually enforces the
	// property is TestTheStanzaWalkerResolvesTheWholePopulation_8690, which
	// checks it over the population instead. This stays as the belt — it turns
	// a future walker regression into "inconclusive" rather than a confident
	// wrong verdict — but it is defence-in-depth, not a tested guard.
	if sn.children[s.leaf] != s.node {
		return "inconclusive: stanza node mismatch"
	}
	sawCandidate, sawCompile := false, false
	for _, max := range []int{6, 3, 1} {
		sib := siblingText8690(sn, s.leaf, max)
		if sib == "" {
			break
		}
		sawCandidate = true
		b1, b2 := build(sib+s.leaf+" "+v1+";"), build(sib+s.leaf+" "+v2+";")
		if b1 == nil || b2 == nil {
			continue // this sibling set does not compile; try a smaller one
		}
		sawCompile = true
		// POSITIVE CONTROL. The sibling must itself have changed the compiled
		// config. Without this, "still unread with a sibling" is a conclusion
		// drawn from a fixture that did not actually change.
		if cfgEqual(b1, a1) {
			continue
		}
		if !cfgEqual(b1, b2) {
			return unreadSiblingWall
		}
		return unreadGenuinely
	}
	switch {
	case !sawCandidate:
		return "inconclusive: no sibling declared"
	case !sawCompile:
		return "inconclusive: sibling fixture did not compile"
	default:
		return unreadSiblingsAlsoUnread
	}
}

// unreadPopulation8690 returns the #8735 "stanza registered, leaf contributed
// nothing" class — the 219.
func unreadPopulation8690(t *testing.T, res censusResult) []compactSite {
	t.Helper()
	empty := compileText(t, "")
	var pop []compactSite
	for _, s := range collectCompactSites() {
		key := strings.Join(s.container, " ") + " " + s.leaf
		if res.state[key] != "skipped: leaf value not observable" {
			continue
		}
		v1, _, ok := synthPair(s.node)
		if !ok {
			continue
		}
		parent := s.container[:len(s.container)-1]
		stanza := s.container[len(s.container)-1]
		ctx := contextForStanza(parent, stanza)
		pre := preambleFor(parent, stanza)
		b1 := compileText(t, pre+nest(parent, ctx+stanza+" { "+s.leaf+" "+v1+"; }"))
		skel := compileText(t, pre+nest(parent, ctx+stanza+" { }"))
		if b1 == nil || skel == nil || cfgEqual(b1, empty) || !cfgEqual(b1, skel) {
			continue
		}
		pop = append(pop, s)
	}
	sort.Slice(pop, func(i, j int) bool {
		return strings.Join(pop[i].container, " ")+" "+pop[i].leaf <
			strings.Join(pop[j].container, " ")+" "+pop[j].leaf
	})
	return pop
}

// The report. Counts move as other lanes normalize, so this logs rather than
// pins them; the two cells below pin the properties that must not change.
func TestUnreadVsSiblingWallReport_8690(t *testing.T) {
	pop := unreadPopulation8690(t, runCompactBlockCensus(t))
	t.Logf("#8690 unread-vs-sibling-wall: population %d", len(pop))
	counts := map[string]int{}
	for _, s := range pop {
		counts[classifyUnread8690(t, s)]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  %-46s %3d/%d = %.0f%%", k, counts[k], len(pop),
			100*float64(counts[k])/float64(len(pop)))
	}
}

// BOTH determinable classes must stay REACHABLE. A classifier whose interesting
// arms never fire reports "inconclusive" for everything and reads as a finding
// about the code — the same defect as a partition whose classes sum correctly
// while one of them is empty (#8735).
func TestBothDeterminableClassesAreReachable_8690(t *testing.T) {
	pop := unreadPopulation8690(t, runCompactBlockCensus(t))
	if len(pop) == 0 {
		t.Skip("the population is empty at this head; nothing to classify")
	}
	counts := map[string]int{}
	for _, s := range pop {
		counts[classifyUnread8690(t, s)]++
	}
	if counts[unreadSiblingWall] == 0 {
		t.Errorf("no site classified %q. The experiment's whole purpose is to "+
			"separate that case from a genuinely unread leaf; an arm that never "+
			"fires makes every other number a claim about one class wearing two "+
			"names (#8690)", unreadSiblingWall)
	}
	if counts[unreadGenuinely] == 0 {
		t.Errorf("no site classified %q — see above, in the other direction", unreadGenuinely)
	}
	// THE POSITIVE CONTROL MUST BE DOING WORK, and "some class is inconclusive"
	// cannot see that. Found by mutation: deleting the control turns every
	// siblings-were-unread site into a verdict, and a total over the
	// inconclusive classes stays non-zero because "no sibling declared" is
	// still populated — so the check passed a classifier with no control at
	// all. That is the same defect I reported on #8735 in the other direction:
	// a sum over classes cannot see one class going empty.
	//
	// The one class that EXISTS ONLY BECAUSE THE CONTROL REJECTS A FIXTURE is
	// the one to name.
	if counts[unreadSiblingsAlsoUnread] == 0 {
		t.Errorf("no site classified %q. That class is produced only when the "+
			"positive control rejects a sibling fixture for changing nothing, so "+
			"an empty one means the control is gone or never fires — and every "+
			"verdict above is then drawn from fixtures that may not have changed "+
			"(#8690)", unreadSiblingsAlsoUnread)
	}
}

// The walker must resolve EVERY site in the population, and resolve it to the
// node that declares the leaf under test.
//
// Both arms are defence-in-depth today — they fire for nothing at this head —
// which is exactly why they need a cell: an unfalsifiable guard is one nobody
// notices going wrong. The first run of this experiment returned "stanza node
// unresolved" for 85% of the population because container elements pack their
// instance args ("unit xpfarg"), and an 85% cannot-resolve rate reads like a
// finding about the code until someone asks whether it is plausible.
func TestTheStanzaWalkerResolvesTheWholePopulation_8690(t *testing.T) {
	pop := unreadPopulation8690(t, runCompactBlockCensus(t))
	if len(pop) == 0 {
		t.Skip("empty population at this head")
	}
	var unresolved, mismatched []string
	for _, s := range pop {
		where := strings.Join(s.container, " ") + " " + s.leaf
		sn := stanzaNodeFor8690(s.container)
		if sn == nil {
			unresolved = append(unresolved, where)
			continue
		}
		if sn.children[s.leaf] != s.node {
			mismatched = append(mismatched, where)
		}
	}
	if len(unresolved) > 0 {
		t.Errorf("%d/%d container paths did not resolve, e.g. %v — the classifier "+
			"reports 'inconclusive' for each, which is indistinguishable from a "+
			"real result (#8690)", len(unresolved), len(pop), unresolved[:min8690(3, len(unresolved))])
	}
	if len(mismatched) > 0 {
		t.Errorf("%d/%d resolved to a node that does not declare the leaf, e.g. %v "+
			"— the siblings would then belong to a different stanza",
			len(mismatched), len(pop), mismatched[:min8690(3, len(mismatched))])
	}

	// And the specific shape that broke it, asserted directly rather than only
	// through the population count.
	packed := stanzaNodeFor8690([]string{"class-of-service", "interfaces xpfarg", "unit xpfarg"})
	if packed == nil {
		t.Fatal("a container element packing an instance arg (`unit xpfarg`) does " +
			"not resolve; the walker is not splitting elements on whitespace")
	}
	if _, ok := packed.children["scheduler-map"]; !ok {
		t.Error("the packed path resolved to a node that is not the CoS interface " +
			"unit — it resolved to something, which is worse than resolving to nothing")
	}
}

func min8690(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// The six sibling-wall sites are all `security log stream <s>`, which is the
// container #6821 wrote the required-sibling mechanism for. That is a coherence
// check on the whole experiment: the case the census already knows needs a
// sibling is the case this classifier finds.
func TestTheSiblingWallLandsWhereSixEightTwoOneSaidItWould_8690(t *testing.T) {
	pop := unreadPopulation8690(t, runCompactBlockCensus(t))
	var walls []string
	for _, s := range pop {
		if classifyUnread8690(t, s) == unreadSiblingWall {
			walls = append(walls, strings.Join(s.container, " "))
		}
	}
	if len(walls) == 0 {
		t.Skip("no sibling-wall sites at this head")
	}
	for _, w := range walls {
		if !strings.HasPrefix(w, "security log stream") {
			t.Logf("NOTE: a sibling-wall site outside `security log stream`: %s. "+
				"That is new information rather than a failure — record it on "+
				"#8690 rather than widening this cell to accept it silently", w)
		}
	}
}
