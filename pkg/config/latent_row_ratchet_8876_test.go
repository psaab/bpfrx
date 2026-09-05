package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// THE LATENT-ROW RATCHET (#8876 census close).
//
// A LATENT row is an edge the brace-elision census adjudicated as NOT A DEFECT
// on a premise with an expiry date:
//
//	the edge is UNADMITTED, so the fold never fires -- but nothing is lost
//	TODAY, because the compiler happens to read the packed spelling natively.
//	ADD A VALUE-CARRYING LEAF TO THAT CONTAINER TOMORROW AND IT IS LOST
//	SILENTLY.
//
// The row is a prediction nobody is watching. This ratchet is what makes it
// fire at the moment it comes true: it counts the value-carrying leaves under
// each latent container, and reds when the count MOVES.
//
// # WHAT A FAILURE HERE MEANS
//
// It is not a regression in this file. It means someone added (or removed) a
// leaf under a container whose elided spelling drops values silently. The
// obligation is to ADJUDICATE THE NEW LEAF before landing -- compile the braced
// and elided spellings and check whether the value survives -- not to update the
// number until the test is green. Updating the constant without adjudicating is
// the one action this guard exists to prevent, which is why the failure text
// says so rather than saying "update the expected count".
//
// # THE #8876 DISTINCTION, STATED HERE BECAUSE IT IS WHERE IT GETS LOST
//
// LATENT is not INERT, and the census kept filing one as the other:
//
//	INERT   the value is discarded by the compiler REGARDLESS of spelling.
//	        There is nothing for the fold to lose -- not today, and not after
//	        someone adds a value, because this value already reaches nothing.
//	        An inert row needs no ratchet.
//	LATENT  the value is delivered by the braced spelling and would be lost by
//	        the elided one, and no leaf under it carries a value yet. The
//	        prediction is live; only its surface is missing.
//
// Only LATENT rows belong here. A row that is merely SILENT-and-harmless is
// neither.
//
// # CAVEATS THAT SURVIVED THE CENSUS AND MUST NOT BE RE-LEARNED
//
//   - COUNTS ARE UNIONED ACROSS EVERY SITE, never first-seen. A container
//     reachable by several paths is a DIFFERENT NODE at each, and first-seen-wins
//     made this set depend on Go's map iteration order (252 vs 255, measured).
//     `family inet` is the live example: 4 leaves across 2 sites, and the
//     census's own running list recorded it as 1 because it was measured at one.
//   - A ROW IS CLASSIFIED ACROSS ALL ITS LEAVES, NOT ONE. `policy-statement ->
//     then` was filed LATENT from a fixture that used `accept` -- one of exactly
//     two args:0 survivors out of ten children. All eight value-carrying routing
//     actions are dropped. It is a DEFECT, it is NOT in this table, and it must
//     not be re-added as latent.
//   - `chassis -> cluster` IS DELIBERATELY EXCLUDED despite adjudicating LATENT.
//     It carries 17 value-carrying leaves on an actively-developed container, so
//     a ratchet over it would fire on ordinary work -- and a guard that fires on
//     ordinary work gets worked around, which costs more than the row is worth.
//     Recorded here rather than dropped silently, so the exclusion is a decision
//     someone can reverse rather than an omission they have to rediscover.
//
// # WHY A COUNT AND NOT A SET
//
// The failure enumerates the actual leaves, so the diff is readable. The
// ASSERTION is on the count because that is what cannot be satisfied by editing
// the expectation to match a mistake: a set literal invites "add the new name
// and move on", which is precisely the non-adjudication this guard is for.
// MEMBERSHIP IS BY MEASUREMENT, NOT BY THE CENSUS'S LATENT LABEL. Five rows
// were adjudicated LATENT; only two survive the premise check below.
//
// THE PREMISE A LATENT ROW RESTS ON: "add a value-carrying leaf tomorrow and it
// is lost SILENTLY". That is a claim about what happens to a leaf the compiler
// does not yet know, and it is directly measurable -- put an UNKNOWN leaf under
// the container and see whether anything tells the operator:
//
//	ip ip-sweep                      unknown leaf -> STRICT-REJECTS + warning
//	icmp flood                       unknown leaf -> STRICT-REJECTS + warning
//	interfaces oversubscription-policy  unknown leaf -> warning
//	pool persistent-nat              unknown leaf -> SILENT
//	firewall family inet             unknown leaf -> SILENT
//
// The two screen rows are NOT LATENT: their family reader normalises packed
// tails through the GENERIC schema-driven `packedBody`, so a new leaf reaches
// the switch, lands in `default:`, and #3318's validateScreenUnknownStrict
// refuses the commit fail-closed. A future leaf there cannot vanish quietly --
// it is refused until someone adds compiler support. `interfaces
// oversubscription-policy` warns, so the operator is told.
//
// Keeping those three would have made this guard assert something FALSE in its
// own failure text ("drops values SILENTLY"), and a wrong diagnostic is worse
// than a missing one -- the reader trusts it and stops looking.
var latentRows8876 = map[string]int{
	"family inet":         4,
	"pool persistent-nat": 2,
}

func TestLatentRowsHaveNotGainedALeaf8876(t *testing.T) {
	head := func(e string) string { return strings.Fields(e)[0] }
	leaves := map[string]map[string]bool{}
	sites := map[string]map[string]bool{}
	for _, s := range collectCompactSites() {
		if len(s.container) < 2 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		k := head(s.container[len(s.container)-2]) + " " + head(s.container[len(s.container)-1])
		if _, ok := latentRows8876[k]; !ok {
			continue
		}
		if leaves[k] == nil {
			leaves[k] = map[string]bool{}
			sites[k] = map[string]bool{}
		}
		sites[k][strings.Join(s.container, "|")] = true
		if s.node != nil && (s.node.args >= 1 || s.node.multi || s.node.wildcard != nil) {
			leaves[k][s.leaf] = true
		}
	}

	var edges []string
	for k := range latentRows8876 {
		edges = append(edges, k)
	}
	sort.Strings(edges)

	for _, k := range edges {
		got, ok := leaves[k]
		if !ok {
			t.Errorf("latent edge %q reached NO SITE in the schema walk. Either the "+
				"container was renamed or removed, or collectCompactSites no longer "+
				"enumerates it -- in the second case this row is silently unguarded "+
				"and every other row in this table may be too (#8876)", k)
			continue
		}
		var names []string
		for l := range got {
			names = append(names, l)
		}
		sort.Strings(names)
		if len(names) == latentRows8876[k] {
			continue
		}
		verb := "GAINED"
		if len(names) < latentRows8876[k] {
			verb = "LOST"
		}
		t.Errorf("LATENT ROW %q %s a value-carrying leaf: expected %d, found %d "+
			"across %d site(s).\n  leaves now: %s\n"+
			"  This edge is UNADMITTED by compactNormalizeInScope, so its "+
			"brace-elided spelling drops values SILENTLY -- it was filed NOT A "+
			"DEFECT only because nothing under it carried a value worth losing. "+
			"That premise has now changed.\n"+
			"  ADJUDICATE THE NEW LEAF BEFORE LANDING: compile\n"+
			"      <parent> { <container> { <leaf> <value>; } }   and\n"+
			"      <parent> { <container> <leaf> <value>; }\n"+
			"  and compare with ConfigFingerprint. If the value is lost, this is a "+
			"live silent-drop defect and the fix is to admit the pair, not to "+
			"update the number here.\n"+
			"  DO NOT simply edit latentRows8876 to match. A count updated without "+
			"that comparison converts a caught defect into a filed one, which is "+
			"the single failure this guard exists to prevent (#8876).",
			k, verb, latentRows8876[k], len(names), len(sites[k]), strings.Join(names, " "))
	}

	total := 0
	for _, n := range latentRows8876 {
		total += n
	}
	t.Logf("#8876 latent ratchet: %d edges, %d value-carrying leaves, stable. "+
		"`chassis -> cluster` (17 leaves) is deliberately excluded -- see the "+
		"file comment. `policy-statement -> then` is a DEFECT, not latent.",
		len(latentRows8876), total)
	_ = fmt.Sprint()
}
