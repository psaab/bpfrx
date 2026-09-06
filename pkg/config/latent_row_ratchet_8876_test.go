package config

import (
	"fmt"
	"slices"
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
// # IT WAS A COUNT. THE ARGUMENT FOR THAT WAS WRONG, AND HERE IS WHY.
//
// This table held an INT per edge, justified as: "a set literal invites `add the
// new name and move on', which is precisely the non-adjudication this guard is
// for." That reasoning does not survive being stated next to its alternative.
// Bumping `4` to `5` is exactly as cheap as appending a name -- the thing that
// actually resists a lazy edit is the failure TEXT and the adjudication it
// demands, not the data type. The count bought nothing on the axis it was
// chosen for.
//
// AND IT PAID FOR THAT NOTHING WITH A BLIND SPOT: a SWAP. Lose `filter`, gain
// `policer`, and the count is still 4 -- a new value-carrying leaf appears under
// an unadmitted edge, exactly the event this ratchet exists to catch, and it
// passes in silence. A rename is the ordinary way that happens.
//
// Found while repairing a DIFFERENT ratchet (#8807) whose good-news branch --
// "unmeasured rows FELL, tighten the constant" -- would have banked a coverage
// loss as progress. The lesson generalised: A RATCHET KEYED ON A COUNT CANNOT
// SEE A SUBSTITUTION, and the direction that looks like nothing happened is the
// one nobody audits. Recorded as a falsified argument rather than quietly
// rewritten, because the next person to prefer a count over a set deserves the
// counterexample and not just the conclusion.
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
var latentRows8876 = map[string][]string{
	"family inet":         {"address", "filter", "mtu", "unnumbered-address"},
	"pool persistent-nat": {"inactivity-timeout", "permit"},
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
		want := append([]string(nil), latentRows8876[k]...)
		sort.Strings(want)
		if slices.Equal(names, want) {
			continue
		}
		var gained, lost []string
		for _, n := range names {
			if !slices.Contains(want, n) {
				gained = append(gained, n)
			}
		}
		for _, n := range want {
			if !slices.Contains(names, n) {
				lost = append(lost, n)
			}
		}
		// A SWAP -- equal counts, different members -- is the case the old
		// count-keyed assertion could not see at all.
		verb := "CHANGED"
		switch {
		case len(gained) > 0 && len(lost) == 0:
			verb = "GAINED " + strings.Join(gained, " ")
		case len(lost) > 0 && len(gained) == 0:
			verb = "LOST " + strings.Join(lost, " ")
		case len(gained) > 0 && len(lost) > 0:
			verb = "SWAPPED (lost " + strings.Join(lost, " ") +
				", gained " + strings.Join(gained, " ") + ")"
		}
		t.Errorf("LATENT ROW %q %s its value-carrying leaves: expected %v, found %v "+
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
			"  DO NOT simply edit latentRows8876 to match. A membership list "+
			"updated without that comparison converts a caught defect into a filed "+
			"one, which is the single failure this guard exists to prevent (#8876).",
			k, verb, want, names, len(sites[k]), strings.Join(names, " "))
	}

	total := 0
	for _, n := range latentRows8876 {
		total += len(n)
	}
	t.Logf("#8876 latent ratchet: %d edges, %d value-carrying leaves, stable. "+
		"`chassis -> cluster` (17 leaves) is deliberately excluded -- see the "+
		"file comment. `policy-statement -> then` is a DEFECT, not latent.",
		len(latentRows8876), total)
	_ = fmt.Sprint()
}
