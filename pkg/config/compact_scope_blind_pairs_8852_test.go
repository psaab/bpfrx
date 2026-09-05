package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #8852: a scope widening whose pair yields ZERO census sites is
// indistinguishable from one the guard fully adjudicated. Both are green.
//
// THE DEFECT. TestCompactNormalizeScopePreservesCompiledResult8690 (arm 2)
// adjudicates the sites collectCompactSites generates. That census emits a site
// only for a SINGLE-ARG VALUED LEAF or a NAMED-INSTANCE container:
//
//	wildcardNamed := ch.args == 0 && ch.wildcard != nil
//	if (ch.wildcard == nil && ch.args == 1 || wildcardNamed) && len(path) >= 1 {
//
// So admitting a pair whose HEAD is a plain container, a zero-arg leaf, or a
// multi-arg node produces no site at all — the pair is adjudicated by nothing,
// and nothing in the output says so. It does not even reach a skip bucket:
// the unsynthesizable / unparsable / inScopeUnexaminable buckets are populated
// per SITE, and there is no site.
//
// MEASURED. #8847 admitted three top-level pairs and arm 2 adjudicated NONE of
// them. Attribution was established by REMOVING the three entries from
// compactNormalizeInScope and re-counting: the adjudicated total was unchanged,
// so no adjudicated site depended on them. That toggle is the only sound
// instrument here — a substring or path-prefix test over the site paths
// attributes `routing-options static route` to ("routing-options","static")
// when its actual pair is ("static","route"), because the arm derives
// `stanza := container[len-1]`. A site's path prefix is not its pair.
//
// WHY A SET AND NOT A THRESHOLD, and why the reason is DERIVED rather than
// declared. This is the same shape as the inScopeUnexaminable list above it: a
// NEW blind pair reds, and a pair that BECOMES adjudicated also reds, so the
// list cannot quietly outlive its reason. The registered reason is then
// RE-DERIVED from the schema on every run and compared, so registration cannot
// become a silent escape hatch — you cannot park a pair here with a reason that
// is not true of its node. And a pair blind for NO recognised structural reason
// fails outright: that is a bug in the census, not a registrable exception.
//
// Registering a pair here is NOT a statement that its folding is correct. It
// records that this arm does not measure it. Blind means unmeasured, not safe.
//
// AND TWO OF THESE ARE CONFIRMED BROKEN, so do not read the list as a benign
// inventory. Measured braced-vs-elided, both compiling clean through the strict
// path with the value simply gone:
//
//	security-zone address-book   braced addresses=1  -> elided 0
//	policies from-zone           braced policies=1   -> elided 0
//
// The second is the product's primary enforcement surface: the elided
// `security policies from-zone <a> to-zone <b> { ... }` spelling compiles to
// ZERO zone-pair policies. Their fixes belong to #8850, not here — this cell
// measures the GUARD's coverage, not the fold's correctness, and repairing a
// fold does not remove its pair from this list (the pair leaves only when arm 2
// starts generating a site for it).
//
// The `policies from-zone` measurement needs its zones DEFINED in the braced
// arm; without `security-zone trust` / `untrust` present the braced control
// fails an undefined-zone gate and the comparison is vacuous in the direction
// that looks like a defect.
//
// A third pair, `security-zone host-inbound-traffic`, was reported broken and
// did NOT reproduce here: `system-services` and `protocols` both survive the
// elided spelling, and the both-leaves-packed form is correctly REJECTED with a
// specific diagnostic. Recorded as unreproduced rather than omitted, because a
// list of confirmed defects that quietly drops a member is how a claim outlives
// its evidence.
var knownBlindScopePairs8852 = map[string]string{
	// Head is a plain container (args==0, no wildcard, has children).
	"policies global":            "plain-container",
	"policy then":                "plain-container",
	"routing-options static":     "plain-container",
	"security alg":               "plain-container",
	"security flow":              "plain-container",
	"security-zone address-book": "plain-container",
	// #8850 admitted ("firewall","family") so an elided `firewall family inet
	// { filter ... }` compiles its filters instead of silently producing zero.
	// `family` is args:0 with children and no wildcard, so blindShape8852
	// classifies it plain-container like the rest of this group -- the census
	// emits no site for it, which is why arm 2 adjudicates nothing. Registered
	// rather than left to red: the pair is admitted deliberately and its
	// behaviour is asserted directly by TestElidedFirewallFamily8850, which
	// compares the WHOLE Firewall struct braced-vs-elided for inet and inet6.
	"firewall family":                    "plain-container",
	"security-zone host-inbound-traffic": "plain-container",
	// Head takes two or more identity args.
	//
	// #8850 admitted ("address-book","address") and ("global","address") so that
	// an elided `address-book address a1 10.0.0.1/32;` compiles its entries
	// instead of silently producing an EMPTY book. `address` is args:2 (name and
	// prefix), so blindShape8852 classifies both multi-arg and the census emits
	// no site -- arm 2 adjudicates nothing for them.
	//
	// Registered rather than left to red, on the same terms as `firewall family`
	// above: the pair is admitted deliberately and its behaviour is asserted
	// DIRECTLY by TestElidedAddressBook8850, which compares the compiled address
	// NAMES braced-vs-elided for both books at one and at TWO entries. The
	// two-entry arm is the one that matters -- the scope entry alone folds a
	// multi-statement run into one and silently keeps only the first.
	"address-book address":    "multi-arg",
	"global address":          "multi-arg",
	"gateway local-identity":  "multi-arg",
	"gateway remote-identity": "multi-arg",
	"policies from-zone":      "multi-arg",
	"policy pre-shared-key":   "multi-arg",
	// Head is a leaf that takes no arg of its own.
	"flow tcp-mss":                       "zero-arg-leaf",
	"match destination-address-excluded": "zero-arg-leaf",
	"match source-address-excluded":      "zero-arg-leaf",
}

// blindShape8852 classifies WHY the census emits no site for a head node,
// mirroring the emission condition in collectCompactSites. Returns "" when the
// node's shape IS one the census emits, so a caller can tell "blind for a known
// structural reason" from "blind for a reason this model does not explain".
func blindShape8852(n *schemaNode) string {
	switch {
	case n == nil:
		return "not-found"
	case n.args >= 2:
		return "multi-arg"
	case n.args == 0 && n.wildcard == nil && n.children != nil:
		return "plain-container"
	case n.args == 0 && n.wildcard == nil && n.children == nil:
		return "zero-arg-leaf"
	}
	return "" // the census DOES emit sites for this shape
}

func TestScopeWideningYieldsAdjudicatedSites8852(t *testing.T) {
	// Sites per (container, head). A container ELEMENT may hold several
	// space-separated tokens ("application xpfarg" is ONE element), so flatten
	// and split before walking back past the schema arg placeholders — keying
	// on container[len-1] verbatim makes almost every named-instance pair look
	// blind, which is how this census first reported 213 instead of 14.
	siteCount := map[[2]string]int{}
	for _, s := range collectCompactSites() {
		if len(s.container) == 0 {
			continue
		}
		toks := strings.Fields(strings.Join(s.container, " "))
		ci := len(toks) - 1
		for ci > 0 && strings.HasPrefix(toks[ci], "xpf") {
			ci--
		}
		siteCount[[2]string{toks[ci], s.leaf}]++
	}

	admitted := map[[2]string]*schemaNode{}
	var walk func(n *schemaNode, kw string, d int)
	walk = func(n *schemaNode, kw string, d int) {
		if n == nil || d > 9 {
			return
		}
		for name, ch := range n.children {
			if kw != "" && compactNormalizeInScope(kw, name) {
				admitted[[2]string{kw, name}] = ch
			}
			walk(ch, name, d+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, kw, d+1)
		}
	}
	walk(setSchema, "", 0)

	if len(admitted) == 0 {
		t.Fatal("DEGENERACY: no admitted pair was reachable in the schema, so " +
			"every check below is vacuous")
	}

	var blind []string
	unexplained := map[string]string{}
	derived := map[string]string{}
	for p, node := range admitted {
		if siteCount[p] > 0 {
			continue
		}
		key := p[0] + " " + p[1]
		blind = append(blind, key)
		shape := blindShape8852(node)
		derived[key] = shape
		if shape == "" || shape == "not-found" {
			unexplained[key] = shape
		}
	}
	sort.Strings(blind)

	// A pair blind for no recognised structural reason is a census bug, not a
	// registrable exception — registration is bounded to the width of the
	// mechanism it describes.
	if len(unexplained) > 0 {
		t.Errorf("%d admitted pair(s) yield NO census site for a reason this "+
			"model does not explain: %v\nThe census emits a site only for a "+
			"single-arg valued leaf or a named-instance container. A pair "+
			"blind outside that set means collectCompactSites changed and this "+
			"classifier did not — fix the census or the classifier, do NOT "+
			"register it (#8852).", len(unexplained), unexplained)
	}

	var want []string
	for k := range knownBlindScopePairs8852 {
		want = append(want, k)
	}
	sort.Strings(want)
	if strings.Join(blind, "\n") != strings.Join(want, "\n") {
		t.Errorf("the set of admitted pairs arm 2 adjudicates NOTHING for has "+
			"changed.\n got %d:\n  %s\nwant %d:\n  %s\n"+
			"A NEW entry means a widening was admitted that "+
			"TestCompactNormalizeScopePreservesCompiledResult8690 does not "+
			"measure at all — it is green and silent about that pair, which is "+
			"indistinguishable from having adjudicated it. A REMOVED entry "+
			"means a pair became adjudicated and its registration must go, so "+
			"this list cannot outlive its reason (#8852).",
			len(blind), strings.Join(blind, "\n  "),
			len(want), strings.Join(want, "\n  "))
	}

	// The registered reason is RE-DERIVED and compared, so a pair cannot be
	// parked here under a reason that is not true of its node.
	for key, reg := range knownBlindScopePairs8852 {
		got, ok := derived[key]
		if !ok {
			continue // set mismatch already reported above
		}
		if got != reg {
			t.Errorf("blind pair %q is registered as %q but its schema node is "+
				"%q. The reason is re-derived every run precisely so a "+
				"registration cannot drift from the shape that causes it "+
				"(#8852).", key, reg, got)
		}
	}

	t.Logf("#8852: %d admitted pairs, %d with >=1 adjudicated site, %d blind (all registered)",
		len(admitted), len(admitted)-len(blind), len(blind))
	_ = fmt.Sprint
}
