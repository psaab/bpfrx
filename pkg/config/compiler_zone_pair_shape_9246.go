package config

import "strings"

// malformedZonePairShape9246 reports the residue of a bracketed `to-zone` list
// on a hierarchical `from-zone X to-zone Y` node, or "" when the shape is fine.
//
// THE SIGNATURE IS THE ABSORBED RULE, not merely "an unexpected child".
// `to-zone [ untrust dmz ]` lexes to the ordinary 4-key shape and pushes the
// whole statement onto one leaf:
//
//	[from-zone trust to-zone untrust]
//	  [dmz policy p1 then permit]      <- Keys[0] is a zone name, `policy` follows
//
// so the pair compiles with ZERO policies and the authored rule exists nowhere.
// The test is therefore: a child whose FIRST key is not `policy` but which
// carries `policy` later in the same key list. That pair of conditions is what
// distinguishes absorbed tokens from every legitimate child.
//
// WHY NOT "any child that is not `policy`", which is what this checked first:
// it has real false positives, and they were found by running the suite rather
// than by reasoning about it.
//
//   - `inactive: policy p1 ...` is a supported Junos marker and lands as a
//     child whose first key is `inactive:`. Flagging it refused a spelling the
//     product accepts (TestInactive_UpgradeEquivalence).
//   - the #2419 census synthesises placeholder paths such as
//     `from-zone xpfarg xpfarg xpfarg policy ...`, which are not configs at all.
//
// SCOPE: `from-zone [ ... ]` is deliberately NOT flagged here. It collapses the
// other way -- the keys shift so Keys[3] becomes the literal "to-zone" -- and
// is ALREADY refused today, as an undefined zone named "to-zone". That message
// blames the wrong thing, but it is loud, and the silent to-zone case is the
// defect. Widening this to the from-zone shape also flags the census
// placeholders above, which is a real cost for a message improvement.
func malformedZonePairShape9246(n *Node) string {
	if n == nil || len(n.Keys) < 4 || n.Keys[2] != "to-zone" {
		return ""
	}
	for _, c := range n.Children {
		if len(c.Keys) < 2 || c.Keys[0] == "policy" {
			continue
		}
		// `inactive: policy p1 ...` is a SUPPORTED Junos spelling (#2008 H1):
		// the marker is a statement prefix, so the node's first key is the
		// marker and `policy` follows it -- byte-identical to the absorbed
		// shape. Keyed on the parser's own constant rather than a literal, so
		// the two cannot drift.
		if c.Keys[0] == inactiveMarker {
			continue
		}
		carriesRule := false
		for _, k := range c.Keys[1:] {
			if k == "policy" {
				carriesRule = true
				break
			}
		}
		if !carriesRule {
			continue
		}
		return "from-zone " + n.Keys[1] + " to-zone [ " + n.Keys[3] + " " + c.Keys[0] + " ... ]" +
			": a bracketed [ ... ] zone list is not valid on to-zone — a policy context is ONE " +
			"zone pair, so `" + c.Keys[0] + "` and everything after it (" +
			strings.Join(c.Keys[1:], " ") + ") were absorbed as tokens and the policy was NOT " +
			"attached to any context. Write one `from-zone <zone> to-zone <zone>` context per pair"
	}
	return ""
}
