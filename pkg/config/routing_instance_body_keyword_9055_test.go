package config

import "testing"

// #9055: which routing-instance keywords are followed by a BRACED BODY rather
// than by a value.
//
// Pinned as a unit, because through the compiler this predicate is
// UNDER-EXERCISED: a mutation making EVERY keyword body-bearing survives the
// end-to-end cells. It is inert there for a specific reason — the Keys loop has
// already consumed a value keyword's value before the property loop runs, and a
// value form carries no Children for the re-dispatch to mis-route. So
// over-application costs nothing today, and would cost something the moment a
// value keyword could carry a body.
//
// Testing it directly rather than writing "this mutation survives, correctly"
// into the source: whether a guard is reachable through its only caller today
// is a different question from whether it is right.
func TestRoutingInstanceBodyKeywords9055(t *testing.T) {
	// The two that own a body. Getting either wrong is the defect: an elided
	// `routing-options` loses the VRF's static routes, and an elided
	// `protocols` loses the adjacency AND binds the OSPF area's interface as a
	// VRF member.
	for _, kw := range []string{"routing-options", "protocols"} {
		if !routingInstanceKeywordOwnsBody9055(kw) {
			t.Errorf("%q owns a body and must be re-dispatched", kw)
		}
	}
	// The value-bearing ones. `vrf-target`, `route-distinguisher` and
	// `vrf-table-label` are admitted and compile to no field at all —
	// accepted-but-inert, with no braced/elided divergence to fix, and none
	// introduced by treating them as bodies.
	for _, kw := range []string{
		"instance-type", "description", "interface",
		"vrf-target", "route-distinguisher", "vrf-table-label",
	} {
		if routingInstanceKeywordOwnsBody9055(kw) {
			t.Errorf("%q takes a VALUE, not a body; re-dispatching it would hand the "+
				"property loop a synthesized node named after the value", kw)
		}
	}
	// Not a routing-instance keyword at all — an instance NAME, or the value of
	// a value keyword — must never be treated as a body.
	for _, tok := range []string{"ri1", "vrf", "ge-0/0/1.0", "", "static", "ospf"} {
		if routingInstanceKeywordOwnsBody9055(tok) {
			t.Errorf("%q is not an admitted routing-instance keyword", tok)
		}
	}
}

// The body-bearing set must be a SUBSET of the admitted set, or a keyword could
// be re-dispatched that the instance loop never admits — the drift that started
// this (#8787 stopped the switch at three of eight its own helper names).
func TestBodyKeywordsAreAdmitted9055(t *testing.T) {
	for _, kw := range []string{
		"instance-type", "description", "interface", "routing-options",
		"protocols", "vrf-target", "vrf-table-label", "route-distinguisher",
		"ri1", "vrf", "nonsense",
	} {
		if routingInstanceKeywordOwnsBody9055(kw) && !isRoutingInstanceKeyword8787(kw) {
			t.Errorf("%q is treated as body-bearing but is not admitted", kw)
		}
	}
}
