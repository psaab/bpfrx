package config

import (
	"strings"
	"testing"
)

// #8662 fixture sweep. The compact/block census could not rule 103 sites
// because synthPair fell through to an invented pair "xpfaaa"/"xpfbbb" for any
// leaf declaring no examples. Many leaves reject that outright — `unit xpfaaa`
// is not a unit number — so BOTH spellings compiled to nothing, the vacuity
// guard fired, and the site was recorded "leaf value not observable".
//
// That verdict was about the FIXTURE, not the leaf. Synthesising from the
// schema's own valueHint made 21 more sites rulable and exposed 14 real
// divergences that had been invisible — including a login `uid`, an interface
// `unit`, and BFD `minimum-interval` on four routing protocols.
//
// The lesson these cells exist to protect: a probe that cannot express a VALID
// value makes every leaf look dead, and the deadness is a property of the probe.

func TestSynthPairUsesSchemaValueHints8662(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *schemaNode
		want string // v1 must be this
	}{
		{"unit number", &schemaNode{valueHint: ValueHintUnitNumber}, "0"},
		{"interface name", &schemaNode{valueHint: ValueHintInterfaceName}, "ge-0/0/0.0"},
		{"numeric placeholder", &schemaNode{placeholder: "<0..255>"}, "1"},
		// #8690: these three cases carry the `protocols` family's synthesis
		// coverage, which used to ride on a membership anchor below.
		//
		// `protocols bgp group <g> neighbor <n> peer-as` was that anchor — the
		// last divergent protocols site, so its continued PRESENCE in the
		// inventory proved synthesis still produced a valid value for it.
		// Normalizing it emptied the family, and membership cannot carry a
		// claim about a site that is no longer divergent.
		//
		// THE SHIPPED NODE IS COVERED TWICE, AND THAT IS WHY IT NEEDS THREE
		// CASES RATHER THAN ONE. A first attempt asserted the shipped shape
		// alone and claimed the value came from valueType. Mutation refuted
		// both halves: disabling the `case ValueInteger` branch left the test
		// GREEN, and measurement showed why — the placeholder heuristic runs
		// FIRST and `<as-number>` matches it on the substring "number", so
		// valueType is never consulted for this node. The mechanism was the
		// opposite of the one written down.
		//
		// The redundancy is real and good for the census — a single-path
		// regression cannot silently un-rule this leaf — but it makes a test
		// over the shipped node mutation-INSENSITIVE by construction, because
		// no single change can move it. So each path is pinned in isolation,
		// and the shipped shape is kept to record that both cover it.
		{"integer leaf, no placeholder (valueType path)",
			&schemaNode{valueType: ValueInteger}, "1"},
		{"non-numeric placeholder matching \"number\" (placeholder path)",
			&schemaNode{placeholder: "<as-number>"}, "1"},
		{"bgp peer-as as shipped — both paths cover it",
			&schemaNode{valueType: ValueInteger, placeholder: "<as-number>",
				validator: ValidateInteger(1, 4294967295)}, "1"},
	} {
		v1, v2, ok := synthPair(tc.node)
		if !ok {
			t.Errorf("%s: synthPair refused to synthesise", tc.name)
			continue
		}
		if v1 == v2 {
			t.Errorf("%s: the pair must be DISTINCT, both %q", tc.name, v1)
		}
		if v1 == "xpfaaa" {
			t.Errorf("%s: fell through to the invented identifier; the schema declares what "+
				"this leaf takes and the probe ignored it", tc.name)
		}
		if v1 != tc.want {
			t.Errorf("%s: v1 = %q, want %q", tc.name, v1, tc.want)
		}
	}
}

// The sites the widened synthesis made visible must stay visible. If synthesis
// regresses they silently return to "not observable" — which reads as clean.
func TestHintExposedDivergencesStayVisible8662(t *testing.T) {
	sites, _ := readInventory(t)
	inInventory := func(s string) bool {
		for _, line := range sites {
			if line == s {
				return true
			}
		}
		return false
	}
	// One from each family the sweep exposed, chosen because each is a value an
	// operator would notice missing.
	for _, want := range []string{
		"interfaces xpfname unit",
		"system login user xpfarg uid",
		// #8690 family 4 normalized the two protocols entries that used to sit
		// here — `protocols ospf reference-bandwidth` and `protocols isis
		// interface <i> bfd-liveness-detection minimum-interval` — so they left
		// the inventory and can no longer serve as "still visible" anchors.
		// This cell said what to do in its own failure message ("if the compact
		// reader was FIXED, remove this line and say so"), and this is that.
		//
		// The protocols family has NO membership anchor any more, and this is
		// the one departure that could not be handled by replacement.
		//
		// `protocols bgp group <g> neighbor <n> peer-as` was the last divergent
		// protocols site. #8690 classified it BENIGN — the gate objects to the
		// dropped peer-as, and the pass restores it — and normalizing it emptied
		// the family, so there is nothing left to point at. Replacing an anchor
		// requires another divergent site in the same family; completion removes
		// that option, which is a good outcome that costs a guard.
		//
		// The coverage is NOT dropped, it MOVED: the property this anchor
		// proved — that synthesis still produces a valid value for that leaf —
		// is now asserted directly in TestSynthPairUsesSchemaValueHints8662, on
		// the node's shape rather than on its inventory membership. That form
		// is strictly stronger here, because it keeps working after the site is
		// fixed, which is precisely where the membership form stopped working.
	} {
		if !inInventory(want) {
			t.Errorf("%q left the inventory. If the compact reader was FIXED, remove this line "+
				"and say so. If synthPair stopped producing a valid value for it, the site is "+
				"unruled again and its silence means nothing (#8662)", want)
		}
	}
}

// Degeneracy control for the pair above: the inventory must actually be
// populated, or every membership assertion in this file passes vacuously.
func TestInventoryIsPopulated8662(t *testing.T) {
	sites, checked := readInventory(t)
	if len(sites) == 0 {
		t.Fatal("the inventory has no site lines; the cells in this file prove nothing")
	}
	if checked < 600 {
		t.Errorf("checked count %d is far below the ~677 this sweep measured — the census is "+
			"seeing much less of its population than it did, and every 'clean' verdict "+
			"downstream is correspondingly weaker", checked)
	}
	if !strings.Contains(strings.Join(sites, "\n"), "security") {
		t.Error("no security sites at all; the inventory looks truncated")
	}
}
