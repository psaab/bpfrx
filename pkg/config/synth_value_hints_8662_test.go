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
		"protocols ospf reference-bandwidth",
		"protocols isis interface xpfarg bfd-liveness-detection minimum-interval",
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
