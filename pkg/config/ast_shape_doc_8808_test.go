package config

import (
	"reflect"
	"strings"
	"testing"
)

// #8808: CLAUDE.md's "Parser Dual AST Shape" section illustrated the
// flat-versus-hierarchical difference with `family inet`, for which there is no
// difference. It was the ONLY example given, so it is the one readers
// generalise from, and it is wrong in the direction that makes people SKIP a
// measurement: a compiler exercised only against `family inet` looks
// shape-agnostic while being blind to every non-compound container.
//
// These cells pin both halves of the corrected documentation. The strings below
// appear verbatim in CLAUDE.md; changing the doc means changing this file.
//
// WHY THESE COMPARE STRUCTURE RATHER THAN reflect.DeepEqual. The two trees are
// NOT DeepEqual, and the reason is not structural: the hierarchical parser
// records source positions (`Line`, `Column`) while `SetPath` leaves them zero.
// Measured -- that is the ONLY difference, at every node:
//
//	flat  {Keys:[family inet] ... Line:0 Column:0}
//	hier  {Keys:[family inet] ... Line:1 Column:42}
//
// So the issue's phrase "byte-identical" is a shade too strong and the
// correct claim is "structurally identical". This matters for the cell's
// design, not just its prose: a DeepEqual assertion here would fail for a
// reason that has nothing to do with AST shape, and the natural way to make it
// pass would be to loosen the comparison until it stopped discriminating at
// all. The comparison is therefore explicit about what it ignores, and a
// separate assertion proves that position metadata is the ONLY thing ignored.

const (
	// the doc's OLD example: `family` is compoundKey, so the shapes CONVERGE.
	docFlatFamilyInet = "set interfaces eth0 unit 0 family inet dhcp"
	docHierFamilyInet = "interfaces { eth0 { unit 0 { family inet { dhcp; } } } }"

	// the doc's REPLACEMENT example: no compoundKey, so the shapes DIVERGE.
	// Note the hierarchical form is TWO STATEMENTS, not nested braces --
	// writing it nested would build a chain in both spellings and illustrate
	// nothing, which is the #8808 defect committed a second time.
	docFlatBGP = "set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001"
	docHierBGP = "protocols { bgp { group g1 { neighbor 10.0.0.1; peer-as 65001; } } }"
)

func astShapeFlat(t *testing.T, line string) []*Node {
	t.Helper()
	tr := &ConfigTree{}
	toks, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", line, err)
	}
	if err := tr.SetPath(toks); err != nil {
		t.Fatalf("SetPath(%q): %v", line, err)
	}
	return tr.Children
}

func astShapeHier(t *testing.T, text string) []*Node {
	t.Helper()
	root, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse(%q): %v", text, perrs)
	}
	return root.Children
}

// astShapeRender renders the structural identity of a forest: keys, nesting and
// leafness. It deliberately omits Line/Column (see the file comment).
func astShapeRender(ns []*Node) string {
	var b strings.Builder
	var walk func(n *Node, d int)
	walk = func(n *Node, d int) {
		b.WriteString(strings.Repeat("  ", d))
		b.WriteString(strings.Join(n.Keys, " "))
		if n.IsLeaf {
			b.WriteString(" ;")
		}
		b.WriteByte('\n')
		for _, c := range n.Children {
			walk(c, d+1)
		}
	}
	for _, n := range ns {
		walk(n, 0)
	}
	return b.String()
}

// astShapeZeroPos returns a deep copy with position metadata cleared, so that
// DeepEqual measures everything EXCEPT source position.
func astShapeZeroPos(ns []*Node) []*Node {
	out := make([]*Node, 0, len(ns))
	for _, n := range ns {
		c := *n
		c.Line, c.Column = 0, 0
		c.Children = astShapeZeroPos(n.Children)
		out = append(out, &c)
	}
	return out
}

// TestDocAST8808FamilyInetShapesConverge pins the claim the corrected doc makes
// about its OLD example: for a compoundKey container both spellings produce the
// same tree, so `family inet` cannot illustrate the dual shape.
func TestDocAST8808FamilyInetShapesConverge(t *testing.T) {
	flat := astShapeFlat(t, docFlatFamilyInet)
	hier := astShapeHier(t, docHierFamilyInet)

	if got, want := astShapeRender(flat), astShapeRender(hier); got != want {
		t.Errorf("`family inet` flat and hierarchical trees now DIFFER structurally.\n"+
			"CLAUDE.md states they are identical because `family` is compoundKey\n"+
			"(#8808). If that changed, the doc is now wrong in the OTHER direction\n"+
			"and must be updated together with this test.\n\nflat:\n%s\nhier:\n%s", got, want)
	}

	// Everything except source position must match, which is the precise claim.
	if !reflect.DeepEqual(astShapeZeroPos(flat), astShapeZeroPos(hier)) {
		t.Errorf("`family inet` trees differ in a field beyond Line/Column.\n" +
			"The documented claim is that source position is the ONLY difference;\n" +
			"some other node field now diverges and the doc understates it.")
	}

	// VACUITY CONTROL. Two empty forests render identically and compare equal,
	// so both assertions above would pass on a parse that built nothing. Pin
	// the actual shape.
	got := astShapeRender(flat)
	want := "interfaces\n  eth0\n    unit 0\n      family inet\n        dhcp ;\n"
	if got != want {
		t.Errorf("the `family inet` tree is not the shape CLAUDE.md documents.\n"+
			"got:\n%s\nwant:\n%s", got, want)
	}
}

// TestDocAST8808BGPShapesDiverge pins the replacement example: a non-compound
// container really does build a CHAIN under flat `set` while the hierarchical
// spelling of the same configuration builds SIBLINGS. That divergence is the
// property the CLAUDE.md section exists to teach; if it stops holding, the
// section's premise is gone, not just its example.
func TestDocAST8808BGPShapesDiverge(t *testing.T) {
	flat := astShapeRender(astShapeFlat(t, docFlatBGP))
	wantFlat := "protocols\n  bgp\n    group g1\n      neighbor 10.0.0.1\n        peer-as 65001 ;\n"
	if flat != wantFlat {
		t.Errorf("flat `set` no longer builds a CHAIN for a non-compound container.\n"+
			"CLAUDE.md uses this exact line to illustrate that each leaf nests under\n"+
			"the previous one (#8808). Update both together.\ngot:\n%s\nwant:\n%s",
			flat, wantFlat)
	}

	hier := astShapeRender(astShapeHier(t, docHierBGP))
	wantHier := "protocols\n  bgp\n    group g1\n      neighbor 10.0.0.1 ;\n      peer-as 65001 ;\n"
	if hier != wantHier {
		t.Errorf("the hierarchical spelling no longer builds SIBLINGS.\ngot:\n%s\nwant:\n%s",
			hier, wantHier)
	}

	// The DIVERGENCE is the whole point. Without this the two assertions above
	// could both hold on trees that happen to be identical, and the example
	// would illustrate nothing -- the #8808 defect, committed again in the
	// replacement example.
	if flat == hier {
		t.Errorf("flat and hierarchical BGP trees are IDENTICAL, so this example\n"+
			"teaches nothing. Pick a container that actually diverges.\n%s", flat)
	}
}
