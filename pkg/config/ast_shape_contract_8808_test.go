package config

import (
	"strings"
	"testing"
)

// #8808: what the "dual AST shape" actually is.
//
// The project docs recorded it as flat-`set`-versus-hierarchical:
//
//	Hierarchical `family inet { dhcp; }` -> Node{Keys:["family","inet"]} with children
//	Flat `set … family inet dhcp`        -> Node{Keys:["family"]} with child Node{Keys:["inet"]}
//
// The second line is false, and it is false for the example it uses. Flat `set`
// produces the SAME tree as the hierarchical form -- `SetPath` descends a
// compoundKey container exactly as the parser does (ast_edit.go:506, :850, :999).
// This cell measures it rather than restating it.
//
// THE REAL AXIS IS BRACING, and there are three shapes, not two:
//
//	family inet { dhcp; }        [family inet] + child [dhcp]     COMPOUND
//	family { inet { dhcp; } }    [family] > [inet] > [dhcp]       SPLIT
//	family inet dhcp;            [family inet dhcp]               PACKED (#2419)
//
// A compiler must handle all three, and the split form is where the documented
// `Keys:["family"]` + child `Keys:["inet"]` shape really comes from -- an
// operator bracing the family separately, not a `set` command.
//
// WHY A GUARD AND NOT JUST A DOC FIX. The false line is false in the direction
// that makes people SKIP A MEASUREMENT: it says the flat surface has a different
// shape, so a defect proven against the compound shape looks inapplicable to it.
// That reasoning was applied during #8763 and the flat surface was nearly left
// unmeasured; it is in fact affected identically. Prose that a reader can act on
// wrongly should be pinned by something that fails.
func TestFlatSetAndHierarchicalProduceTheSameTree8808(t *testing.T) {
	for _, c := range []struct {
		name string
		hier string
		flat []string
	}{
		{
			"the documented example: family inet dhcp",
			"interfaces {\n eth0 {\n  unit 0 {\n   family inet {\n    dhcp;\n   }\n  }\n }\n}\n",
			[]string{"set interfaces eth0 unit 0 family inet dhcp"},
		},
		{
			"a NON-compound container: bgp group neighbor peer-as",
			"protocols {\n bgp {\n  group g1 {\n   neighbor 10.0.0.1 {\n    peer-as 65001;\n   }\n  }\n }\n}\n",
			[]string{"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001"},
		},
		{
			"nested containers: security policy match",
			"security {\n policies {\n  global {\n   policy p1 {\n    match {\n     source-address any;\n    }\n   }\n  }\n }\n}\n",
			[]string{"set security policies global policy p1 match source-address any"},
		},
		{
			"a bracketed list (#2419 collapse)",
			"firewall {\n family inet {\n  filter f1 {\n   term t1 {\n    from {\n     protocol [ tcp udp ];\n    }\n   }\n  }\n }\n}\n",
			[]string{"set firewall family inet filter f1 term t1 from protocol [ tcp udp ]"},
		},
	} {
		hier, perrs := NewParser(c.hier).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: parse: %v", c.name, perrs)
		}
		flat := &ConfigTree{}
		for _, line := range c.flat {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("%s: ParseSetCommand(%q): %v", c.name, line, err)
			}
			flat.SetPath(path)
		}
		h, f := astShape8808(hier.Children, 0), astShape8808(flat.Children, 0)
		if h != f {
			t.Errorf("%s: the flat `set` tree differs from the hierarchical one.\n"+
				"hierarchical:\n%s\nflat:\n%s\n"+
				"If this is a deliberate change, the docs corrected in #8808 must change with it -- "+
				"they now state the two are identical and that the real variable is BRACING.",
				c.name, h, f)
		}
	}
}

// The three bracing shapes, which is what "handle both shapes" is really about.
// Without this the cell above would read as "shape does not vary", which is the
// opposite error.
func TestBracingProducesThreeDistinctShapes8808(t *testing.T) {
	unit := func(inner string) string {
		return "interfaces {\n eth0 {\n  unit 0 {\n" + inner + "\n  }\n }\n}\n"
	}
	shapes := map[string]string{}
	for _, c := range []struct{ name, text string }{
		{"COMPOUND family inet { dhcp; }", unit("   family inet {\n    dhcp;\n   }")},
		{"SPLIT    family { inet { dhcp; } }", unit("   family {\n    inet {\n     dhcp;\n    }\n   }")},
		{"PACKED   family inet dhcp;", unit("   family inet dhcp;")},
	} {
		tree, perrs := NewParser(c.text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: parse: %v", c.name, perrs)
		}
		shapes[c.name] = astShape8808(tree.Children, 0)
		t.Logf("%s ->\n%s", c.name, shapes[c.name])
	}
	seen := map[string]string{}
	for name, shape := range shapes {
		if other, dup := seen[shape]; dup {
			t.Errorf("%q and %q produce the SAME tree, so the three-shape claim in the docs "+
				"corrected by #8808 is wrong: a compiler handling one would handle the other, "+
				"and the distinction the docs draw would be meaningless", name, other)
		}
		seen[shape] = name
	}
	// The SPLIT form is the one the docs used to attribute to flat `set`.
	if !strings.Contains(shapes["SPLIT    family { inet { dhcp; } }"], "[family]\n") {
		t.Error("the SPLIT form no longer produces a bare [family] node with an [inet] child -- " +
			"that shape is what the old doc line described, and the correction says a separately " +
			"BRACED family is where it comes from (#8808)")
	}
}

func astShape8808(nodes []*Node, depth int) string {
	var b strings.Builder
	for _, n := range nodes {
		if n == nil {
			continue
		}
		b.WriteString(strings.Repeat("  ", depth) + "[" + strings.Join(n.Keys, " ") + "]\n")
		b.WriteString(astShape8808(n.Children, depth+1))
	}
	return b.String()
}
