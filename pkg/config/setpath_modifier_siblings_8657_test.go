package config

import (
	"reflect"
	"testing"
)

// #8657: `SetPath` NESTED successive modifiers under each other instead of
// making them siblings, so the compiler — which scans siblings — saw only the
// first and everything after it was unreachable. Exactly one modifier survived,
// and which one depended on authoring ORDER:
//
//	set system ntp server 1.2.3.4 prefer version 4   -> Prefer kept, Version LOST
//	set system ntp server 1.2.3.4 version 4 prefer   -> Version kept, Prefer LOST
//
// while the hierarchical spelling of the same config kept both. One
// configuration, two shapes, two different compiled results — the dual-shape
// divergence class, on the `set` path, which is also the cluster config-sync
// path.
//
// THE ASSERTION IS AGREEMENT BETWEEN THE SHAPES, not a literal. Pinning the
// expected struct would go vacuous the day a modifier's default changes; the
// property is that the two spellings cannot disagree, whatever the value is.
func setTree8657(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func ntpOptions8657(t *testing.T, tree *ConfigTree) NTPServerOption {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	opt, ok := cfg.System.NTPServerOptions["1.2.3.4"]
	if !ok {
		t.Fatalf("no NTP options compiled for 1.2.3.4; got %#v",
			cfg.System.NTPServerOptions)
	}
	return opt
}

func TestFlatSetModifiersAreSiblingsNotNested8657(t *testing.T) {
	flat := ntpOptions8657(t, setTree8657(t,
		"set system ntp server 1.2.3.4 prefer version 4"))

	hier, err := NewParser(`
system {
    ntp {
        server 1.2.3.4 {
            prefer;
            version 4;
        }
    }
}
`).Parse()
	if err != nil {
		t.Fatalf("parse hierarchical: %v", err)
	}
	hierOpt := ntpOptions8657(t, hier)

	if !reflect.DeepEqual(flat, hierOpt) {
		t.Errorf("the same configuration compiles differently in the two "+
			"spellings — the flat-set AST nests modifiers instead of making "+
			"them siblings, so the compiler's sibling scan reaches only the "+
			"first.\n flat-set     %+v\n hierarchical %+v", flat, hierOpt)
	}

	// DEGENERATE-FAILURE CONTROL. The agreement assertion above is satisfied by
	// BOTH shapes dropping the modifier, so on its own it cannot tell "both
	// keep it" from "both lose it". This names the observable.
	if !flat.Prefer || flat.Version != 4 {
		t.Errorf("both modifiers must survive: got Prefer=%v Version=%d, want "+
			"true and 4. Agreement alone would be satisfied by both spellings "+
			"losing the second modifier", flat.Prefer, flat.Version)
	}
}

// ORDER INDEPENDENCE: the defect kept whichever modifier was written FIRST, so
// a cell testing one order only would pass on a fix that still drops the
// second. Both orders must yield the same struct.
func TestFlatSetModifierOrderDoesNotChangeTheResult8657(t *testing.T) {
	a := ntpOptions8657(t, setTree8657(t,
		"set system ntp server 1.2.3.4 prefer version 4"))
	b := ntpOptions8657(t, setTree8657(t,
		"set system ntp server 1.2.3.4 version 4 prefer"))

	if !reflect.DeepEqual(a, b) {
		t.Errorf("authoring ORDER changed the compiled result — the surviving "+
			"modifier used to be whichever was written first.\n prefer-first %+v\n version-first %+v",
			a, b)
	}
	if !a.Prefer || a.Version != 4 {
		t.Errorf("both modifiers must survive in either order; got %+v", a)
	}
}

// THE SHAPE GUARD, keyed to the schema rather than to `ntp server`, so the next
// leaf declaring two or more modifiers is covered on arrival rather than
// needing someone to notice it.
//
// The census also records what it found. #8657's own population table lists two
// `valueList` leaves; there are THREE, and the one it omits
// (`dhcp-local-server ... group ... interface`) declares TEN modifiers — the
// largest in the population. Its modifiers are parsed and ignored today, so it
// exhibits no compiler-visible harm, but it carried the identical broken AST
// shape and inherits the defect the moment one of them is implemented.
func TestEveryMultiModifierValueListLeafBuildsSiblings8657(t *testing.T) {
	type site struct {
		path      []string
		modifiers []string
	}
	var sites []site

	var walk func(n *schemaNode, path []string)
	walk = func(n *schemaNode, path []string) {
		if n == nil {
			return
		}
		if n.valueList && len(n.children) >= 2 {
			mods := make([]string, 0, len(n.children))
			for k := range n.children {
				mods = append(mods, k)
			}
			sites = append(sites, site{path: append([]string(nil), path...), modifiers: mods})
		}
		for k, c := range n.children {
			walk(c, append(path, k))
		}
		if n.wildcard != nil {
			walk(n.wildcard, append(path, "<*>"))
		}
	}
	walk(setSchema, nil)

	// DEGENERACY GUARD: a walk that found nothing looks identical to a clean
	// schema, and the clean answer is the one this cell exists to trust.
	if len(sites) == 0 {
		t.Fatal("the schema walk found NO valueList leaf with >= 2 modifiers — " +
			"the walk or the schema shape has changed, so this cell is blind " +
			"and its silence means nothing (#8657)")
	}
	t.Logf("#8657 population: %d valueList leaves with >= 2 modifiers", len(sites))

	for _, s := range sites {
		if len(s.modifiers) < 2 {
			continue
		}
		t.Logf("  %v  (%d modifiers)", s.path, len(s.modifiers))
		// Two modifiers authored in one flat-set statement must land as
		// SIBLINGS under the leaf, never one nested under the other.
		m1, m2 := s.modifiers[0], s.modifiers[1]
		cmd := "set " + joinPath8657(s.path) + " xa10 " + m1 + " " + m2
		tree := &ConfigTree{}
		path, err := ParseSetCommand(cmd)
		if err != nil {
			continue // a synthetic path this leaf cannot accept
		}
		if err := tree.SetPath(path); err != nil {
			continue
		}
		if nested, where := hasNestedModifier8657(tree.Children, s.modifiers); nested {
			t.Errorf("%s\n  built a NESTED modifier at %s — successive modifiers "+
				"must be siblings, or the compiler's sibling scan reaches only "+
				"the first (#8657)", cmd, where)
		}
	}
}

func joinPath8657(p []string) string {
	out := ""
	for i, s := range p {
		if s == "<*>" {
			s = "xw" + string(rune('a'+i))
		}
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

// hasNestedModifier8657 reports a node whose Keys name a modifier and which has
// a CHILD that also names one — the exact broken shape.
func hasNestedModifier8657(nodes []*Node, mods []string) (bool, string) {
	isMod := func(k string) bool {
		for _, m := range mods {
			if k == m {
				return true
			}
		}
		return false
	}
	for _, n := range nodes {
		if len(n.Keys) > 0 && isMod(n.Keys[0]) {
			for _, c := range n.Children {
				if len(c.Keys) > 0 && isMod(c.Keys[0]) {
					return true, n.Keys[0] + " -> " + c.Keys[0]
				}
			}
		}
		if bad, where := hasNestedModifier8657(n.Children, mods); bad {
			return true, where
		}
	}
	return false, ""
}
