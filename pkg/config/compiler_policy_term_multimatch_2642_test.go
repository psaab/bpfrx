package config

import "testing"

// #2642: a policy term with MULTIPLE same-type `from` match statements
// (community / prefix-list / as-path) must keep EVERY value, not just the
// last. Junos OR's repeated same-type matches ("any"); the pre-#2642
// single-string fields silently dropped all but the last.
//
// The hierarchical (brace) AST accumulates every sibling match — this is the
// primary, fully-fixed path. The flat-set path is #2630-limited: ConfigTree
// .SetPath collapses repeated `from community c1` / `community c2` sibling
// paths into one node before the compiler runs, so only the last value
// survives upstream of the compiler (see TestPolicyTermMultiMatch_FlatSet_2630).

func TestPolicyTermMultiMatch_Hierarchical_2642(t *testing.T) {
	cfg := `policy-options {
    policy-statement P {
        term t1 {
            from {
                community c1;
                community c2;
                prefix-list pl1;
                prefix-list pl2;
                as-path a1;
                as-path a2;
            }
            then accept;
        }
    }
}`
	p := NewParser(cfg)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	term := c.PolicyOptions.PolicyStatements["P"].Terms[0]

	wantSlice := func(name string, got, want []string) {
		if len(got) != len(want) {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s = %v, want %v", name, got, want)
			}
		}
	}
	// fail-on-revert: reverting the field to a single string + overwrite
	// would leave only [c2]/[pl2]/[a2] here — this assertion goes red.
	wantSlice("FromCommunity", term.FromCommunity, []string{"c1", "c2"})
	wantSlice("PrefixList", term.PrefixList, []string{"pl1", "pl2"})
	wantSlice("FromASPath", term.FromASPath, []string{"a1", "a2"})
}

// A single same-type match in the hierarchical path keeps working (regression
// guard for the common case).
func TestPolicyTermSingleMatch_Hierarchical_2642(t *testing.T) {
	cfg := `policy-options {
    policy-statement P {
        term t1 {
            from {
                community c1;
                prefix-list pl1;
                as-path a1;
            }
            then accept;
        }
    }
}`
	p := NewParser(cfg)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	term := c.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.FromCommunity) != 1 || term.FromCommunity[0] != "c1" {
		t.Errorf("FromCommunity = %v, want [c1]", term.FromCommunity)
	}
	if len(term.PrefixList) != 1 || term.PrefixList[0] != "pl1" {
		t.Errorf("PrefixList = %v, want [pl1]", term.PrefixList)
	}
	if len(term.FromASPath) != 1 || term.FromASPath[0] != "a1" {
		t.Errorf("FromASPath = %v, want [a1]", term.FromASPath)
	}
}

// The flat-set path collapses repeated same-type `from <type> <name>` siblings
// upstream of the compiler (ConfigTree.SetPath merges them onto one node), so
// only the LAST value reaches the compiler. This is the SAME flat-set AST
// limitation as #2630 (route-filter), NOT a compiler bug: the compiler appends
// correctly, but never sees more than one value. This test PINS the current
// (limited) flat-set behavior so a future #2630-class SetPath fix that lifts
// it is a deliberate, visible change here. The compiler-side append is proven
// by the hierarchical test above.
func TestPolicyTermMultiMatch_FlatSet_2630Limited(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set policy-options policy-statement P term t1 from community c1",
		"set policy-options policy-statement P term t1 from community c2",
		"set policy-options policy-statement P term t1 from prefix-list pl1",
		"set policy-options policy-statement P term t1 from prefix-list pl2",
		"set policy-options policy-statement P term t1 from as-path a1",
		"set policy-options policy-statement P term t1 from as-path a2",
		"set policy-options policy-statement P term t1 then accept",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	term := c.PolicyOptions.PolicyStatements["P"].Terms[0]
	// Documents the #2630-class limitation: SetPath keeps only the last sibling.
	if len(term.FromCommunity) != 1 || term.FromCommunity[0] != "c2" {
		t.Errorf("flat-set FromCommunity = %v; expected the #2630-limited last-only [c2]", term.FromCommunity)
	}
	if len(term.PrefixList) != 1 || term.PrefixList[0] != "pl2" {
		t.Errorf("flat-set PrefixList = %v; expected the #2630-limited last-only [pl2]", term.PrefixList)
	}
	if len(term.FromASPath) != 1 || term.FromASPath[0] != "a2" {
		t.Errorf("flat-set FromASPath = %v; expected the #2630-limited last-only [a2]", term.FromASPath)
	}
}
