package config

import "testing"

// #2642: a policy term with MULTIPLE same-type `from` match statements
// (community / prefix-list / as-path) must keep EVERY value, not just the
// last. Junos OR's repeated same-type matches ("any"); the pre-#2642
// single-string fields silently dropped all but the last.
//
// The hierarchical (brace) AST accumulates every sibling match — this is the
// primary path. The flat-set path now converges with it (#2630): marking the
// repeatable `from` leaves (route-filter / prefix-list / community / as-path)
// `multi: true` in setSchema makes ConfigTree.SetPath keep every flat-set
// `set ... from <type> <value>` line as a distinct sibling leaf instead of
// overwriting the previous one (see TestPolicyTermMultiMatch_FlatSet_2630).

func TestPolicyTermMultiMatch_Hierarchical_2642(t *testing.T) {
	// Communities must be defined (#2881 cross-reference gate).
	cfg := `policy-options {
    community c1 members 65000:1;
    as-path a1 "^65000 ";
    as-path a2 "^65001 ";
    community c2 members 65000:2;
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
	// Community must be defined (#2881 cross-reference gate).
	cfg := `policy-options {
    community c1 members 65000:1;
    as-path a1 "^65000 ";
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

// #2630 fix: the flat-set path now keeps EVERY repeated same-type `from
// <type> <name>` sibling, converging with the hierarchical AST. Marking the
// repeatable `from` leaves `multi: true` in setSchema makes ConfigTree.SetPath
// append each `set ... from <type> <value>` line as a distinct sibling leaf
// instead of overwriting the previous one. fail-on-revert: dropping `multi`
// from any of these schema leaves makes SetPath collapse the siblings back to
// last-only and these assertions go red.
func TestPolicyTermMultiMatch_FlatSet_2630(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		// Communities must be defined (#2881 cross-reference gate).
		"set policy-options community c1 members 65000:1",
		"set policy-options community c2 members 65000:2",
		// #7471: `from as-path` is definedness-gated now, exactly as
		// `from community` has been since #2881. Define the as-paths so this
		// test keeps MULTI-VALUE RETENTION as its subject rather than passing
		// or failing on a reference gate.
		`set policy-options as-path a1 "^65000 "`,
		`set policy-options as-path a2 "^65001 "`,
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
	wantSlice := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s = %v, want %v", name, got, want)
			}
		}
	}
	wantSlice("flat-set FromCommunity", term.FromCommunity, []string{"c1", "c2"})
	wantSlice("flat-set PrefixList", term.PrefixList, []string{"pl1", "pl2"})
	wantSlice("flat-set FromASPath", term.FromASPath, []string{"a1", "a2"})
}
