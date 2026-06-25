package config

import "testing"

// #2892: BGP policy `then as-path-prepend "<asn> <asn> ..."` must keep EVERY
// ASN in order — the repeated ASN is the AS-path-prepend mechanism (it
// lengthens the advertised AS_PATH so peers prefer a shorter alternate path).
// The leaf is multi:true so a quoted "65001 65001" / bracketed [ 65001 65001 ]
// list (the lexer strips quotes and brackets alike) is flattened onto the
// node's Keys/Children rather than collapsed to last-only. The compiler reads
// every token via firewallMatchValues. fail-on-revert: reading only Keys[1] or
// dropping multi from the schema leaf collapses the list and these go red.

func wantASNs(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", label, got, want)
		}
	}
}

// Hierarchical (brace) AST with a bracketed ASN list.
func TestASPathPrepend_Hierarchical_2892(t *testing.T) {
	cfg := `policy-options {
    policy-statement P {
        term t1 {
            from {
                protocol bgp;
            }
            then {
                as-path-prepend [ 65001 65001 65001 ];
                accept;
            }
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
	wantASNs(t, "ASPathPrepend (hierarchical)", term.ASPathPrepend, []string{"65001", "65001", "65001"})
}

// Flat-set AST with a bracketed ASN list on a single line.
func TestASPathPrepend_FlatSetBracketed_2892(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set policy-options policy-statement P term t1 from protocol bgp",
		"set policy-options policy-statement P term t1 then as-path-prepend [ 65001 65001 65001 ]",
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
	wantASNs(t, "ASPathPrepend (flat-set bracketed)", term.ASPathPrepend, []string{"65001", "65001", "65001"})
}

// A single-ASN prepend keeps working (the common case).
func TestASPathPrepend_SingleASN_2892(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set policy-options policy-statement P term t1 then as-path-prepend 65001",
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
	wantASNs(t, "ASPathPrepend (single)", term.ASPathPrepend, []string{"65001"})
}
