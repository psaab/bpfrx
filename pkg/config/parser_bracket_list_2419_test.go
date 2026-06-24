package config

import (
	"reflect"
	"testing"
)

// #2419: a flat-set command with a bracketed list value —
// `set ... from protocol [ tcp udp icmp ]` — collapsed the bracketed list
// to the FIRST token. The lexer strips the brackets, so the value tokens
// arrive flat on the path ([..., protocol, tcp, udp, icmp]); the flat-set
// SetPath schema-walk then consumed only `args` tokens onto the node key
// (Keys=[protocol tcp]) and split the tail into an ORPHAN child node
// (Keys=[udp icmp]). The compiler read the node key only, so udp/icmp were
// dropped. The hierarchical parser produces a SINGLE leaf
// Keys=[protocol tcp udp icmp]; this test pins the flat-set path to the
// same AST shape (the dual-AST contract — see docs/config-schema.md).
//
// FAIL-ON-REVERT: with the pre-fix SetPath the bracket list collapses to
// Keys=[protocol tcp] + orphan Keys=[udp icmp], so the dual-AST equality
// assertion and the multi-value slice assertions all fail (only "tcp" /
// the first address survives).

// flatSetTree builds a config tree by parsing each flat-set line with
// ParseSetCommand and applying it with SetPath — never NewParser (which
// merges newline-separated set lines into one giant node).
func flatSetTree(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	return tree
}

// findLeafKeys walks the tree to the named match criterion under
// firewall/family inet/filter F/term T/from and returns its full key slice.
func fromCriterionKeys(t *testing.T, tree *ConfigTree, criterion string) []string {
	t.Helper()
	fw := tree.FindChild("firewall")
	if fw == nil {
		t.Fatal("no firewall node")
	}
	var fam, filt, term, from *Node
	for _, c := range fw.Children {
		if c.Name() == "family" {
			fam = c
		}
	}
	if fam == nil {
		t.Fatal("no family node")
	}
	for _, c := range fam.Children {
		if c.Name() == "filter" {
			filt = c
		}
	}
	if filt == nil {
		t.Fatal("no filter node")
	}
	for _, c := range filt.Children {
		if c.Name() == "term" {
			term = c
		}
	}
	if term == nil {
		t.Fatal("no term node")
	}
	for _, c := range term.Children {
		if c.Name() == "from" {
			from = c
		}
	}
	if from == nil {
		t.Fatal("no from node")
	}
	for _, c := range from.Children {
		if c.Name() == criterion {
			if len(c.Children) > 0 {
				t.Fatalf("%s leaf has orphan children %v — flat-set bracket list was split, not collapsed (#2419)",
					criterion, c.Children)
			}
			return c.Keys
		}
	}
	t.Fatalf("no %s node under from", criterion)
	return nil
}

// TestFlatSetBracketListMatchesHierarchical proves the flat-set bracket
// list yields the SAME single-leaf AST shape as the hierarchical parser.
func TestFlatSetBracketListMatchesHierarchical(t *testing.T) {
	hierSrc := `firewall {
    family inet {
        filter F {
            term T {
                from {
                    protocol [ tcp udp icmp ];
                    source-address [ 10.0.0.0/8 192.168.0.0/16 ];
                    source-port [ 80 443 ];
                }
            }
        }
    }
}`
	hierTree, errs := NewParser(hierSrc).Parse()
	if len(errs) > 0 {
		t.Fatalf("hierarchical parse errors: %v", errs)
	}

	flatTree := flatSetTree(t, []string{
		"set firewall family inet filter F term T from protocol [ tcp udp icmp ]",
		"set firewall family inet filter F term T from source-address [ 10.0.0.0/8 192.168.0.0/16 ]",
		"set firewall family inet filter F term T from source-port [ 80 443 ]",
	})

	for _, crit := range []string{"protocol", "source-address", "source-port"} {
		h := fromCriterionKeys(t, hierTree, crit)
		f := fromCriterionKeys(t, flatTree, crit)
		if !reflect.DeepEqual(h, f) {
			t.Errorf("%s: flat-set Keys=%v != hierarchical Keys=%v (dual-AST gap, #2419)", crit, f, h)
		}
	}

	// Spot-check that all three protocol values survived in the flat-set tree.
	got := fromCriterionKeys(t, flatTree, "protocol")
	want := []string{"protocol", "tcp", "udp", "icmp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("flat-set protocol Keys=%v, want %v — list collapsed to first token (#2419)", got, want)
	}
}

// TestFlatSetBracketListEdgeCases covers single-element, empty, and
// no-bracket single-value lists.
func TestFlatSetBracketListEdgeCases(t *testing.T) {
	// Single element in brackets behaves like a single value.
	tree := flatSetTree(t, []string{
		"set firewall family inet filter F term T from protocol [ tcp ]",
	})
	if got, want := fromCriterionKeys(t, tree, "protocol"), []string{"protocol", "tcp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("single-element list: Keys=%v, want %v", got, want)
	}

	// No brackets, single value — unchanged.
	tree = flatSetTree(t, []string{
		"set firewall family inet filter F term T from protocol tcp",
	})
	if got, want := fromCriterionKeys(t, tree, "protocol"), []string{"protocol", "tcp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("single value: Keys=%v, want %v", got, want)
	}

	// Empty list: the lexer strips the brackets so the criterion has no
	// value tokens at all. SetPath must not panic; the protocol node either
	// does not appear or appears with no value (an empty match is a no-op).
	emptyTree := flatSetTree(t, []string{
		"set firewall family inet filter F term T from protocol [ ]",
	})
	// Just ensure it built without error and the term exists.
	if emptyTree.FindChild("firewall") == nil {
		t.Fatal("empty list dropped the whole firewall stanza")
	}
}

// TestFlatSetBracketListCompiles proves the multi-value flat-set list
// reaches the #2545 compiler slices in full (composition of #2419 + #2545).
func TestFlatSetBracketListCompiles(t *testing.T) {
	tree := flatSetTree(t, []string{
		"set firewall family inet filter mv term t from protocol [ tcp udp icmp ]",
		"set firewall family inet filter mv term t from source-address [ 10.0.0.0/8 192.168.0.0/16 ]",
		"set firewall family inet filter mv term t then discard",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	f := cfg.Firewall.FiltersInet["mv"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %#v", f)
	}
	term := f.Terms[0]
	assertStrSet(t, "protocol", term.Protocols, []string{"tcp", "udp", "icmp"})
	assertStrSet(t, "source-address", term.SourceAddresses, []string{"10.0.0.0/8", "192.168.0.0/16"})
}
