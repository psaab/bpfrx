package config

import "testing"

// #2545: `from protocol` / `from dscp` / `from icmp-type` / `from icmp-code`
// are schema-declared multi-value, and Junos accepts the criterion repeated
// within one `from` block. Before this fix the compiler stored them as SCALARS
// and overwrote on each repeated child — the LAST value won and earlier
// constraints were silently dropped (`from protocol tcp; from protocol udp` →
// Protocol == "udp", the TCP constraint lost). These tests assert that repeated
// occurrences ACCUMULATE into a match-ANY set, across BOTH parser AST shapes
// (hierarchical repeated children AND repeated flat-set commands).
//
// FAIL-ON-REVERT: with the pre-fix scalar last-write-wins compiler these tests
// fail — e.g. Protocols would carry only "udp" (length 1), not [tcp, udp].

func TestFirewallFilterMultiValueHierarchical(t *testing.T) {
	input := `firewall {
    family inet {
        filter mv {
            term t {
                from {
                    protocol tcp;
                    protocol udp;
                    dscp ef;
                    dscp af43;
                    icmp-type 8;
                    icmp-type 0;
                    icmp-code 3;
                    icmp-code 4;
                }
                then discard;
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	f := cfg.Firewall.FiltersInet["mv"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %#v", f)
	}
	term := f.Terms[0]
	assertStrSet(t, "protocol", term.Protocols, []string{"tcp", "udp"})
	assertStrSet(t, "dscp", term.DSCPs, []string{"ef", "af43"})
	assertIntSet(t, "icmp-type", term.ICMPTypes, []int{8, 0})
	assertIntSet(t, "icmp-code", term.ICMPCodes, []int{3, 4})
}

func TestFirewallFilterMultiValueFlatSet(t *testing.T) {
	cmds := []string{
		"set firewall family inet filter mv term t from protocol tcp",
		"set firewall family inet filter mv term t from protocol udp",
		"set firewall family inet filter mv term t from dscp ef",
		"set firewall family inet filter mv term t from dscp af43",
		"set firewall family inet filter mv term t from icmp-type 8",
		"set firewall family inet filter mv term t from icmp-type 0",
		"set firewall family inet filter mv term t from icmp-code 3",
		"set firewall family inet filter mv term t from icmp-code 4",
		"set firewall family inet filter mv term t then discard",
	}
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
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	f := cfg.Firewall.FiltersInet["mv"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %#v", f)
	}
	term := f.Terms[0]
	assertStrSet(t, "protocol", term.Protocols, []string{"tcp", "udp"})
	assertStrSet(t, "dscp", term.DSCPs, []string{"ef", "af43"})
	assertIntSet(t, "icmp-type", term.ICMPTypes, []int{8, 0})
	assertIntSet(t, "icmp-code", term.ICMPCodes, []int{3, 4})
}

// TestFirewallFilterMultiValueBracketList covers the bracket-list shape
// (`protocol [ tcp udp ]`), which the parser flattens onto the node Keys.
func TestFirewallFilterMultiValueBracketList(t *testing.T) {
	input := `firewall {
    family inet {
        filter mv {
            term t {
                from {
                    protocol [ tcp udp ];
                }
                then discard;
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	term := cfg.Firewall.FiltersInet["mv"].Terms[0]
	assertStrSet(t, "protocol", term.Protocols, []string{"tcp", "udp"})
}

func assertStrSet(t *testing.T, field string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v (len %d), want %v (len %d) — repeated values must accumulate, not overwrite (#2545)",
			field, got, len(got), want, len(want))
		return
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("%s: missing %q in %v (#2545)", field, w, got)
		}
	}
}

func assertIntSet(t *testing.T, field string, got, want []int) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v (len %d), want %v (len %d) — repeated values must accumulate, not overwrite (#2545)",
			field, got, len(got), want, len(want))
		return
	}
	seen := map[int]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("%s: missing %d in %v (#2545)", field, w, got)
		}
	}
}
