package config

import "testing"

// #3915: compileNAT read each of the source / destination / static / nat64 /
// natv6v4 / proxy-arp sub-blocks under a `nat {}` node with FindChild (first
// match only). The Junos parser APPENDS a repeated hierarchical block as a
// sibling (parseStatements) rather than merging it, so `load override` /
// `load merge` can produce a second `source {}` (or destination/static/...)
// block carrying additional rule-sets. FindChild-first compiled only the first
// block and SILENTLY DROPPED the second block's rule-sets -> the SNAT/DNAT/
// static rule-set vanished and traffic egressed untranslated. The fix iterates
// EVERY same-named sub-block with forEachChild; each sub-block compiler already
// APPENDS its rule-sets and map-assigns its pools, so the duplicate blocks
// MERGE exactly as Junos merges duplicate hierarchical stanzas.
//
// These tests parse a real config (proving the parser emits the two sibling
// sub-blocks), navigate to the single `nat` node, and call compileNAT directly
// so they exercise the exact fix without CompileConfig's zone/policy
// validation. Reverting compileNAT to FindChild-first drops the second block's
// rule-set and every "both present" assertion goes RED.

// natNodeFromText parses cfgText and returns the FIRST `security > nat` node.
func natNodeFromText(t *testing.T, cfgText string) *Node {
	t.Helper()
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatalf("no security node parsed")
	}
	nat := sec.FindChild("nat")
	if nat == nil {
		t.Fatalf("no nat node parsed")
	}
	return nat
}

// countChildren returns how many direct children of nat have the given name.
func countChildren(nat *Node, name string) int {
	n := 0
	for _, c := range nat.Children {
		if c.Name() == name {
			n++
		}
	}
	return n
}

func hasSourceRuleSet(sec *SecurityConfig, name string) bool {
	for _, rs := range sec.NAT.Source {
		if rs.Name == name {
			return true
		}
	}
	return false
}

func hasDestRuleSet(sec *SecurityConfig, name string) bool {
	if sec.NAT.Destination == nil {
		return false
	}
	for _, rs := range sec.NAT.Destination.RuleSets {
		if rs.Name == name {
			return true
		}
	}
	return false
}

func hasStaticRuleSet(sec *SecurityConfig, name string) bool {
	for _, rs := range sec.NAT.Static {
		if rs.Name == name {
			return true
		}
	}
	return false
}

// TestCompileNATDuplicateSourceBlocksMerge is the primary RED-on-revert case:
// two `source {}` blocks under one `nat {}`, the second adding rule-set RS2.
// Both RS1 and RS2 must compile. FindChild-first drops RS2 -> RED (SNAT for the
// second rule-set is missing and that traffic egresses untranslated).
func TestCompileNATDuplicateSourceBlocksMerge(t *testing.T) {
	cfgText := `
security {
    nat {
        source {
            rule-set RS1 {
                from zone trust;
                to zone untrust;
                rule R1 {
                    then {
                        source-nat interface;
                    }
                }
            }
        }
        source {
            rule-set RS2 {
                from zone dmz;
                to zone untrust;
                rule R2 {
                    then {
                        source-nat interface;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	if got := countChildren(nat, "source"); got < 2 {
		t.Fatalf("expected 2 `source` siblings under one nat (the bypass premise), got %d", got)
	}

	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if !hasSourceRuleSet(sec, "RS1") {
		t.Fatalf("first source block rule-set RS1 missing from compiled config")
	}
	if !hasSourceRuleSet(sec, "RS2") {
		t.Fatalf("second source block rule-set RS2 SILENTLY DROPPED (#3915 dup-block bug); Source=%+v", sec.NAT.Source)
	}
	if len(sec.NAT.Source) != 2 {
		t.Fatalf("expected exactly 2 source rule-sets after merge, got %d", len(sec.NAT.Source))
	}
}

// TestCompileNATDuplicateDestinationBlocksMerge: two `destination {}` blocks,
// the second adding pool P2 + rule-set RD2. Both DNAT rule-sets must compile.
func TestCompileNATDuplicateDestinationBlocksMerge(t *testing.T) {
	cfgText := `
security {
    nat {
        destination {
            pool P1 {
                address 10.0.30.100;
            }
            rule-set RD1 {
                from zone untrust;
                rule R1 {
                    match {
                        destination-address 198.51.100.1/32;
                    }
                    then {
                        destination-nat pool P1;
                    }
                }
            }
        }
        destination {
            pool P2 {
                address 10.0.30.200;
            }
            rule-set RD2 {
                from zone untrust;
                rule R2 {
                    match {
                        destination-address 198.51.100.2/32;
                    }
                    then {
                        destination-nat pool P2;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	if got := countChildren(nat, "destination"); got < 2 {
		t.Fatalf("expected 2 `destination` siblings under one nat, got %d", got)
	}

	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if !hasDestRuleSet(sec, "RD1") {
		t.Fatalf("first destination block rule-set RD1 missing")
	}
	if !hasDestRuleSet(sec, "RD2") {
		t.Fatalf("second destination block rule-set RD2 SILENTLY DROPPED (#3915 dup-block bug)")
	}
	if sec.NAT.Destination == nil || len(sec.NAT.Destination.RuleSets) != 2 {
		t.Fatalf("expected 2 destination rule-sets after merge, got %v", sec.NAT.Destination)
	}
	if _, ok := sec.NAT.Destination.Pools["P2"]; !ok {
		t.Fatalf("second destination block pool P2 dropped")
	}
}

// TestCompileNATDuplicateStaticBlocksMerge: two `static {}` blocks, the second
// adding rule-set ST2. Both static rule-sets must compile.
func TestCompileNATDuplicateStaticBlocksMerge(t *testing.T) {
	cfgText := `
security {
    nat {
        static {
            rule-set ST1 {
                from zone untrust;
                rule R1 {
                    match {
                        destination-address 198.51.100.10/32;
                    }
                    then {
                        static-nat prefix 10.0.1.10/32;
                    }
                }
            }
        }
        static {
            rule-set ST2 {
                from zone untrust;
                rule R2 {
                    match {
                        destination-address 198.51.100.20/32;
                    }
                    then {
                        static-nat prefix 10.0.1.20/32;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	if got := countChildren(nat, "static"); got < 2 {
		t.Fatalf("expected 2 `static` siblings under one nat, got %d", got)
	}

	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if !hasStaticRuleSet(sec, "ST1") {
		t.Fatalf("first static block rule-set ST1 missing")
	}
	if !hasStaticRuleSet(sec, "ST2") {
		t.Fatalf("second static block rule-set ST2 SILENTLY DROPPED (#3915 dup-block bug)")
	}
	if len(sec.NAT.Static) != 2 {
		t.Fatalf("expected 2 static rule-sets after merge, got %d", len(sec.NAT.Static))
	}
}

// TestCompileNATDuplicateNAT64BlocksMerge: two `nat64 {}` blocks, the second
// adding rule-set N2.
func TestCompileNATDuplicateNAT64BlocksMerge(t *testing.T) {
	cfgText := `
security {
    nat {
        nat64 {
            rule-set N1 {
                prefix 64:ff9b::/96;
            }
        }
        nat64 {
            rule-set N2 {
                prefix 64:ff9b::/96;
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	if got := countChildren(nat, "nat64"); got < 2 {
		t.Fatalf("expected 2 `nat64` siblings under one nat, got %d", got)
	}

	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	var names []string
	for _, rs := range sec.NAT.NAT64 {
		names = append(names, rs.Name)
	}
	has := func(n string) bool {
		for _, s := range names {
			if s == n {
				return true
			}
		}
		return false
	}
	if !has("N1") || !has("N2") {
		t.Fatalf("nat64 dup-block merge lost a rule-set; got %v (want N1 and N2)", names)
	}
}

// TestCompileNATDuplicateProxyARPBlocksMerge: two `proxy-arp {}` blocks, the
// second adding a second interface entry.
func TestCompileNATDuplicateProxyARPBlocksMerge(t *testing.T) {
	cfgText := `
security {
    nat {
        proxy-arp {
            interface ge-0/0/1.0 {
                address 198.51.100.10/32;
            }
        }
        proxy-arp {
            interface ge-0/0/2.0 {
                address 198.51.100.20/32;
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	if got := countChildren(nat, "proxy-arp"); got < 2 {
		t.Fatalf("expected 2 `proxy-arp` siblings under one nat, got %d", got)
	}

	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	var ifaces []string
	for _, e := range sec.NAT.ProxyARP {
		ifaces = append(ifaces, e.Interface)
	}
	if len(ifaces) != 2 {
		t.Fatalf("proxy-arp dup-block merge lost an entry; got %v (want 2 interfaces)", ifaces)
	}
}

// TestCompileNATSingleBlockUnchanged pins bit-identical behaviour for the
// common single-block case: exactly one source/destination/static block each
// still yields exactly one rule-set, so the forEachChild conversion did not
// regress the normal path.
func TestCompileNATSingleBlockUnchanged(t *testing.T) {
	cfgText := `
security {
    nat {
        source {
            rule-set RS1 {
                from zone trust;
                to zone untrust;
                rule R1 {
                    then {
                        source-nat interface;
                    }
                }
            }
        }
        destination {
            pool P1 {
                address 10.0.30.100;
            }
            rule-set RD1 {
                from zone untrust;
                rule R1 {
                    match {
                        destination-address 198.51.100.1/32;
                    }
                    then {
                        destination-nat pool P1;
                    }
                }
            }
        }
        static {
            rule-set ST1 {
                from zone untrust;
                rule R1 {
                    match {
                        destination-address 198.51.100.10/32;
                    }
                    then {
                        static-nat prefix 10.0.1.10/32;
                    }
                }
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if len(sec.NAT.Source) != 1 || !hasSourceRuleSet(sec, "RS1") {
		t.Fatalf("single source block regressed: Source=%+v", sec.NAT.Source)
	}
	if sec.NAT.Destination == nil || len(sec.NAT.Destination.RuleSets) != 1 || !hasDestRuleSet(sec, "RD1") {
		t.Fatalf("single destination block regressed: %+v", sec.NAT.Destination)
	}
	if len(sec.NAT.Static) != 1 || !hasStaticRuleSet(sec, "ST1") {
		t.Fatalf("single static block regressed: Static=%+v", sec.NAT.Static)
	}
}
