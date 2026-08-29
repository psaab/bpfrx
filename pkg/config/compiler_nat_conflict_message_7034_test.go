package config

import "testing"

// #7034 / #7035: the 2+-action NAT rejection message made two claims about
// itself that were false at the head that shipped them. These tests pin the
// behaviour the corrected message describes, so the message is checked rather
// than asserted — a claim about a compiler's coverage is exactly the kind that
// rots silently, because nothing reads it but a human.

// TestNATTerminalActionPackedContradictionCommits_7034 pins the BOUND on the
// cardinality gate: it counts RESOLVED fields, so a contradiction whose tokens
// are packed onto one node lowers to a single action and commits under strict.
//
// The old parenthetical read "this rejects contradictory actions inside one
// block", which is a completeness claim over the block-level case. It is false
// for every packed spelling below: the compiler's packed branch switches on
// `t.Keys[1]` alone (compileNATSource / compileNATDestination) and drops the
// rest, so the operator gets a green commit for a rule whose authored `off`
// exemption was silently discarded, or whose pool was.
//
// #7033 IS NOW CLOSED, and this test was flipped rather than deleted, as its
// previous version demanded.
//
// What it pinned was a GAP: every case below used to COMMIT under strict. They
// are now rejected. The resolved values it asserted are kept, and that is the
// substance of the flip rather than a courtesy to the old test: #7033 was fixed
// by DETECTION, not by changing what a packed run lowers to, and these
// assertions are the evidence. Two rounds of #6820 tried to fix it in the
// lowering and each was reverted for resolving something new — round 5 made
// `destination-nat interface pool PD` resolve as a pool translation, round 6
// fabricated an exemption from an unrecognised container. Reading the resolved
// Then off the LENIENT path (the strict path now returns no config) shows every
// packed run still lowers exactly as it did before the fix.
func TestNATTerminalActionPackedContradictionRejected_7034_7033(t *testing.T) {
	snat := func(then string) string {
		return `
security {
    nat {
        source {
            pool P { address 203.0.113.5; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    ` + then + `
                }
            }
        }
    }
}`
	}

	lenientThen := func(t *testing.T, cfgText string) NATThen {
		t.Helper()
		tree, perrs := NewParser(cfgText).Parse()
		if len(perrs) > 0 {
			t.Fatalf("Parse: %v", perrs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile failed: %v", err)
		}
		return cfg.Security.NAT.Source[0].Rules[0].Then
	}

	for _, tc := range []struct {
		name     string
		then     string
		wantOff  bool
		wantPool string
	}{
		// `off` first: the pool is dropped.
		{"packed off then pool", "then { source-nat off pool P; }", true, ""},
		// `pool` first: the exemption is dropped — the dangerous direction.
		{"packed pool then off", "then { source-nat pool P off; }", false, "P"},
		// Same contradiction one level down, packed onto the child's keys.
		{"packed child node", "then { source-nat { pool P off; } }", false, "P"},
	} {
		if _, err := compileHier5628(t, snat(tc.then)); err == nil {
			t.Errorf("%s: strict CompileConfig ACCEPTED %q. #7033 is closed; a packed "+
				"cross-mode contradiction must be rejected", tc.name, tc.then)
		}
		got := lenientThen(t, snat(tc.then))
		if got.Off != tc.wantOff || got.PoolName != tc.wantPool {
			t.Errorf("%s: LENIENT resolved Then={Off:%v Interface:%v PoolName:%q}, want "+
				"{Off:%v PoolName:%q}. The #7033 fix must not change what a packed run "+
				"lowers to — that is what separates it from the two reverted attempts "+
				"to fix it in the lowering",
				tc.name, got.Off, got.Interface, got.PoolName, tc.wantOff, tc.wantPool)
		}
		if n := natThenTerminalActionCount(got); n != 1 {
			t.Errorf("%s: natThenTerminalActionCount=%d, want 1 — the packed "+
				"contradiction is still counted as ONE action, which is exactly why "+
				"the resolved-field count cannot see it and a separate check must",
				tc.name, n)
		}
	}

	// The flat `set` spelling packs the same way, and is the shape an operator
	// actually types.
	flatLines := []string{
		"set security nat source pool P address 203.0.113.5",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P off",
	}
	if _, err := CompileConfig(buildTree(t, flatLines)); err == nil {
		t.Error("flat `then source-nat pool P off`: strict CompileConfig ACCEPTED it")
	}
	flatCfg, err := CompileConfigLenient(buildTree(t, flatLines))
	if err != nil {
		t.Fatalf("flat lenient compile failed: %v", err)
	}
	if got := flatCfg.Security.NAT.Source[0].Rules[0].Then; got.PoolName != "P" || got.Off {
		t.Errorf("flat packed lenient: Then={Off:%v PoolName:%q}, want {false P}", got.Off, got.PoolName)
	}

	// Destination NAT packs identically — the rejection is shared by both kinds,
	// so the claim it makes has to be true of both.
	dnatText := `
security {
    nat {
        destination {
            pool PD { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat pool PD off; }
                }
            }
        }
    }
}`
	if _, err := compileHier5628(t, dnatText); err == nil {
		t.Error("packed DNAT contradiction: strict CompileConfig ACCEPTED it")
	}
	dtree, perrs := NewParser(dnatText).Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	dnat, err := CompileConfigLenient(dtree)
	if err != nil {
		t.Fatalf("DNAT lenient compile failed: %v", err)
	}
	if got := dnat.Security.NAT.Destination.RuleSets[0].Rules[0].Then; got.PoolName != "PD" || got.Off {
		t.Errorf("packed DNAT lenient: Then={Off:%v PoolName:%q}, want {false PD}", got.Off, got.PoolName)
	}
}

// TestNATTerminalActionContainerOrderPicksSurvivor_7035 pins that configuration
// order DOES choose the survivor across duplicate `then` containers — the case
// in which the old unscoped clause ("the survivor is not chosen by
// configuration order") was printed and false.
//
// Both fixtures below carry the SAME two containers and differ only in their
// order. Both are rejected by the strict gate (each container carries two
// actions, so the count on the winning container is two) and both print the
// message. On the tolerant path — the one an already-persisted or peer-synced
// config takes — the #3850 reset makes the LAST container supply the fields, so
// the surviving action flips between `interface` and `off` with the order.
func TestNATTerminalActionContainerOrderPicksSurvivor_7035(t *testing.T) {
	cfgText := func(first, second string) string {
		return `
security {
    nat {
        source {
            pool P { address 203.0.113.5; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { ` + first + ` pool P; } }
                    then { source-nat { ` + second + ` pool P; } }
                }
            }
        }
    }
}`
	}

	for _, tc := range []struct {
		name          string
		first, second string
		wantOff       bool
		wantInterface bool
	}{
		{"off first, interface last", "off;", "interface;", false, true},
		{"interface first, off last", "interface;", "off;", true, false},
	} {
		text := cfgText(tc.first, tc.second)

		// Strict rejects both, with the same message — which is why an unscoped
		// "not chosen by configuration order" was false in exactly the case that
		// printed it.
		p := NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: Parse: %v", tc.name, perrs)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("%s: strict CompileConfig ACCEPTED a rule whose winning `then` "+
				"container carries two actions", tc.name)
		}

		// The tolerant survivor is what container order actually selects.
		p2 := NewParser(text)
		tree2, perrs2 := p2.Parse()
		if len(perrs2) > 0 {
			t.Fatalf("%s: Parse (lenient): %v", tc.name, perrs2)
		}
		cfg, err := CompileConfigLenient(tree2)
		if err != nil {
			t.Fatalf("%s: CompileConfigLenient must not brick on a malformed rule "+
				"(#1960): %v", tc.name, err)
		}
		got := cfg.Security.NAT.Source[0].Rules[0].Then
		if got.Off != tc.wantOff || got.Interface != tc.wantInterface {
			t.Errorf("%s: resolved Then={Off:%v Interface:%v PoolName:%q}, want "+
				"{Off:%v Interface:%v} — the LAST container supplies the fields "+
				"(#3850), so swapping the containers swaps which contradiction, and "+
				"therefore which surviving action, the operator gets",
				tc.name, got.Off, got.Interface, got.PoolName, tc.wantOff, tc.wantInterface)
		}
		if got.PoolName != "P" {
			t.Errorf("%s: PoolName=%q, want P (the pool is authored in both containers)",
				tc.name, got.PoolName)
		}
	}
}
