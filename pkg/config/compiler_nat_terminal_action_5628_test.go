package config

import (
	"strings"
	"testing"
)

// #5628 (codex-review-181 M16): a source- or destination-NAT rule's complete
// `then {}` block must carry EXACTLY ONE NAT-terminal translation action —
// SNAT: `source-nat interface` | `source-nat pool <p>` | `source-nat off`;
// DNAT: `destination-nat pool <p>` | `destination-nat off`. Before the fix the
// schema permitted a block with ZERO actions (actionless: the snapshot builder
// installs no translation and the rule does not stop evaluation, so an intended
// `off` exemption silently disappears and the traffic falls through —
// translated by a later broader rule if one matches, otherwise left
// untranslated) or TWO+ mutually-exclusive actions (the
// compiler silently picked one by packed-key / child order, so an exemption
// could publish as a translation — the inverse of the authored action).
//
// validateNATTerminalActionCardinalityStrict hard-rejects both at strict commit
// (CompileConfig); the tolerant load / peer-sync path (CompileConfigLenient)
// downgrades to a warning (#1960 no-brick). Duplicate `then` CONTAINERS remain
// #3850's intentional last-wins merge and must NOT be rejected.
//
// RED on revert: reverting the gate (validateNATTerminalActionCardinalityStrict
// + its runUniformGates call) makes CompileConfig ACCEPT the zero/two-action
// configs, so every "want reject" case fails; reverting the compiler_nat_source
// / compiler_nat_destination hierarchical setter change (independent `if`s back
// to the `else if` chain) makes a single-node `source-nat { interface; pool p }`
// resolve to one field again, so the hierarchical two-action cases fail.

// compileHier parses hierarchical Junos text and strict-compiles it.
func compileHier5628(t *testing.T, cfgText string) (*Config, error) {
	t.Helper()
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	return CompileConfig(tree)
}

// wantCardinalityReject asserts CompileConfig rejected with the #5628 message.
func wantCardinalityReject5628(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: CompileConfig ACCEPTED a malformed NAT `then` block; want a "+
			"#5628 terminal-action-cardinality rejection (RED on revert: pre-fix "+
			"accepted 0/2 actions)", name)
	}
	if !strings.Contains(err.Error(), "translation action") {
		t.Fatalf("%s: CompileConfig rejected with the wrong error %q; want the #5628 "+
			"terminal-action-cardinality message", name, err.Error())
	}
}

// TestNATTerminalActionMessageContent_6820 binds what the two rejection
// messages SAY, not merely that they fire.
//
// wantCardinalityReject5628 matches on "translation action", which both arities
// share and neither owns. That left the message bodies content-unbound: #6820
// rewrote the 2+-action text — it used to claim "the compiler would silently
// pick one by packed-key/child order, so an intended exemption can publish as a
// translation", a mechanism the compiler stopped using at #5628 and which the
// same file's CONTRADICTORY bullet already contradicted — and the whole edit
// landed with no test able to see it. These strings are operator-visible on
// BOTH paths: verbatim in the strict commit rejection, and wrapped into a
// cfg.Warnings entry on the tolerant load / peer-sync path
// (compiler_uniformgates_firewall_nat2.go), which is the only signal an
// operator gets there since `show` renders one selected action.
//
// Asserted per-arity and per-kind, because the mechanism sentence differs: the
// precedence clause is a parameter of the shared `check` closure, so a source
// rule must name the `interface`/`pool` ordering and a destination rule — which
// has no `interface` action at all — must not.
func TestNATTerminalActionMessageContent_6820(t *testing.T) {
	twoActionSNAT := buildTree(t, []string{
		"set security nat source pool P address 203.0.113.5",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set security nat source rule-set RS rule R1 then source-nat off",
	})
	_, err := CompileConfig(twoActionSNAT)
	if err == nil {
		t.Fatal("CompileConfig ACCEPTED a two-action source-NAT rule")
	}
	for _, want := range []string{
		"2 mutually-exclusive translation actions",
		"every one of them is published to the dataplane",
		"fixed precedence",
		"`off` wins over `interface`, and `interface` over `pool`",
		"all but one action is silently discarded",
		// #6820 round 4: the survivor clause must be the PRECISE form, the one
		// docs/config-schema.md and the peer-effective test already carry. Round
		// 3 shipped a looser paraphrase here — "not the one you configured first
		// or last" — which is literally FALSE for a 2-action rule, where one
		// action IS first and the other IS last (this test's own DNAT fixture
		// authors `pool PD` first and `off` second, and `off` wins). Three
		// renderings of one fix went out together and the operator-facing one was
		// the wrong one, in a round whose subject was an operator-facing sentence
		// being false. Assert the exact phrase, because the loose form reads
		// better and that is precisely where it wins.
		//
		// #7035 narrowed that phrase. The unscoped form ("the survivor is not
		// chosen by configuration order") was false in exactly the case that
		// prints it: with duplicate `then` CONTAINERS the #3850 reset makes the
		// LAST container supply the counted fields, so container order selects
		// which contradiction — and therefore which survivor — you get. The
		// clause is now scoped to the block, and the parenthetical carries the
		// cross-container case. Both halves are asserted, so neither the old
		// unscoped form nor a silent drop of the scope can return.
		"WITHIN THIS BLOCK, the survivor is decided by that fixed precedence " +
			"rather than by the order the actions were written",
		"container order therefore does decide WHICH contradiction you get here",
		// #7034: the parenthetical used to end "this rejects contradictory
		// actions inside one block", which reads as a completeness claim and is
		// false for every token-packed spelling (`source-nat pool P off` and
		// friends lower to ONE field and commit — see
		// TestNATTerminalActionPackedContradictionCommits_7034). It now states
		// the shape it actually covers and names #7033 for the rest.
		"a contradiction whose tokens are PACKED onto one node",
		"#7033",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("2+-action SNAT rejection missing %q — the message must describe the "+
				"mechanism the compiler ACTUALLY uses (publish-all + dataplane precedence), "+
				"not the pre-#5628 packed-key/child-order pick: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "packed-key") || strings.Contains(err.Error(), "child order") {
		t.Errorf("2+-action rejection still tells the operator the compiler picks an "+
			"action by packed-key/child order; it records every field (#5628) and the "+
			"dataplane resolves them: %v", err)
	}

	twoActionDNAT := buildTree(t, []string{
		"set security nat destination pool PD address 10.0.0.5",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool PD",
		"set security nat destination rule-set RD rule R1 then destination-nat off",
	})
	_, err = CompileConfig(twoActionDNAT)
	if err == nil {
		t.Fatal("CompileConfig ACCEPTED a two-action destination-NAT rule")
	}
	if !strings.Contains(err.Error(), "`off`-over-`pool` precedence") {
		t.Errorf("2+-action DNAT rejection must name the DESTINATION precedence: %v", err)
	}
	if strings.Contains(err.Error(), "`interface`") {
		t.Errorf("2+-action DNAT rejection names `interface`, an action a destination-NAT "+
			"rule cannot carry — the mechanism clause leaked across kinds: %v", err)
	}
	// The kind-specific MECHANISM, not just the ordering (#6820 round 3). The DNAT
	// builder short-circuits on `isOff` and never resolves the pool
	// (pkg/dataplane/userspace/nat_destination.go), so telling a DNAT operator
	// that "every one of them is published to the dataplane" — true only of SNAT —
	// describes a path their rule does not take. A shared sentence here is
	// necessarily false for one of the two kinds.
	if !strings.Contains(err.Error(), "the compiler resolves `off` itself") {
		t.Errorf("2+-action DNAT rejection must say the COMPILER resolves `off` (pool-less "+
			"exemption, no pool lookup), not that every action reaches the dataplane: %v", err)
	}
	if strings.Contains(err.Error(), "every one of them is published") {
		t.Errorf("2+-action DNAT rejection claims every action is published — false for "+
			"destination NAT, whose builder skips pool resolution entirely for an `off` "+
			"rule and publishes an empty PoolAddress: %v", err)
	}

	// The ZERO-action message was rewritten by this PR too ("falls through —
	// translated by a later broader rule if one matches, otherwise left
	// untranslated", replacing a claim that a later rule always exists). Bind
	// both halves of that disjunction so neither can silently return to the
	// single-outcome wording.
	zeroAction := buildTree(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
	})
	_, err = CompileConfig(zeroAction)
	if err == nil {
		t.Fatal("CompileConfig ACCEPTED a zero-action source-NAT rule")
	}
	for _, want := range []string{
		"carries no translation action",
		"does not stop rule evaluation",
		"translated by a later broader rule if one matches",
		"otherwise left untranslated",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("zero-action rejection missing %q — the message must state BOTH "+
				"fall-through outcomes; asserting only the translated one presumes a "+
				"later rule exists (#6820): %v", want, err)
		}
	}
}

// --- VALID single-action rules must COMPILE clean (flat + hierarchical) ------

func TestNATTerminalActionValidSingle_5628(t *testing.T) {
	// Flat SNAT: exactly one `source-nat interface`.
	flatSNAT := buildTree(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat interface",
	})
	if _, err := CompileConfig(flatSNAT); err != nil {
		t.Fatalf("flat single-action SNAT rejected: %v", err)
	}

	// Flat DNAT: exactly one `destination-nat off`.
	flatDNAT := buildTree(t, []string{
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
		"set security nat destination rule-set RD rule R1 then destination-nat off",
	})
	if _, err := CompileConfig(flatDNAT); err != nil {
		t.Fatalf("flat single-action DNAT rejected: %v", err)
	}

	// Hierarchical SNAT: exactly one `source-nat pool p`.
	if _, err := compileHier5628(t, `
security {
    nat {
        source {
            pool p { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat pool p; }
                }
            }
        }
    }
}`); err != nil {
		t.Fatalf("hierarchical single-action SNAT rejected: %v", err)
	}

	// Hierarchical DNAT: exactly one `destination-nat pool p`.
	if _, err := compileHier5628(t, `
security {
    nat {
        destination {
            pool p { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat pool p; }
                }
            }
        }
    }
}`); err != nil {
		t.Fatalf("hierarchical single-action DNAT rejected: %v", err)
	}
}

// --- ZERO-action rules must be REJECTED (flat + hierarchical) ----------------

func TestNATTerminalActionZeroRejected_5628(t *testing.T) {
	// Flat SNAT: a rule with a match but NO `then` action.
	flatSNAT := buildTree(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
	})
	_, err := CompileConfig(flatSNAT)
	wantCardinalityReject5628(t, "flat zero-action SNAT", err)

	// Flat DNAT: a rule with a match but NO `then` action.
	flatDNAT := buildTree(t, []string{
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
	})
	_, err = CompileConfig(flatDNAT)
	wantCardinalityReject5628(t, "flat zero-action DNAT", err)

	// Hierarchical SNAT: an empty `then {}` block.
	_, err = compileHier5628(t, `
security {
    nat {
        source {
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { }
                }
            }
        }
    }
}`)
	wantCardinalityReject5628(t, "hierarchical zero-action SNAT", err)

	// Hierarchical DNAT: a rule with a match but no `then`.
	_, err = compileHier5628(t, `
security {
    nat {
        destination {
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                }
            }
        }
    }
}`)
	wantCardinalityReject5628(t, "hierarchical zero-action DNAT", err)
}

// --- TWO-action rules must be REJECTED (flat + hierarchical) -----------------

func TestNATTerminalActionTwoRejected_5628(t *testing.T) {
	// Flat SNAT: `source-nat interface` + `source-nat off` in one rule. SetPath
	// merges the two `then source-nat ...` lines into ONE source-nat node with
	// two children (interface, off) — a single complete then-block carrying two
	// mutually-exclusive actions.
	flatSNAT := buildTree(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat interface",
		"set security nat source rule-set RS rule R1 then source-nat off",
	})
	_, err := CompileConfig(flatSNAT)
	wantCardinalityReject5628(t, "flat two-action SNAT (interface+off)", err)

	// Flat DNAT: `destination-nat off` + `destination-nat pool p1` in one rule.
	flatDNAT := buildTree(t, []string{
		"set security nat destination pool p1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
		"set security nat destination rule-set RD rule R1 then destination-nat off",
		"set security nat destination rule-set RD rule R1 then destination-nat pool p1",
	})
	_, err = CompileConfig(flatDNAT)
	wantCardinalityReject5628(t, "flat two-action DNAT (off+pool)", err)

	// Hierarchical SNAT: a single `source-nat { interface; pool p; }` node. The
	// pre-#5628 else-if setter silently picked interface; the independent-if
	// setter now records both fields so the gate rejects.
	_, err = compileHier5628(t, `
security {
    nat {
        source {
            pool p { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; pool p; } }
                }
            }
        }
    }
}`)
	wantCardinalityReject5628(t, "hierarchical two-action SNAT (interface+pool one node)", err)

	// Hierarchical DNAT: a single `destination-nat { pool p; off; }` node.
	_, err = compileHier5628(t, `
security {
    nat {
        destination {
            pool p { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat { pool p; off; } }
                }
            }
        }
    }
}`)
	wantCardinalityReject5628(t, "hierarchical two-action DNAT (pool+off one node)", err)
}

// --- #3850 duplicate `then` CONTAINERS must NOT be false-rejected -----------

// TestNATTerminalActionDup3850LastWins_5628 pins that the cardinality gate does
// NOT reject a rule merely because it has two `then` CONTAINERS. Two `then`
// blocks each naming ONE source-nat action resolve last-wins (#3850): the
// compiler resets rule.Then per block, so the winning block carries exactly one
// action. This must compile AND resolve to the LAST block's pool.
func TestNATTerminalActionDup3850LastWins_5628(t *testing.T) {
	cfg, err := compileHier5628(t, `
security {
    nat {
        source {
            pool poolB { address 5.6.7.8; }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat interface; }
                    then { source-nat pool poolB; }
                }
            }
        }
    }
}`)
	if err != nil {
		t.Fatalf("#3850 duplicate-then-container rule FALSE-REJECTED by the #5628 gate "+
			"(must be last-wins, not a conflict): %v", err)
	}
	if len(cfg.Security.NAT.Source) == 0 || len(cfg.Security.NAT.Source[0].Rules) == 0 {
		t.Fatalf("no source NAT rule compiled")
	}
	r := cfg.Security.NAT.Source[0].Rules[0]
	if r.Then.PoolName != "poolB" || r.Then.Interface {
		t.Fatalf("#3850 last-wins broken: Then={Interface:%v PoolName:%q}, want "+
			"{false poolB} (second then block wins, first block's interface cleared)",
			r.Then.Interface, r.Then.PoolName)
	}
}

// TestNATTerminalActionDupIdenticalPool3850_5628 pins that two `then` containers
// naming the SAME pool also commit (last-wins to that pool, count one).
func TestNATTerminalActionDupIdenticalPool3850_5628(t *testing.T) {
	cfg, err := compileHier5628(t, `
security {
    nat {
        destination {
            pool p1 { address 10.0.30.100; }
            rule-set RD {
                from zone untrust;
                rule R1 {
                    match { destination-address 198.51.100.1/32; }
                    then { destination-nat pool p1; }
                    then { destination-nat pool p1; }
                }
            }
        }
    }
}`)
	if err != nil {
		t.Fatalf("#3850 duplicate identical-pool then-containers false-rejected: %v", err)
	}
	r := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if r.Then.PoolName != "p1" {
		t.Fatalf("duplicate identical-pool: PoolName=%q, want p1", r.Then.PoolName)
	}
}

// --- Tolerant load / peer-sync path WARNS, never bricks (#1960) --------------

func TestNATTerminalActionLenientWarns_5628(t *testing.T) {
	// A zero-action DNAT rule that strict-rejects must instead WARN-and-compile
	// on the tolerant path so an already-persisted / peer-synced config boots.
	flatDNAT := buildTree(t, []string{
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
	})
	// Strict rejects.
	if _, err := CompileConfig(flatDNAT); err == nil {
		t.Fatal("strict CompileConfig must reject the zero-action DNAT rule")
	}
	// Lenient warns and compiles.
	cfg, err := CompileConfigLenient(flatDNAT)
	if err != nil {
		t.Fatalf("tolerant CompileConfigLenient must NOT brick on a zero-action rule "+
			"(#1960 no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "NAT terminal-action cardinality") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant path must record a NAT terminal-action-cardinality "+
			"downgrade warning; warnings=%v", cfg.Warnings)
	}
}
