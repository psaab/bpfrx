package config

import (
	"strconv"
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
	if defects := natCardinalityMessageDefects6820("source", err.Error()); len(defects) > 0 {
		for _, d := range defects {
			t.Errorf("2+-action SNAT rejection: %s\n  message: %v", d, err)
		}
	}
	if !strings.Contains(err.Error(), "2 mutually-exclusive translation actions") {
		t.Errorf("2+-action SNAT rejection must report the ARITY it counted: %v", err)
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
	if defects := natCardinalityMessageDefects6820("destination", err.Error()); len(defects) > 0 {
		for _, d := range defects {
			t.Errorf("2+-action DNAT rejection: %s\n  message: %v", d, err)
		}
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

// --- #6820 round 5: bind the CLAIMS to the BEHAVIOUR, not to their wording ---
//
// Round 4 pinned the sentence "the survivor is not chosen by configuration
// order" with a case-sensitive strings.Contains. That pins BYTES, not MEANING,
// two ways over:
//
//   - the sentence was FALSE. compileNATSource/compileNATDestination reset
//     rule.Then per `then` CONTAINER (#3850 last-wins), so with duplicate
//     containers the LAST one supplies the counted fields and configuration
//     order DOES choose the survivor — measured below, both directions.
//   - a substring pin cannot see polarity. `The statement "the survivor is not
//     chosen by configuration order" is false; configuration order chooses it.`
//     contains the pinned run verbatim and passes. Proving that a PARAPHRASE
//     reds proves only that the pin detects rewording; a negation containing
//     the run is the case that matters, and it was never tested.
//
// The fix is not a longer string. A claim about behaviour is bound to the
// BEHAVIOUR here (the two tests below run configs through the pipeline and
// assert the actual survivor), and the residue that can only be text is pinned
// as WHOLE sentences with their context by natCardinalityMessageDefects_6820,
// which also rejects a refutation frame and is itself proved to fire by being
// fed the negation above.

// natThenSurvivor6820 names the single translation that survives a resolved
// NATThen under the documented fixed precedence the rejection message states:
// `off` > `interface` > `pool` for source NAT, `off` > `pool` for destination
// NAT (which has no interface mode). Enforcement lives in Rust (nat/source.rs,
// nat/destination.rs) and is pinned there; this mirror exists so the Go-side
// tests can state a survivor in the same terms the operator-facing message
// does.
func natThenSurvivor6820(then NATThen) string {
	switch {
	case then.Off:
		return "off"
	case then.Interface:
		return "interface"
	case then.PoolName != "":
		return "pool " + then.PoolName
	default:
		return "none"
	}
}

// tolerantNATThen6820 compiles cfgText on the TOLERANT path (#1960 no-brick,
// the arm a malformed rule actually reaches at runtime) and returns the
// resolved NATThen of the single rule. The strict path rejects these configs by
// design, so the resolved survivor is only observable here.
func tolerantNATThen6820(t *testing.T, label, cfgText string, dest bool) NATThen {
	t.Helper()
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("%s: parse: %v", label, perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("%s: CompileConfigLenient: %v", label, err)
	}
	var found []NATThen
	if dest {
		if cfg.Security.NAT.Destination != nil {
			for _, rs := range cfg.Security.NAT.Destination.RuleSets {
				for _, r := range rs.Rules {
					found = append(found, r.Then)
				}
			}
		}
	} else {
		for _, rs := range cfg.Security.NAT.Source {
			for _, r := range rs.Rules {
				found = append(found, r.Then)
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: want exactly 1 compiled NAT rule, got %d", label, len(found))
	}
	return found[0]
}

func snatCfg6820(then string) string {
	return `
security { nat { source {
  pool P { address 203.0.113.5; }
  rule-set RS { from zone trust; to zone untrust;
    rule R1 { match { source-address 10.0.0.0/24; }
      ` + then + `
    } } } } }
`
}

func dnatCfg6820(then string) string {
	return `
security { nat { destination {
  pool PD { address 10.0.0.5; }
  rule-set RD { from zone untrust;
    rule R1 { match { destination-address 198.51.100.1/32; }
      ` + then + `
    } } } } }
`
}

// TestNATSurvivorIsOrderInvariantWithinBlock_6820 binds the corrected message's
// scoped claim — the survivor is decided by the fixed precedence "rather than
// by the order the actions are written inside this block" — by AUTHORING each
// contradiction in both within-block orders and asserting the resolved NATThen
// is identical.
//
// This is also the behavioural binding for #6820 B1. A packed action leaf
// (`source-nat off pool P` -> Keys=[source-nat off pool P]) used to be read as
// Keys[1] ALONE, so the two orders resolved DIFFERENTLY — off for one, pool for
// the other — and, because only one field was ever lowered, the cardinality
// gate counted n == 1 and STRICTLY COMMITTED the contradiction. Both halves are
// asserted: the two orders agree, AND strict commit rejects.
//
// RED on revert: restoring the Keys[1]-only read (or any first-match scan) in
// applyNATThenActions makes the packed rows resolve to different survivors and
// makes strict commit accept them.
func TestNATSurvivorIsOrderInvariantWithinBlock_6820(t *testing.T) {
	cases := []struct {
		name         string
		dest         bool
		orderA       string
		orderB       string
		wantSurvivor string
	}{
		{
			name: "SNAT packed off/pool", orderA: "then { source-nat off pool P; }",
			orderB: "then { source-nat pool P off; }", wantSurvivor: "off",
		},
		{
			name: "SNAT packed interface/pool", orderA: "then { source-nat interface pool P; }",
			orderB: "then { source-nat pool P interface; }", wantSurvivor: "interface",
		},
		{
			name: "SNAT hierarchical off/pool", orderA: "then { source-nat { off; pool P; } }",
			orderB: "then { source-nat { pool P; off; } }", wantSurvivor: "off",
		},
		{
			name: "SNAT hierarchical interface/pool", orderA: "then { source-nat { interface; pool P; } }",
			orderB: "then { source-nat { pool P; interface; } }", wantSurvivor: "interface",
		},
		{
			name: "DNAT packed off/pool", dest: true, orderA: "then { destination-nat off pool PD; }",
			orderB: "then { destination-nat pool PD off; }", wantSurvivor: "off",
		},
		{
			name: "DNAT hierarchical off/pool", dest: true, orderA: "then { destination-nat { off; pool PD; } }",
			orderB: "then { destination-nat { pool PD; off; } }", wantSurvivor: "off",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			build := snatCfg6820
			if tc.dest {
				build = dnatCfg6820
			}
			thenA := tolerantNATThen6820(t, tc.name+" orderA", build(tc.orderA), tc.dest)
			thenB := tolerantNATThen6820(t, tc.name+" orderB", build(tc.orderB), tc.dest)
			if thenA != thenB {
				t.Errorf("within-block authoring order CHANGED the resolved translation:\n"+
					"  %-8s %q -> %+v\n  %-8s %q -> %+v\n"+
					"The rejection message tells the operator the survivor is decided by the "+
					"fixed precedence rather than by the order the actions are written inside "+
					"the block. That is only true if every authored action is lowered; a "+
					"first-match read of the packed Keys tail or the children drops all but "+
					"one and makes the outcome depend on which token came first (#6820 B1).",
					"orderA", tc.orderA, thenA, "orderB", tc.orderB, thenB)
			}
			if got := natThenSurvivor6820(thenA); got != tc.wantSurvivor {
				t.Errorf("survivor = %q, want %q (resolved %+v)", got, tc.wantSurvivor, thenA)
			}
			// Every authored action must reach the gate, so STRICT commit must
			// reject both orders. Before #6820 B1 the packed rows committed.
			for _, order := range []string{tc.orderA, tc.orderB} {
				p := NewParser(build(order))
				tree, perrs := p.Parse()
				if len(perrs) > 0 {
					t.Fatalf("parse %q: %v", order, perrs)
				}
				if _, err := CompileConfig(tree); err == nil {
					t.Errorf("STRICT commit ACCEPTED the contradictory rule %q — the "+
						"cardinality gate saw fewer actions than were authored, which is "+
						"exactly the #6820 B1 escape (packed tail read as Keys[1] alone)", order)
				} else if !strings.Contains(err.Error(), "mutually-exclusive translation actions") {
					t.Errorf("STRICT commit rejected %q with the wrong gate: %v", order, err)
				}
			}
		})
	}
}

// TestNATDuplicateContainerLastWinsChoosesSurvivor_6820 binds the other half of
// the corrected sentence: configuration order IS relevant to the rule as a
// whole, at CONTAINER granularity. compileNATSource resets rule.Then at the top
// of each `then` container (#3850 last-wins), so the LAST container supplies
// the fields, and the fixed precedence resolves only among those.
//
// The rows are the ones that refuted round 4's sentence: the SAME two
// contradictory containers in either order resolve to DIFFERENT survivors. The
// test asserts each survivor AND asserts the two differ, so a message claiming
// order is irrelevant is contradicted by a measurement in the same package.
//
// RED on revert: removing the per-container `rule.Then = NATThen{}` reset makes
// both orders accumulate every field, so both resolve to `off` and the
// "order chose" inequality fails.
func TestNATDuplicateContainerLastWinsChoosesSurvivor_6820(t *testing.T) {
	const contradictoryOffFirst = `then { source-nat { off; pool P; } }
      then { source-nat { interface; pool P; } }`
	const contradictoryIfaceFirst = `then { source-nat { interface; pool P; } }
      then { source-nat { off; pool P; } }`

	offFirst := tolerantNATThen6820(t, "off+pool then interface+pool",
		snatCfg6820(contradictoryOffFirst), false)
	ifaceFirst := tolerantNATThen6820(t, "interface+pool then off+pool",
		snatCfg6820(contradictoryIfaceFirst), false)

	if got, want := natThenSurvivor6820(offFirst), "interface"; got != want {
		t.Errorf("[off+pool] then [interface+pool]: survivor = %q, want %q (%+v) — the "+
			"LAST container must supply the counted actions (#3850 last-wins)", got, want, offFirst)
	}
	if got, want := natThenSurvivor6820(ifaceFirst), "off"; got != want {
		t.Errorf("[interface+pool] then [off+pool]: survivor = %q, want %q (%+v)",
			got, want, ifaceFirst)
	}
	if natThenSurvivor6820(offFirst) == natThenSurvivor6820(ifaceFirst) {
		t.Fatalf("swapping the two `then` CONTAINERS did not change the survivor (%q both "+
			"ways) — this test exists because it DOES, and the round-4 rejection sentence "+
			"claimed the opposite", natThenSurvivor6820(offFirst))
	}

	// Single-action containers: #3850's intentional last-wins merge. These
	// COMMIT (the gate counts the winning container only) and the last container
	// still decides — the same order-dependence, in the shape the gate
	// deliberately does not reject.
	lastPool := tolerantNATThen6820(t, "off then pool",
		snatCfg6820("then { source-nat { off; } }\n      then { source-nat { pool P; } }"), false)
	lastOff := tolerantNATThen6820(t, "pool then off",
		snatCfg6820("then { source-nat { pool P; } }\n      then { source-nat { off; } }"), false)
	if got, want := natThenSurvivor6820(lastPool), "pool P"; got != want {
		t.Errorf("[off] then [pool P]: survivor = %q, want %q (%+v)", got, want, lastPool)
	}
	if got, want := natThenSurvivor6820(lastOff), "off"; got != want {
		t.Errorf("[pool P] then [off]: survivor = %q, want %q (%+v)", got, want, lastOff)
	}
	for _, cfgText := range []string{
		snatCfg6820("then { source-nat { off; } }\n      then { source-nat { pool P; } }"),
		snatCfg6820("then { source-nat { pool P; } }\n      then { source-nat { off; } }"),
	} {
		p := NewParser(cfgText)
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Errorf("STRICT commit REJECTED duplicate single-action `then` containers; "+
				"#3850 last-wins must keep committing and the message says so explicitly: %v", err)
		}
	}
}

// natCardinalityMessageDefects6820 reports every way msg fails to STATE the
// #6820 mechanism claims for the given NAT kind. An empty result means the
// message states them. kind is "source" or "destination".
//
// WHY a function over a string, and not inline strings.Contains calls in the
// test (#6820 round 5, B3). The round-4 binder pinned one bare clause — "the
// survivor is not chosen by configuration order" — with a case-sensitive
// Contains. That pins BYTES, not MEANING, and this rewrite passes it verbatim:
//
//	The statement "the survivor is not chosen by configuration order" is
//	false; configuration order chooses it.
//
// Proving that a PARAPHRASE reds proves only that the pin detects rewording; a
// bare-clause pin cannot see polarity at all. So this checker does two things a
// clause pin cannot, and is a FUNCTION so the test can feed it a negation and
// prove it fires — a green assertion with no witnessing red shows only that the
// checker ran:
//
//   - it pins each kind's mechanism sentence CONCATENATED with the shared claim
//     tail, as ONE contiguous run. A run is what makes an interior deletion
//     visible: dropping "and never looking the pool up, and the dataplane
//     applies the same " from the DNAT text leaves a semantically damaged
//     message that every clause-level pin still accepts (#6820 B4).
//   - it rejects a REFUTATION FRAME anywhere in the message. None of these
//     markers occur in the true text (note "is not irrelevant" is deliberately
//     not matched by them), and a message that quotes the claim in order to
//     deny it necessarily carries one.
//
// The behavioural half of these claims is NOT checked here — a message is not
// evidence about the code. It is measured by
// TestNATSurvivorIsOrderInvariantWithinBlock_6820 (within-block order does not
// choose) and TestNATDuplicateContainerLastWinsChoosesSurvivor_6820 (container
// order does).
func natCardinalityMessageDefects6820(kind, msg string) []string {
	const sharedTail = ", so all but one action is silently discarded, and which one " +
		"survives is decided by that precedence rather than by the order the actions " +
		"are written inside this block. Configuration order is not irrelevant to the " +
		"rule as a whole: duplicate `then` CONTAINERS are resolved FIRST, last-wins " +
		"per #3850 — the LAST container supplies the actions counted here — and the " +
		"precedence above then resolves among them. (This rejects contradictory " +
		"actions inside one block; it does not reject duplicate containers.)"

	const sourceMechanism = "every one of them is published to the dataplane, which " +
		"resolves the rule by a fixed precedence — `off` wins over `interface`, and " +
		"`interface` over `pool`"
	const destMechanism = "the compiler resolves `off` itself, publishing a pool-less " +
		"exemption and never looking the pool up, and the dataplane applies the same " +
		"`off`-over-`pool` precedence to any entry that carries both"

	var defects []string
	var wantRun string
	switch kind {
	case "source":
		wantRun = sourceMechanism + sharedTail
		if strings.Contains(msg, "the compiler resolves `off` itself") {
			defects = append(defects, "carries the DESTINATION mechanism (the compiler "+
				"resolving `off`); source NAT forwards every field and the dataplane picks")
		}
	case "destination":
		wantRun = destMechanism + sharedTail
		if strings.Contains(msg, "`interface`") {
			defects = append(defects, "names `interface`, an action a destination-NAT rule "+
				"cannot carry — the mechanism clause leaked across kinds")
		}
		if strings.Contains(msg, "every one of them is published") {
			defects = append(defects, "claims every action is published — false for "+
				"destination NAT, whose builder skips pool resolution entirely for an `off` "+
				"rule and publishes an empty PoolAddress")
		}
	default:
		return []string{"natCardinalityMessageDefects6820: unknown kind " + kind}
	}
	if !strings.Contains(msg, wantRun) {
		defects = append(defects, "does not carry the "+kind+
			"-NAT mechanism sentence joined to the claim tail as one contiguous run; want:\n    "+
			wantRun)
	}

	// The mechanism the compiler stopped using. Both halves are dead since
	// #6820 B1 (child order died at #5628, packed-key order at #6820).
	for _, stale := range []string{"packed-key", "child order"} {
		if strings.Contains(msg, stale) {
			defects = append(defects, "still tells the operator the compiler picks an action "+
				"by "+stale+"; it records every authored field from both the packed tail and "+
				"the children (applyNATThenActions) and the dataplane resolves them")
		}
	}

	// Polarity. A message that quotes a claim to DENY it satisfies every
	// substring pin above; only a refutation-frame check sees it.
	for _, frame := range []string{
		"is false", "is not true", "is incorrect", "is wrong",
		"the statement", "contrary to", "does choose", "chooses it",
	} {
		if strings.Contains(strings.ToLower(msg), frame) {
			defects = append(defects, "carries the refutation marker "+strconv.Quote(frame)+
				" — the rejection text must ASSERT the mechanism, not quote and deny it. A "+
				"negation that embeds the pinned run verbatim passes every substring pin "+
				"(#6820 B3)")
		}
	}
	return defects
}

// TestNATCardinalityMessageCheckerRejectsNegation_6820 is the witnessing RED for
// natCardinalityMessageDefects6820: without it, "the checker returned no
// defects" is indistinguishable from a checker that cannot fail.
//
// The negative fixture is deliberately the HARD one. It is the REAL rejection
// text, unmodified, with a refutation frame prepended — so every contiguous-run
// pin still matches and only the polarity gate can catch it. That is exactly
// the shape round 4's binder admitted.
func TestNATCardinalityMessageCheckerRejectsNegation_6820(t *testing.T) {
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
	real := err.Error()

	// Control: the real message must pass, or the negatives below prove nothing.
	if defects := natCardinalityMessageDefects6820("source", real); len(defects) > 0 {
		t.Fatalf("control: the REAL rejection text was reported defective, so this test's "+
			"negatives are meaningless: %v", defects)
	}

	negated := "The statement below is false; configuration order chooses it. " + real
	if defects := natCardinalityMessageDefects6820("source", negated); len(defects) == 0 {
		t.Errorf("a NEGATION of the claim passed the checker. It embeds the whole pinned "+
			"run verbatim, so every substring pin matches; only the refutation-frame gate "+
			"can reject it, and it did not fire:\n  %s", negated)
	}

	// B4: an interior deletion from the DNAT mechanism must be visible. The
	// fragment below was deletable at round 4 with the binder still green.
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
	realDNAT := err.Error()
	if defects := natCardinalityMessageDefects6820("destination", realDNAT); len(defects) > 0 {
		t.Fatalf("control: the REAL DNAT rejection text was reported defective: %v", defects)
	}
	const b4Fragment = "and never looking the pool up, and the dataplane applies the same "
	if !strings.Contains(realDNAT, b4Fragment) {
		t.Fatalf("the #6820 B4 fragment is no longer in the DNAT message; re-derive this "+
			"test's deletion fixture: %s", realDNAT)
	}
	damaged := strings.Replace(realDNAT, b4Fragment, "", 1)
	if defects := natCardinalityMessageDefects6820("destination", damaged); len(defects) == 0 {
		t.Errorf("deleting %q from the DNAT mechanism left the checker green — the run pin "+
			"is not contiguous enough to see an interior deletion (#6820 B4):\n  %s",
			b4Fragment, damaged)
	}
}
