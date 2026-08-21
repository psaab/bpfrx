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
	return tolerantNATThenTree6820(t, label, tree, dest)
}

// tolerantNATThenTree6820 is tolerantNATThen6820 over an already-built tree, so
// a flat-set fixture (ParseSetCommand + SetPath — the only way to build the
// grandchild-chain AST shape, per CLAUDE.md) can be resolved the same way a
// hierarchical one is.
func tolerantNATThenTree6820(t *testing.T, label string, tree *ConfigTree, dest bool) NATThen {
	t.Helper()
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

// natThenShape6820 is ONE of the AST shapes a NAT rule's `then` action block
// reaches the compiler in. Which shape an operator gets is decided by the
// SYNTAX they used, not by what they wrote, so a table that builds only one
// shape cannot see a compiler bug that lives in another (#6820 round 6, B1):
//
//	set … then source-nat off pool P       [source-nat] / [off] / [pool P]   a GRANDCHILD chain
//	then { source-nat off pool P; }        Keys=[source-nat off pool P]      packed on the container
//	then { source-nat { off pool P; } }    [source-nat] / [off pool P]       packed on a CHILD
//	then { source-nat { off; pool P; } }   [source-nat] / [off] + [pool P]   sibling children (#5628)
//
// The flat-set row is the one the round-5 table missed entirely, and CLAUDE.md
// says why it must be built with ParseSetCommand + SetPath rather than
// NewParser: "the parser treats newlines as whitespace and will merge all set
// lines into one giant node". Only SetPath builds the chain, so only SetPath
// exercises the grandchild read.
//
// Each shape takes the SAME list of action clauses (e.g. ["off", "pool P"]) so
// one row of a table is authored once and measured in every shape.
type natThenShape6820 struct {
	name  string
	build func(t *testing.T, dest bool, actions []string) *ConfigTree
}

// natSetPrologue6820 returns the flat-set commands that define the pool,
// rule-set and match for one NAT kind, plus the `set … rule R1 ` prefix a
// then-clause is appended to.
func natSetPrologue6820(dest bool) (prologue []string, rulePrefix string) {
	if dest {
		return []string{
			"set security nat destination pool PD address 10.0.0.5",
			"set security nat destination rule-set RD from zone untrust",
			"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
		}, "set security nat destination rule-set RD rule R1 "
	}
	return []string{
		"set security nat source pool P address 203.0.113.5",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
	}, "set security nat source rule-set RS rule R1 "
}

func natThenKeyword6820(dest bool) string {
	if dest {
		return "destination-nat"
	}
	return "source-nat"
}

// natHierTree6820 parses a hierarchical config carrying the given `then` block.
func natHierTree6820(t *testing.T, dest bool, thenBlock string) *ConfigTree {
	t.Helper()
	text := snatCfg6820(thenBlock)
	if dest {
		text = dnatCfg6820(thenBlock)
	}
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", thenBlock, perrs)
	}
	return tree
}

// natThenShapes6820 is the shape matrix every contradiction row is run through.
var natThenShapes6820 = []natThenShape6820{
	{
		name: "flat-set (SetPath grandchild chain)",
		build: func(t *testing.T, dest bool, actions []string) *ConfigTree {
			t.Helper()
			prologue, prefix := natSetPrologue6820(dest)
			lines := append(append([]string{}, prologue...),
				prefix+"then "+natThenKeyword6820(dest)+" "+strings.Join(actions, " "))
			tree := &ConfigTree{}
			for _, l := range lines {
				path, err := ParseSetCommand(l)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", l, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", l, err)
				}
			}
			return tree
		},
	},
	{
		name: "hierarchical packed on the container",
		build: func(t *testing.T, dest bool, actions []string) *ConfigTree {
			t.Helper()
			return natHierTree6820(t, dest,
				"then { "+natThenKeyword6820(dest)+" "+strings.Join(actions, " ")+"; }")
		},
	},
	{
		name: "hierarchical packed on a child",
		build: func(t *testing.T, dest bool, actions []string) *ConfigTree {
			t.Helper()
			return natHierTree6820(t, dest,
				"then { "+natThenKeyword6820(dest)+" { "+strings.Join(actions, " ")+"; } }")
		},
	},
	{
		name: "hierarchical sibling children (#5628)",
		build: func(t *testing.T, dest bool, actions []string) *ConfigTree {
			t.Helper()
			return natHierTree6820(t, dest,
				"then { "+natThenKeyword6820(dest)+" { "+strings.Join(actions, "; ")+"; } }")
		},
	},
}

// TestNATSurvivorIsOrderInvariantWithinBlock_6820 binds the corrected message's
// scoped claim — the survivor is decided by the fixed precedence "rather than
// by the order the actions are written inside this block" — by AUTHORING each
// contradiction in both within-block orders, IN EVERY AST SHAPE, and asserting
// the resolved NATThen is identical across all of them.
//
// This is the behavioural binding for #6820 B1. A contradiction used to lower
// exactly ONE field, so the two orders resolved DIFFERENTLY — off for one, pool
// for the other — and, because only one field was ever lowered, the cardinality
// gate counted n == 1 and STRICTLY COMMITTED the contradiction. Round 5 fixed
// the container-packed shape; the flat-set chain and the child-packed tail were
// still escaping, and no fixture in this file could see them because every row
// was built with NewParser. Three assertions per shape — the two orders agree,
// the survivor is the documented one, and strict commit rejects — plus a
// cross-shape assertion that all four shapes resolve IDENTICALLY, which is the
// property the operator actually depends on (the same config, typed two ways,
// must mean the same thing).
//
// RED on revert: restoring any first-match / single-level read in
// applyNATThenActions makes the affected shapes resolve to different survivors
// and makes strict commit accept them.
func TestNATSurvivorIsOrderInvariantWithinBlock_6820(t *testing.T) {
	cases := []struct {
		name         string
		dest         bool
		orderA       []string
		orderB       []string
		wantSurvivor string
	}{
		{
			name: "SNAT off/pool", orderA: []string{"off", "pool P"},
			orderB: []string{"pool P", "off"}, wantSurvivor: "off",
		},
		{
			name: "SNAT interface/pool", orderA: []string{"interface", "pool P"},
			orderB: []string{"pool P", "interface"}, wantSurvivor: "interface",
		},
		{
			name: "DNAT off/pool", dest: true, orderA: []string{"off", "pool PD"},
			orderB: []string{"pool PD", "off"}, wantSurvivor: "off",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			perShape := make(map[string]NATThen, len(natThenShapes6820))
			for _, shape := range natThenShapes6820 {
				treeA := shape.build(t, tc.dest, tc.orderA)
				treeB := shape.build(t, tc.dest, tc.orderB)
				thenA := tolerantNATThenTree6820(t, tc.name+" "+shape.name+" orderA", treeA, tc.dest)
				thenB := tolerantNATThenTree6820(t, tc.name+" "+shape.name+" orderB", treeB, tc.dest)
				if thenA != thenB {
					t.Errorf("[%s] within-block authoring order CHANGED the resolved translation:\n"+
						"  orderA %v -> %+v\n  orderB %v -> %+v\n"+
						"The rejection message tells the operator the survivor is decided by the "+
						"fixed precedence rather than by the order the actions are written inside "+
						"the block. That is only true if every authored action is lowered; a scan "+
						"that misses this AST shape drops all but one and makes the outcome depend "+
						"on which token came first (#6820 B1).",
						shape.name, tc.orderA, thenA, tc.orderB, thenB)
				}
				if got := natThenSurvivor6820(thenA); got != tc.wantSurvivor {
					t.Errorf("[%s] survivor = %q, want %q (resolved %+v)",
						shape.name, got, tc.wantSurvivor, thenA)
				}
				// Every authored action must reach the gate, so STRICT commit
				// must reject both orders in every shape.
				for label, tree := range map[string]*ConfigTree{"orderA": treeA, "orderB": treeB} {
					if _, err := CompileConfig(tree); err == nil {
						t.Errorf("[%s] STRICT commit ACCEPTED the contradictory %s rule — the "+
							"cardinality gate saw fewer actions than were authored, which is "+
							"exactly the #6820 escape", shape.name, label)
					} else if !strings.Contains(err.Error(), "mutually-exclusive translation actions") {
						t.Errorf("[%s] STRICT commit rejected %s with the wrong gate: %v",
							shape.name, label, err)
					}
				}
				perShape[shape.name] = thenA
			}
			// Cross-shape: the same authored actions must resolve to the same
			// translation whichever syntax typed them.
			ref := perShape[natThenShapes6820[0].name]
			for _, shape := range natThenShapes6820[1:] {
				if got := perShape[shape.name]; got != ref {
					t.Errorf("the SAME actions resolve differently per syntax:\n"+
						"  %-38s -> %+v\n  %-38s -> %+v\n"+
						"An operator typing one config two ways must get one meaning.",
						natThenShapes6820[0].name, ref, shape.name, got)
				}
			}
		})
	}
}

// TestNATThenPoolNamedLikeAnActionKeyword_6820 binds the claim on
// applyNATThenActions that "`pool` consumes exactly ONE value token, so a pool
// legitimately NAMED off/interface/pool is read as a NAME and stays one
// action". That claim is what keeps the accumulating scan from turning a VALID
// config into a false rejection, and nothing bound it (#6820 round 6, B4 M3).
//
// RED on revert: deleting the value-token consumption (`i++`) in
// applyNATThenActions makes `then source-nat pool off` re-read "off" as the
// `off` EXEMPTION, so the rule carries two actions and a legitimate config is
// REJECTED at commit.
func TestNATThenPoolNamedLikeAnActionKeyword_6820(t *testing.T) {
	for _, poolName := range []string{"off", "interface", "pool"} {
		for _, shape := range natThenShapes6820 {
			t.Run(poolName+"/"+shape.name, func(t *testing.T) {
				// Build with the stock prologue, then rename the pool: the
				// shape builders all reference pool "P".
				tree := shape.build(t, false, []string{"pool " + poolName})
				renameSourcePool6820(t, tree, poolName)
				then := tolerantNATThenTree6820(t, "pool named "+poolName, tree, false)
				if then.PoolName != poolName {
					t.Errorf("`source-nat pool %s` resolved PoolName=%q, want %q (%+v) — "+
						"the pool NAME was re-read as an action keyword",
						poolName, then.PoolName, poolName, then)
				}
				if then.Off || then.Interface {
					t.Errorf("`source-nat pool %s` lowered a second action (%+v); a pool NAME "+
						"that happens to spell an action keyword is still just a name",
						poolName, then)
				}
				if _, err := CompileConfig(tree); err != nil {
					t.Errorf("STRICT commit REJECTED the VALID single-action rule "+
						"`source-nat pool %s`: %v", poolName, err)
				}
			})
		}
	}
}

// renameSourcePool6820 renames the `security nat source pool P` definition to
// name, so a rule referencing a pool called "off"/"interface"/"pool" resolves.
func renameSourcePool6820(t *testing.T, tree *ConfigTree, name string) {
	t.Helper()
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatal("no security node")
	}
	nat := sec.FindChild("nat")
	if nat == nil {
		t.Fatal("no nat node")
	}
	src := nat.FindChild("source")
	if src == nil {
		t.Fatal("no source node")
	}
	for _, c := range src.Children {
		if c.Name() == "pool" && len(c.Keys) >= 2 {
			c.Keys[1] = name
			return
		}
	}
	t.Fatal("no source pool node to rename")
}

// TestNATThenUnrecognizedLeadingTokenIsNotSkipped_6820 binds the
// stop-at-unrecognized rule in applyNATThenActions, which is what keeps the
// accumulating scan from changing an ACCEPTING decision (#6820 round 6, B3/B4).
//
// Round 5's scan SKIPPED a token it did not recognize and read the next one, so
// `then { destination-nat interface pool PD; }` — rejected before the PR, since
// destination NAT has no interface translation mode — began COMMITTING as a
// pool translation. That is a silent reinterpretation of an operator action,
// introduced by the PR whose purpose is to stop exactly that. The same hole
// applied to arbitrary unrecognized tokens on BOTH kinds, so both are bound.
//
// RED on revert: deleting the `allowInterface` guard makes the `interface`-only
// destination rows ACCEPT (and lower Interface on a DNAT rule, which has no
// such mode); deleting the `default: break scan` arm makes every
// leading-garbage row ACCEPT as a pool translation.
func TestNATThenUnrecognizedLeadingTokenIsNotSkipped_6820(t *testing.T) {
	cases := []struct {
		name   string
		dest   bool
		then   string
		reason string
	}{
		{"DNAT interface alone", true, "then { destination-nat interface; }",
			"destination NAT has no interface translation mode"},
		{"DNAT interface then pool", true, "then { destination-nat interface pool PD; }",
			"skipping `interface` would silently publish a pool translation"},
		{"DNAT garbage then pool", true, "then { destination-nat frobnicate pool PD; }",
			"skipping an unknown token would silently publish a pool translation"},
		{"SNAT garbage then pool", false, "then { source-nat frobnicate pool P; }",
			"skipping an unknown token would silently publish a pool translation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := natHierTree6820(t, tc.dest, tc.then)
			if _, err := CompileConfig(tree); err == nil {
				t.Errorf("STRICT commit ACCEPTED %q — %s. An accumulating scan must STOP at "+
					"an unrecognized leading token, not skip past it to the next one "+
					"(#6820 round 6, B3)", tc.then, tc.reason)
			}
			then := tolerantNATThenTree6820(t, tc.name, tree, tc.dest)
			if natThenSurvivor6820(then) != "none" {
				t.Errorf("%q resolved to a translation %+v (survivor %q); it must lower NO "+
					"terminal action", tc.then, then, natThenSurvivor6820(then))
			}
			if tc.dest && then.Interface {
				t.Errorf("%q lowered Interface on a DESTINATION-NAT rule (%+v); destination "+
					"NAT has no interface translation mode", tc.then, then)
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
// message carries the pinned runs and none of the listed stale/refutation
// markers. kind is "source" or "destination".
//
// # What this checker does, and what it explicitly does NOT do
//
// It does two things a bare `strings.Contains` on one clause cannot:
//
//   - it pins each kind's mechanism sentence CONCATENATED with the shared claim
//     tail, as ONE contiguous run. A run is what makes an interior deletion
//     visible: dropping "and never looking the pool up, and the dataplane
//     applies the same " from the DNAT text leaves a semantically damaged
//     message that every clause-level pin still accepts (#6820 B4).
//   - it rejects a fixed VOCABULARY of stale-mechanism and refutation markers,
//     matched after normalisation (case, whitespace, hyphen-vs-space), so
//     "packed key order" and "packed-key order" are one token.
//
// It is NOT a polarity oracle, and #6820 round 5 wrongly claimed it was: that
// revision asserted "a message that quotes the claim in order to deny it
// necessarily carries one [refutation marker]". That is false. `The above is
// untrue.` denies the claim and carries none of the markers, and eight more
// rewrites that are FLATLY FALSE about the compiler score zero defects here —
// enumerated and measured in natCardinalityMessageRewrites6820. A keyword list
// cannot express "this message contains no claim that contradicts the message";
// extending the list to cover those nine would pin ten fixtures instead of one
// and leave the tenth-plus-one bypass just as open. So the claim is narrowed to
// what the list delivers: it is a FLOOR over a specific vocabulary.
//
// The property the round-5 text wanted is expressed instead by
// natCardinalitySourceMessage6820 / natCardinalityDestMessage6820: the whole
// operator-facing message, pinned by EQUALITY. Equality has no vocabulary and
// no polarity model — any appended denial, any prepended disclaimer, any
// interior edit is a mismatch. That is the guard
// TestNATCardinalityMessageRewritesAreCaught_6820 puts every rewrite through;
// this checker's remaining job is to say WHICH WAY a drifted message drifted.
//
// The behavioural half of these claims is NOT checked by either — a message is
// not evidence about the code. It is measured by
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
		"actions inside one block. Duplicate containers are NOT rejected, but only " +
		"the brace syntax can author them: repeated `set ... then ...` commands " +
		"MERGE into a single block, so in `set` syntax this rejection is what you get.)"

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

	// Marker scans run on the NORMALISED text so a rewrite cannot slip a marker
	// past on spelling alone — "packed key order" and "packed-key order" are the
	// same token here (#6820 round 6, B2).
	norm := natMessageNormalize6820(msg)

	// The mechanism the compiler stopped using. Both halves are dead since
	// #6820 (child order died at #5628; the packed/chained reads at rounds 5-6).
	for _, stale := range []string{"packed key", "child order"} {
		if strings.Contains(norm, stale) {
			defects = append(defects, "still tells the operator the compiler picks an action "+
				"by "+stale+" order; it records every authored field from the whole `then` "+
				"subtree (applyNATThenActions) and the dataplane resolves them")
		}
	}

	// A FLOOR over a refutation vocabulary — not a polarity gate. See the
	// function comment and natCardinalityMessageRewrites6820: nine rewrites that
	// are false about the compiler score zero here. Equality against the golden
	// message is what actually catches those.
	for _, frame := range natCardinalityRefutationMarkers6820 {
		if strings.Contains(norm, frame) {
			defects = append(defects, "carries the refutation marker "+strconv.Quote(frame)+
				" — the rejection text must ASSERT the mechanism, not quote and deny it")
		}
	}
	return defects
}

// natCardinalityRefutationMarkers6820 is the refutation vocabulary
// natCardinalityMessageDefects6820 scans for, in NORMALISED form (lower-case,
// hyphens as spaces, single-spaced). It is a FLOOR, deliberately not extended
// to cover every measured bypass — see natCardinalityMessageRewrites6820.
var natCardinalityRefutationMarkers6820 = []string{
	"is false", "is not true", "is incorrect", "is wrong",
	"the statement", "contrary to", "does choose", "chooses it",
}

// natMessageNormalize6820 folds the spellings a marker scan must not be fooled
// by: case, hyphen-vs-space, and whitespace runs.
func natMessageNormalize6820(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(strings.ToLower(s), "-", " ")), " ")
}

// twoActionRejectionMessage6820 compiles a rule carrying two mutually-exclusive
// terminal actions and returns the strict rejection text verbatim. The fixture
// names are fixed so the message is fully determined and can be pinned by
// equality.
func twoActionRejectionMessage6820(t *testing.T, dest bool) string {
	t.Helper()
	lines := []string{
		"set security nat source pool P address 203.0.113.5",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set security nat source rule-set RS rule R1 then source-nat off",
	}
	if dest {
		lines = []string{
			"set security nat destination pool PD address 10.0.0.5",
			"set security nat destination rule-set RD from zone untrust",
			"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.1/32",
			"set security nat destination rule-set RD rule R1 then destination-nat pool PD",
			"set security nat destination rule-set RD rule R1 then destination-nat off",
		}
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatalf("CompileConfig ACCEPTED a two-action NAT rule (dest=%v)", dest)
	}
	return err.Error()
}

// The WHOLE operator-facing rejection text, pinned by equality (#6820 round 6,
// B2). Equality is the guard that expresses what a keyword list cannot: it has
// no vocabulary and no polarity model, so an appended denial, a prepended
// disclaimer, a reworded clause and an interior deletion are all just
// mismatches. Editing the message is expected to red these constants — that IS
// the review prompt, on text an operator reads when a commit is refused.
const natCardinalitySourceMessage6820 = "source-nat rule-set \"RS\" rule \"R1\": " +
	"`then` carries 2 mutually-exclusive translation actions (expected exactly one of " +
	"`source-nat interface`, `source-nat pool <p>`, or `source-nat off`); every one of " +
	"them is published to the dataplane, which resolves the rule by a fixed precedence " +
	"— `off` wins over `interface`, and `interface` over `pool`, so all but one action " +
	"is silently discarded, and which one survives is decided by that precedence rather " +
	"than by the order the actions are written inside this block. Configuration order is " +
	"not irrelevant to the rule as a whole: duplicate `then` CONTAINERS are resolved " +
	"FIRST, last-wins per #3850 — the LAST container supplies the actions counted here " +
	"— and the precedence above then resolves among them. (This rejects contradictory " +
	"actions inside one block. Duplicate containers are NOT rejected, but only the brace " +
	"syntax can author them: repeated `set ... then ...` commands MERGE into a single " +
	"block, so in `set` syntax this rejection is what you get.)"

const natCardinalityDestMessage6820 = "destination-nat rule-set \"RD\" rule \"R1\": " +
	"`then` carries 2 mutually-exclusive translation actions (expected exactly one of " +
	"`destination-nat pool <p>` or `destination-nat off`); the compiler resolves `off` " +
	"itself, publishing a pool-less exemption and never looking the pool up, and the " +
	"dataplane applies the same `off`-over-`pool` precedence to any entry that carries " +
	"both, so all but one action is silently discarded, and which one survives is decided " +
	"by that precedence rather than by the order the actions are written inside this " +
	"block. Configuration order is not irrelevant to the rule as a whole: duplicate " +
	"`then` CONTAINERS are resolved FIRST, last-wins per #3850 — the LAST container " +
	"supplies the actions counted here — and the precedence above then resolves among " +
	"them. (This rejects contradictory actions inside one block. Duplicate containers " +
	"are NOT rejected, but only the brace syntax can author them: repeated " +
	"`set ... then ...` commands MERGE into a single block, so in `set` syntax this " +
	"rejection is what you get.)"

// natCardinalityMessageRewrites6820 enumerates rewrites of the REAL rejection
// text that are FALSE about the compiler. Each carries the measured verdict of
// natCardinalityMessageDefects6820's marker vocabulary, so the vocabulary's
// reach is RECORDED rather than claimed.
//
// The `vocabularyCatches: false` rows are the point. Round 5 claimed the
// checker rejects any message that "quotes the claim in order to deny it";
// `The above is untrue.` does exactly that and scores zero. A keyword list
// cannot express the property, and adding these nine phrases to the list would
// pin ten fixtures instead of one — the same defect one turn later. The list
// stays a FLOOR; equality against the golden is what catches every row.
var natCardinalityMessageRewrites6820 = []struct {
	name              string
	rewrite           func(real string) string
	vocabularyCatches bool
	why               string
}{
	{"prepended-negation", func(r string) string {
		return "The statement below is false; configuration order chooses it. " + r
	}, true, "carries three listed markers; the one fixture round 5 tested"},
	{"untrue", func(r string) string { return r + " The above is untrue." },
		false, "denies the claim with a word the list does not carry"},
	{"inaccurate", func(r string) string { return r + " That description is inaccurate." },
		false, "same, different word"},
	{"never-applied", func(r string) string {
		return r + " In practice the precedence above is never applied; the first action written wins."
	}, false, "asserts the pre-#5628 behaviour as current, with no refutation vocabulary"},
	{"order-selects", func(r string) string {
		return r + " In fact, the order the actions appear inside the block selects the survivor."
	}, false, "directly contradicts the pinned run; no marker"},
	{"disregard", func(r string) string { return r + " Disregard the preceding sentence." },
		false, "retracts without denying"},
	{"opposite-plain", func(r string) string {
		return r + " The opposite holds: whichever action you write first is the one kept."
	}, false, "states the inverse in plain words"},
	{"no-longer-current", func(r string) string {
		return "The following no longer describes this release. " + r
	}, false, "a prefix disclaimer, not a denial"},
	{"stale-round4-claim-returns", func(r string) string {
		return r + " Note that the survivor is not chosen by configuration order."
	}, false, "re-adds the exact unqualified sentence #6820 round 4 shipped and round 5 removed as FALSE"},
	{"packed-key-respelled", func(r string) string {
		return r + " The compiler selects an action by packed key order."
	}, true, "the stale-mechanism marker, caught only because the scan now normalises hyphen-vs-space"},
}

// TestNATCardinalityMessageRewritesAreCaught_6820 is the witnessing RED for the
// message guards: without it, "the checker returned no defects" is
// indistinguishable from a checker that cannot fail.
//
// It asserts three things. (1) The REAL text equals its golden and scores zero
// defects — the control, without which every negative below proves nothing.
// (2) EVERY rewrite in natCardinalityMessageRewrites6820 is caught by the
// equality guard. (3) The marker vocabulary's verdict on each rewrite matches
// the recorded `vocabularyCatches` column — so the eight it cannot see stay
// visible in this file rather than being papered over, and any future widening
// of the list has to update the column.
func TestNATCardinalityMessageRewritesAreCaught_6820(t *testing.T) {
	for _, kind := range []struct {
		name   string
		dest   bool
		golden string
	}{
		{"source", false, natCardinalitySourceMessage6820},
		{"destination", true, natCardinalityDestMessage6820},
	} {
		t.Run(kind.name, func(t *testing.T) {
			real := twoActionRejectionMessage6820(t, kind.dest)
			if real != kind.golden {
				t.Fatalf("the %s-NAT rejection text CHANGED. If the edit is intended, update "+
					"the golden — and re-read it as an operator would, because this text is "+
					"the only signal a refused commit gives.\n  got:  %s\n  want: %s",
					kind.name, real, kind.golden)
			}
			if defects := natCardinalityMessageDefects6820(kind.name, real); len(defects) > 0 {
				t.Fatalf("control: the REAL %s rejection text was reported defective, so this "+
					"test's negatives are meaningless: %v", kind.name, defects)
			}
			for _, rw := range natCardinalityMessageRewrites6820 {
				rewritten := rw.rewrite(real)
				if rewritten == kind.golden {
					t.Errorf("%s: rewrite %q left the message IDENTICAL to the golden; the "+
						"rewrite is not exercising anything", kind.name, rw.name)
				}
				caught := len(natCardinalityMessageDefects6820(kind.name, rewritten)) > 0
				if caught != rw.vocabularyCatches {
					t.Errorf("%s: rewrite %q — marker vocabulary caught=%v, recorded %v (%s).\n"+
						"The column records the vocabulary's REACH; it is a floor, not a "+
						"polarity guarantee. Update it if the list changed on purpose.\n  %s",
						kind.name, rw.name, caught, rw.vocabularyCatches, rw.why, rewritten)
				}
			}
		})
	}
}

// TestNATCardinalityMessageInteriorDeletionIsVisible_6820 keeps the #6820 B4
// case explicit: an interior deletion from the DNAT mechanism sentence leaves a
// semantically damaged message that every clause-level pin accepts. Both guards
// must see it — the contiguous-run pin (which is what makes the checker useful
// as a diagnostic) and equality.
func TestNATCardinalityMessageInteriorDeletionIsVisible_6820(t *testing.T) {
	realDNAT := twoActionRejectionMessage6820(t, true)
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
	if damaged == natCardinalityDestMessage6820 {
		t.Errorf("the interior deletion left the message equal to the golden")
	}
}

// TestNATDuplicateThenSetCommandsMergeAndAreRejected_6820 binds the corrected
// closing sentence of the rejection text: duplicate `then` CONTAINERS are not
// rejected, "but only the brace syntax can author them: repeated `set ... then
// ...` commands MERGE into a single block".
//
// The previous wording — "it does not reject duplicate containers" — misleads
// exactly the operator most likely to hit this, because in `set` syntax there
// is no way to author a duplicate container: SetPath merges the repeated
// commands into ONE `then` node, so the two actions land in one block and ARE
// rejected here. Both halves are measured.
func TestNATDuplicateThenSetCommandsMergeAndAreRejected_6820(t *testing.T) {
	// set syntax: two `then source-nat` commands MERGE into one block.
	merged := buildTree(t, []string{
		"set security nat source pool P address 203.0.113.5",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set security nat source rule-set RS rule R1 then source-nat off",
	})
	thenNodes := findNATRuleThenNodes6820(t, merged)
	if len(thenNodes) != 1 {
		t.Fatalf("repeated `set ... then source-nat ...` produced %d `then` containers, want "+
			"1 — the message tells the operator they MERGE", len(thenNodes))
	}
	if _, err := CompileConfig(merged); err == nil {
		t.Error("repeated `set ... then source-nat ...` commands COMMITTED; they merge into " +
			"one block carrying two actions, which this gate must reject")
	} else if !strings.Contains(err.Error(), "mutually-exclusive translation actions") {
		t.Errorf("merged set commands rejected by the wrong gate: %v", err)
	}

	// brace syntax: two containers stay two, and #3850 last-wins keeps them
	// committing.
	braced := natHierTree6820(t, false,
		"then { source-nat { off; } }\n      then { source-nat { pool P; } }")
	if n := len(findNATRuleThenNodes6820(t, braced)); n != 2 {
		t.Fatalf("the brace syntax produced %d `then` containers, want 2", n)
	}
	if _, err := CompileConfig(braced); err != nil {
		t.Errorf("duplicate `then` CONTAINERS must keep committing (#3850 last-wins), and "+
			"the message says so: %v", err)
	}
}

// findNATRuleThenNodes6820 returns the `then` nodes of the first source-NAT
// rule in the tree, so a test can assert how many CONTAINERS a syntax produced.
func findNATRuleThenNodes6820(t *testing.T, tree *ConfigTree) []*Node {
	t.Helper()
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatal("no security node")
	}
	nat := sec.FindChild("nat")
	if nat == nil {
		t.Fatal("no nat node")
	}
	src := nat.FindChild("source")
	if src == nil {
		t.Fatal("no source node")
	}
	for _, rs := range src.Children {
		if rs.Name() != "rule-set" {
			continue
		}
		for _, rule := range rs.Children {
			if rule.Name() != "rule" {
				continue
			}
			return rule.FindChildren("then")
		}
	}
	t.Fatal("no source-NAT rule node")
	return nil
}
