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
