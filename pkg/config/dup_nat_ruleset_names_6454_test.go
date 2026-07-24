package config

import (
	"strings"
	"testing"
)

// #6454 (C181-M18 sibling): two rule-SETS with the SAME name within one NAT
// type (source/destination/static/nat64) BOTH survive — compileNATSource /
// compileNATDestination / compileNATStatic / compileNAT64 each APPEND the
// rule-set (they never merge by name), so both compile as separate first-match
// tables sharing one operational identity (the rule-set name). For the counted
// natTypes that identity is also the shared natType/ruleSet/rule counter
// namespace, so per-rule telemetry merges and show/counter surfaces cannot
// disambiguate; a counter-less nat64 rule-set still shares its show-surface
// name identity. validateDuplicateNATRuleSetNamesAST rejects this at strict
// commit and warns on the tolerant load path (#1960).
//
// This is the rule-SET axis one level above the #5649 rule-NAME gate. The
// fixtures use DISJOINT rule names inside each duplicate rule-set so the #5649
// gate (which runs first, keyed by (natType, ruleSet, rule)) does NOT fire —
// control reaches THIS gate.
//
// RED-on-revert: neutralize the gate so it never records a duplicate (guard the
// `seen[key]` detection with `&& false`, keeping the fmt/sort references and
// therefore the imports live — a clean assertion RED, not a build break). The
// strict sub-tests then no longer see a #6454 error and go RED.

// parseHier6454 parses a hierarchical (brace-delimited) config via NewParser —
// the correct tool for a hierarchical duplicate block. Flat `set` MERGES a
// repeated rule-set onto one node (see the equivalence sub-test), so only the
// hierarchical shape can express the duplicate this gate targets.
func parseHier6454(t *testing.T, input string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func setTree6454(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
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
	return tree
}

// TestDuplicateNATRuleSetNameRejected is the #6454 RED-on-revert proof: strict
// commit (CompileConfig, the stable public entrypoint) hard-rejects a duplicate
// rule-SET name in each of source / destination / static / nat64. The gate runs
// pre-expansion and returns before zone/policy validation, so a NAT-only fixture
// reaches exactly this error.
func TestDuplicateNATRuleSetNameRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
	}{
		{
			name: "source",
			cfg: `security {
    nat {
        source {
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
            }
            rule-set RS {
                from zone dmz;
                to zone untrust;
                rule R2 {
                    match { source-address 10.0.1.0/24; }
                    then { source-nat { off; } }
                }
            }
        }
    }
}`,
		},
		{
			name: "destination",
			cfg: `security {
    nat {
        destination {
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 203.0.113.10/32; }
                    then { destination-nat off; }
                }
            }
            rule-set RS {
                from zone untrust;
                rule R2 {
                    match { destination-address 203.0.113.11/32; }
                    then { destination-nat off; }
                }
            }
        }
    }
}`,
		},
		{
			name: "static",
			cfg: `security {
    nat {
        static {
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 203.0.113.10/32; }
                    then { static-nat { prefix 10.0.0.10/32; } }
                }
            }
            rule-set RS {
                from zone untrust;
                rule R2 {
                    match { destination-address 203.0.113.11/32; }
                    then { static-nat { prefix 10.0.0.11/32; } }
                }
            }
        }
    }
}`,
		},
		{
			// nat64 rule-sets carry prefix / source-pool and NO `rule` nodes, so
			// the #5649 rule-name gate correctly excludes them — but a duplicate
			// nat64 rule-set NAME is its own fail-open this gate closes. Both
			// prefixes are valid /96 so the ONLY defect is the duplicate name.
			name: "nat64",
			cfg: `security {
    nat {
        nat64 {
            rule-set RS { prefix 64:ff9b::/96; }
            rule-set RS { prefix 64:ff9b::/96; }
        }
    }
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier6454(t, tc.cfg)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig must reject a duplicate NAT %s rule-set name", tc.name)
			}
			// Bind the exact natType phrase, not just the bare word, plus the
			// rule-set name and the issue tag.
			for _, want := range []string{"NAT " + tc.name + " rule-set", "RS", "6454"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error should mention %q, got: %v", want, err)
				}
			}
		})
	}
}

// TestDuplicateNATRuleSetNameNat64NotCounter binds the type-agnostic-diagnostic
// contract for the counter-less nat64 case: a nat64 rule-set has no per-rule
// counter (NATCounterKey is only assigned for source/destination/static rules),
// so the #6454 diagnostic must NOT claim a per-rule counter for it. Mirrors the
// #5649 NPTv6 counter-less fold.
func TestDuplicateNATRuleSetNameNat64NotCounter(t *testing.T) {
	tree := parseHier6454(t, `security {
    nat {
        nat64 {
            rule-set RS { prefix 64:ff9b::/96; }
            rule-set RS { prefix 64:ff9b::/96; }
        }
    }
}`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig must reject a duplicate nat64 rule-set name")
	}
	msg := err.Error()
	for _, want := range []string{"NAT nat64 rule-set", "RS", "6454"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("nat64 duplicate error should mention %q, got: %v", want, err)
		}
	}
	// The type-agnostic diagnostic must not claim a per-rule counter (false for
	// a counter-less nat64 rule-set).
	if strings.Contains(msg, "counter") {
		t.Fatalf("nat64 duplicate diagnostic must NOT claim a per-rule counter, got: %v", err)
	}
}

// TestDuplicateNATRuleSetNameLenientWarns proves the tolerant path (Load /
// peer-sync) downgrades the reject to a warning so an already-persisted or
// peer-synced config still boots through (#1960 class).
func TestDuplicateNATRuleSetNameLenientWarns(t *testing.T) {
	tree := parseHier6454(t, `security {
    nat {
        source {
            rule-set RS {
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
            }
            rule-set RS {
                rule R2 {
                    match { source-address 10.0.1.0/24; }
                    then { source-nat { off; } }
                }
            }
        }
    }
}`)

	// Strict: hard error.
	if _, err := validateDuplicateNATRuleSetNamesAST(tree, false); err == nil {
		t.Fatal("strict validator must reject the duplicate rule-set name")
	}

	// Lenient: no error, one warning that names the rule-set and references #6454.
	warnings, err := validateDuplicateNATRuleSetNamesAST(tree, true)
	if err != nil {
		t.Fatalf("lenient validator must not error, got: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("lenient validator must emit exactly one warning, got %d: %v", len(warnings), warnings)
	}
	for _, want := range []string{"RS", "6454"} {
		if !strings.Contains(warnings[0], want) {
			t.Fatalf("warning should mention %q, got: %v", want, warnings[0])
		}
	}
}

// TestDuplicateNATRuleSetNameNoFalsePositive guards the gate's scope: distinct
// rule-set names, the SAME rule-set name in two DIFFERENT nat types (a distinct
// natType namespace — the counter key is prefixed by natType), a single
// rule-set carrying a bracket list of from-scopes that Cartesian-expands into
// multiple same-named NATRuleSet objects downstream (#3096, one AST instance —
// NOT a duplicate), and the flat-set form (which MERGES a repeated rule-set onto
// one node) must all pass strict.
func TestDuplicateNATRuleSetNameNoFalsePositive(t *testing.T) {
	t.Run("distinct rule-set names in one nat type", func(t *testing.T) {
		tree := parseHier6454(t, `security {
    nat {
        source {
            rule-set RS_A { rule R1 { then { source-nat { interface; } } } }
            rule-set RS_B { rule R1 { then { source-nat { off; } } } }
        }
    }
}`)
		if _, err := validateDuplicateNATRuleSetNamesAST(tree, false); err != nil {
			t.Fatalf("distinct rule-set names must pass, got: %v", err)
		}
	})

	t.Run("same rule-set name in two different nat types", func(t *testing.T) {
		// source RS keys "source\x00RS", static RS keys "static\x00RS": distinct
		// namespaces (the counter key is natType-prefixed), so this is legitimate.
		tree := parseHier6454(t, `security {
    nat {
        source {
            rule-set RS { rule R1 { then { source-nat { interface; } } } }
        }
        static {
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 203.0.113.10/32; }
                    then { static-nat { prefix 10.0.0.10/32; } }
                }
            }
        }
    }
}`)
		if _, err := validateDuplicateNATRuleSetNamesAST(tree, false); err != nil {
			t.Fatalf("same rule-set name across different nat types is a distinct identity and must pass, got: %v", err)
		}
	})

	t.Run("bracket-list from-scope expands one authored rule-set (#3096)", func(t *testing.T) {
		// ONE authored `rule-set RS` with a bracket list of from-zones
		// Cartesian-expands into TWO same-named NATRuleSet objects downstream in
		// compileNATSource — but that is one AST rule-set instance, not a
		// duplicate. Dedup at the compiled level would false-positive here; the
		// gate dedups at the AST instance level, so this passes.
		tree := parseHier6454(t, `security {
    nat {
        source {
            rule-set RS {
                from zone [ trust dmz ];
                to zone untrust;
                rule R1 { then { source-nat { interface; } } }
            }
        }
    }
}`)
		if _, err := validateDuplicateNATRuleSetNamesAST(tree, false); err != nil {
			t.Fatalf("a single bracket-list-scoped rule-set must pass (one AST instance), got: %v", err)
		}
	})

	t.Run("flat-set repeated rule-set merges (dual-AST equivalence)", func(t *testing.T) {
		tree := setTree6454(t, []string{
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS rule R1 then source-nat interface",
			"set security nat source rule-set RS rule R2 then source-nat off",
		})
		if _, err := validateDuplicateNATRuleSetNamesAST(tree, false); err != nil {
			t.Fatalf("flat-set repeated rule-set statements merge onto one node and must pass, got: %v", err)
		}
	})
}
