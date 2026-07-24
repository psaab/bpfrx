package config

import (
	"strings"
	"testing"
)

// #6455 closes two limitations the pre-expansion duplicate-name gate family
// (validateDuplicateNamedBlockAST #5180, validateDuplicateNATRuleNamesAST #5649,
// validateDuplicateNATRuleSetNamesAST #6454) shared:
//
//   1. GROUP-AUTHORED duplicates: the gates scanned only the top-level stanzas,
//      so a duplicate authored ENTIRELY inside an applied group body (no inline
//      peer to deep-merge it) survived apply-groups expansion as two rows with no
//      gate to catch it. The fix scans each group body as a SEPARATE namespace.
//   2. QUOTED-EMPTY names: the gates `continue` on an empty name, so a
//      quoted-empty name (`rule ""`, `rule-set ""`, `group ""`, `interface ""`)
//      was neither rejected as a duplicate nor rejected as empty. The fix records
//      it as an emptyName6455 defect (strict rejects, lenient warns).
//
// All tests drive the PUBLIC compile entry points (CompileConfig /
// CompileConfigLenient), not the private validators, so both the reject behavior
// AND the no-false-positive guarantees (apply-groups deep-merge, cross-group
// coalescing, #3096 bracket-list expansion) are bound through the REAL commit
// path — a future change to the compile-path expansion that reintroduced a
// false positive would turn an accept sub-test RED.
//
// RED-on-revert: the group-body scan (scanNamespaces) and the empty-name
// recording are the fix. Neutralizing either (scan only tree.Children, or restore
// the `continue` on an empty name) makes CompileConfig return nil for the reject
// fixtures below — the strict sub-tests then go RED on a clean assertion, while
// the no-false-positive accepts stay green (they never depended on the new
// behavior).

func parseHier6455(t *testing.T, input string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

// TestDup6455GroupAuthoredDuplicateRejected is the Finding 1 RED-on-revert proof:
// a duplicate authored entirely inside an applied group body — for each of the
// family's four axes (NAT rule #5649, NAT rule-set #6454, interface #5180, screen
// ids-option #5180) — is hard-rejected at strict commit, and the diagnostic names
// the enclosing group so the operator can find it.
func TestDup6455GroupAuthoredDuplicateRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want []string // substrings the error must contain
	}{
		{
			// Two `rule R` in one rule-set inside group G — caught by the #5649
			// rule-NAME gate (runs before the #6454 rule-SET gate).
			name: "nat rule (#5649)",
			cfg: `groups {
    G {
        security {
            nat {
                source {
                    rule-set RS {
                        rule R { then { source-nat { interface; } } }
                        rule R { then { source-nat { off; } } }
                    }
                }
            }
        }
    }
}
apply-groups G;`,
			want: []string{"NAT source rule", `"R"`, `rule-set "RS"`, `in group "G"`, "5649"},
		},
		{
			// Two `rule-set RS` with DISJOINT rule names inside group G — the
			// #5649 rule-name gate does not fire (R1 != R2), so control reaches the
			// #6454 rule-SET gate.
			name: "nat rule-set (#6454)",
			cfg: `groups {
    G {
        security {
            nat {
                source {
                    rule-set RS { rule R1 { then { source-nat { interface; } } } }
                    rule-set RS { rule R2 { then { source-nat { off; } } } }
                }
            }
        }
    }
}
apply-groups G;`,
			want: []string{"NAT source rule-set", `"RS"`, `in group "G"`, "6454"},
		},
		{
			name: "interface (#5180)",
			cfg: `groups {
    G {
        interfaces {
            ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
            ge-0/0/0 { unit 1 { family inet { address 10.0.1.1/24; } } }
        }
    }
}
apply-groups G;`,
			want: []string{"interface", `"ge-0/0/0"`, `in group "G"`, "5180"},
		},
		{
			name: "screen ids-option (#5180)",
			cfg: `groups {
    G {
        security {
            screen {
                ids-option P { icmp { ping-death; } }
                ids-option P { tcp { syn-fin; } }
            }
        }
    }
}
apply-groups G;`,
			want: []string{"screen ids-option", `"P"`, `in group "G"`, "5180"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHier6455(t, tc.cfg))
			if err == nil {
				t.Fatalf("CompileConfig must reject a group-authored duplicate (%s)", tc.name)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error should mention %q, got: %v", want, err)
				}
			}
		})
	}
}

// TestDup6455QuotedEmptyNameRejected is the Finding 2 RED-on-revert proof: a
// single quoted-empty name for each of the family's containers is hard-rejected
// at strict commit as an authoring error (an empty name is not a valid
// operational identity), regardless of duplication. Each error carries the #6455
// tag and the container kind.
func TestDup6455QuotedEmptyNameRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		kind string
	}{
		{
			name: "nat rule-set",
			cfg:  `security { nat { source { rule-set "" { rule R1 { then { source-nat { interface; } } } } } } }`,
			kind: "NAT source rule-set",
		},
		{
			name: "nat rule",
			cfg:  `security { nat { source { rule-set RS { rule "" { then { source-nat { interface; } } } } } } }`,
			kind: "NAT source rule",
		},
		{
			name: "group",
			cfg:  `groups { "" { system { host-name foo; } } }`,
			kind: "group",
		},
		{
			name: "interface",
			cfg:  `interfaces { "" { unit 0 { family inet { address 10.0.0.1/24; } } } }`,
			kind: "interface",
		},
		{
			name: "screen ids-option",
			cfg:  `security { screen { ids-option "" { icmp { ping-death; } } } }`,
			kind: "screen ids-option",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHier6455(t, tc.cfg))
			if err == nil {
				t.Fatalf("CompileConfig must reject an empty %s name", tc.kind)
			}
			for _, want := range []string{"empty", tc.kind, "6455"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("empty-%s error should mention %q, got: %v", tc.name, want, err)
				}
			}
		})
	}
}

// TestDup6455LenientWarns proves the tolerant path (Load / peer-sync, #1960)
// downgrades BOTH new reject classes to warnings so an already-persisted or
// peer-synced config still boots through. A group-authored duplicate and a
// quoted-empty name each surface a #6455-family warning rather than a hard error.
func TestDup6455LenientWarns(t *testing.T) {
	t.Run("group-authored duplicate warns", func(t *testing.T) {
		const cfg = `groups {
    G {
        security {
            nat {
                source {
                    rule-set RS {
                        rule R { then { source-nat { interface; } } }
                        rule R { then { source-nat { off; } } }
                    }
                }
            }
        }
    }
}
apply-groups G;`
		if _, err := CompileConfig(parseHier6455(t, cfg)); err == nil {
			t.Fatal("strict CompileConfig must reject the group-authored duplicate")
		}
		lenientCfg, err := CompileConfigLenient(parseHier6455(t, cfg))
		if err != nil {
			t.Fatalf("CompileConfigLenient must not hard-fail on a group-authored duplicate, got: %v", err)
		}
		if !hasWarning6455(lenientCfg.Warnings, `in group "G"`, `"R"`, "5649") {
			t.Fatalf("lenient compile must warn naming the group-authored duplicate, warnings: %v", lenientCfg.Warnings)
		}
	})

	t.Run("quoted-empty name warns", func(t *testing.T) {
		const cfg = `security { nat { source { rule-set "" { rule R1 { then { source-nat { interface; } } } } } } }`
		if _, err := CompileConfig(parseHier6455(t, cfg)); err == nil {
			t.Fatal("strict CompileConfig must reject the empty rule-set name")
		}
		lenientCfg, err := CompileConfigLenient(parseHier6455(t, cfg))
		if err != nil {
			t.Fatalf("CompileConfigLenient must not hard-fail on an empty name, got: %v", err)
		}
		if !hasWarning6455(lenientCfg.Warnings, "empty", "NAT source rule-set", "6455") {
			t.Fatalf("lenient compile must warn on the empty rule-set name, warnings: %v", lenientCfg.Warnings)
		}
	})
}

// TestDup6455NoFalsePositive is the critical guard: the group-body scan must NOT
// flag a LEGITIMATE apply-groups expansion. All four fixtures commit cleanly.
func TestDup6455NoFalsePositive(t *testing.T) {
	// apply-groups deep-merge: an inline `rule-set RS { rule R1 }` and a
	// group-authored `rule-set RS { rule R2 }` are DIFFERENT namespaces that
	// mergeNodes coalesces into ONE rule-set carrying BOTH rules — not a
	// duplicate. Neither namespace has an internal duplicate, so the gate must
	// accept, and the merged rule-set must carry R1 AND R2 (proof the merge, not
	// a drop, happened).
	t.Run("apply-groups deep-merge (NAT rule-set)", func(t *testing.T) {
		cfg, err := CompileConfig(parseHier6455(t, `security {
    nat {
        source {
            rule-set RS { rule R1 { then { source-nat { interface; } } } }
        }
    }
}
groups {
    G {
        security {
            nat {
                source {
                    rule-set RS { rule R2 { then { source-nat { off; } } } }
                }
            }
        }
    }
}
apply-groups G;`))
		if err != nil {
			t.Fatalf("an apply-groups deep-merge into a same-named inline rule-set must commit, got: %v", err)
		}
		rules := 0
		count := 0
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				count++
				rules = len(rs.Rules)
			}
		}
		if count != 1 || rules != 2 {
			t.Fatalf("deep-merge must yield 1 source rule-set RS carrying 2 rules, got count=%d rules=%d", count, rules)
		}
	})

	// apply-groups deep-merge (interface): an inline ge-0/0/0 and a
	// group-authored ge-0/0/0 merge into one interface — not a duplicate.
	t.Run("apply-groups deep-merge (interface)", func(t *testing.T) {
		_, err := CompileConfig(parseHier6455(t, `interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
groups {
    G {
        interfaces {
            ge-0/0/0 { unit 1 { family inet { address 10.0.1.1/24; } } }
        }
    }
}
apply-groups G;`))
		if err != nil {
			t.Fatalf("an apply-groups deep-merge into a same-named inline interface must commit, got: %v", err)
		}
	})

	// Two DIFFERENT groups authoring the SAME rule-set/rule (identical action)
	// both applied to the top context: mergeNodes coalesces them into ONE row, so
	// there is no surviving duplicate. Each group body is internally clean, so the
	// per-namespace scan must not flag it.
	t.Run("cross-group same name coalesces", func(t *testing.T) {
		cfg, err := CompileConfig(parseHier6455(t, `groups {
    G1 { security { nat { source { rule-set RS { rule R { then { source-nat { off; } } } } } } } }
    G2 { security { nat { source { rule-set RS { rule R { then { source-nat { off; } } } } } } } }
}
apply-groups [ G1 G2 ];`))
		if err != nil {
			t.Fatalf("two groups authoring the same rule must coalesce and commit, got: %v", err)
		}
		count := 0
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("cross-group same rule-set must coalesce to 1 source rule-set RS, got %d", count)
		}
	})

	// #3096 inside a group body: ONE authored `rule-set RS` with a bracket list of
	// from-zones Cartesian-expands into TWO same-named NATRuleSet objects at
	// COMPILE time — but that is one AST rule-set instance in the group body, not a
	// duplicate. The gate scans the pre-compile AST, so the expansion is not
	// flagged, and the two expanded entries (from trust + from dmz) are present.
	t.Run("group-authored #3096 bracket-list expansion", func(t *testing.T) {
		cfg, err := CompileConfig(parseHier6455(t, `groups {
    G {
        security {
            nat {
                source {
                    rule-set RS {
                        from zone [ trust dmz ];
                        to zone untrust;
                        rule R1 { then { source-nat { interface; } } }
                    }
                }
            }
        }
    }
}
apply-groups G;`))
		if err != nil {
			t.Fatalf("a single group-authored bracket-list-scoped rule-set must commit (one AST instance), got: %v", err)
		}
		fromZones := map[string]bool{}
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				fromZones[rs.FromZone] = true
			}
		}
		if !fromZones["trust"] || !fromZones["dmz"] {
			t.Fatalf("expanded rule-sets must cover from-zones {trust, dmz}, got: %v", fromZones)
		}
	})
}

// hasWarning6455 reports whether some warning contains ALL of the given
// substrings.
func hasWarning6455(warnings []string, subs ...string) bool {
	for _, w := range warnings {
		all := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
