package config

import (
	"strings"
	"testing"
)

// This file closes the #6479 FINAL hostile-review finding: the MULTI-BLOCK
// (sibling-target) silent-accept. A single `then {}` block may carry several
// `static-nat` sibling targets (the hierarchical `then { static-nat {…}
// static-nat {…} }` shape). Junos merges those siblings into one action, so a
// `mapped-port` on ANY sibling is part of that action. Before this fix the child
// loop in compileNATStatic ASSIGNED the mapped-port state per sibling target, so
// a LATER clean sibling's (0,"",false) reading OVERWROTE an earlier sibling's
// malformed/presence stamp — reopening the C179-038 silent-accept for the
// multi-block shape, in BOTH the nptv6 and the non-nptv6 branches:
//
//   then {
//       static-nat { nptv6-prefix 2001:db8:1::/64 { mapped-port notaport; } }
//       static-nat { prefix 2001:db8:2::/64; }   // clears MappedPortPresent
//   }
//
// compiled clean (MappedPortPresent ended false → validateNPTv6Strict never
// fired). The fix folds each sibling through mergeMappedPortState so presence
// OR-accumulates and a malformed operand latches fail-closed regardless of a
// later clean sibling, in either target order and mixed with prefix-name.
//
// The invariants are the same two the shapes file pins:
//
//   INVARIANT A (security, absolute): NO multi-block authoring shape may SILENTLY
//     ACCEPT a present-but-malformed mapped-port. Every malformed sibling fails
//     closed (strict error / lenient warning) with MappedPort==0.
//   INVARIANT B (no regression): a VALID mapped-port on one sibling is NOT
//     silently cleared by a clean sibling, and among valid siblings last-wins.
//
// The sibling shapes below are authored hierarchically (buildHier): the flat-set
// `set` form of the same lines collapses onto ONE static-nat node whose children
// staticNATMappedPortForNode already folds (covered by the shapes-matrix file);
// the multi-static-nat-sibling AST only arises from a hierarchical `then` block.

// hierRuleV6 wraps a nptv6-matching IPv6 rule body (external match /64) around
// the given `then {}` inner text.
func hierRuleV6(thenInner string) string {
	return `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 2001:db8:9::/64; }
                    then {
` + thenInner + `
                    }
                }
            }
        }
    }
}`
}

// hierRuleV4AB wraps an IPv4 host-match rule body (NO match destination-port, so
// a malformed mapped-port is the only defect) with a global address-book entry
// MP_TARGET for the prefix-name shapes.
func hierRuleV4AB(thenInner string) string {
	return `security {
    address-book { global { address MP_TARGET 10.0.0.9/32; } }
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.1/32; }
                    then {
` + thenInner + `
                    }
                }
            }
        }
    }
}`
}

// TestStaticNATMappedPortMultiBlockNPTv6Sibling6479 pins the nptv6 multi-block
// sibling shapes: a malformed (or even valid) nptv6 mapped-port carried by one
// sibling must reject on PRESENCE regardless of a clean sibling target in either
// order, and mixed with a prefix-name target. This is the exact silent-accept the
// fix closes (the clean sibling used to clear MappedPortPresent).
func TestStaticNATMappedPortMultiBlockNPTv6Sibling6479(t *testing.T) {
	cases := []struct {
		name  string
		inner string
	}{
		{
			// nptv6 MALFORMED first, clean matching-length prefix second — the
			// prefix sibling used to clear the stamp AND leave a matching-length
			// Then so no length error masked the drop. The pure silent-accept.
			name: "nptv6-malformed-then-prefix",
			inner: `                        static-nat { nptv6-prefix 2001:db8:1::/64 { mapped-port notaport; } }
                        static-nat { prefix 2001:db8:2::/64; }`,
		},
		{
			// nptv6 MALFORMED first, clean prefix-NAME second (472/478 path).
			name: "nptv6-malformed-then-prefix-name",
			inner: `                        static-nat { nptv6-prefix 2001:db8:1::/64 { mapped-port 70000; } }
                        static-nat { prefix-name MP6; }`,
		},
		{
			// Clean prefix first, nptv6 MALFORMED second (opposite order).
			name: "prefix-then-nptv6-malformed",
			inner: `                        static-nat { prefix 2001:db8:2::/64; }
                        static-nat { nptv6-prefix 2001:db8:1::/64 { mapped-port notaport; } }`,
		},
		{
			// A VALID nptv6 mapped-port is still meaningless (RFC 6296) — reject on
			// presence even though a clean prefix sibling follows.
			name: "nptv6-valid-then-prefix",
			inner: `                        static-nat { nptv6-prefix 2001:db8:1::/64 { mapped-port 8080; } }
                        static-nat { prefix 2001:db8:2::/64; }`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertNPTv6MappedPortReject(t, func() *ConfigTree {
				cfg := c.inner
				// The prefix-name case needs a global address-book /64 entry named
				// MP6 whose prefix matches the external match length.
				body := `security {
    address-book { global { address MP6 2001:db8:2::/64; } }
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 2001:db8:9::/64; }
                    then {
` + cfg + `
                    }
                }
            }
        }
    }
}`
				return buildHier(t, body)
			})
		})
	}
}

// TestStaticNATMappedPortMultiBlockPrefixSibling6479 pins the NON-nptv6 multi-
// block sibling shapes: a malformed mapped-port on one prefix/prefix-name sibling
// must fail closed (naming the token) even with NO `match destination-port` and a
// clean sibling target following — the non-nptv6 analogue the fix must not leave
// open.
func TestStaticNATMappedPortMultiBlockPrefixSibling6479(t *testing.T) {
	cases := []struct {
		name  string
		inner string
	}{
		{
			name: "prefix-malformed-then-clean-prefix",
			inner: `                        static-nat { prefix 10.0.0.5/32 { mapped-port notaport; } }
                        static-nat { prefix 10.0.0.6/32; }`,
		},
		{
			name: "clean-prefix-then-prefix-malformed",
			inner: `                        static-nat { prefix 10.0.0.6/32; }
                        static-nat { prefix 10.0.0.5/32 { mapped-port notaport; } }`,
		},
		{
			name: "prefix-malformed-then-clean-prefix-name",
			inner: `                        static-nat { prefix 10.0.0.5/32 { mapped-port notaport; } }
                        static-nat { prefix-name MP_TARGET; }`,
		},
		{
			name: "prefix-name-malformed-then-clean-prefix",
			inner: `                        static-nat { prefix-name MP_TARGET { mapped-port notaport; } }
                        static-nat { prefix 10.0.0.6/32; }`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertMappedPortReject(t, func() *ConfigTree {
				return buildHier(t, hierRuleV4AB(c.inner))
			}, `"notaport"`)
		})
	}
}

// TestStaticNATMappedPortMultiBlockAccept6479 is the INVARIANT B guard: a clean
// sibling target must NOT silently clear a VALID mapped-port set by another
// sibling, and among valid siblings the LAST valid port wins. (Before the fix the
// per-sibling overwrite dropped the valid port to a plain 1:1.)
func TestStaticNATMappedPortMultiBlockAccept6479(t *testing.T) {
	// A valid mapped-port on the first sibling survives a clean second sibling.
	t.Run("valid-then-clean-sibling-keeps-port", func(t *testing.T) {
		tree := buildHier(t, `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.1/32; destination-port 8080; }
                    then {
                        static-nat { prefix 10.0.0.5/32 { mapped-port 9090; } }
                        static-nat { prefix 10.0.0.5/32; }
                    }
                }
            }
        }
    }
}`)
		assertMappedPortAccept(t, tree, 9090)
	})

	// Two valid siblings: last-valid-wins (9090), matching combineMappedPort-
	// Operands' duplicate-stanza last-wins across sibling targets.
	t.Run("two-valid-siblings-last-wins", func(t *testing.T) {
		tree := buildHier(t, `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.1/32; destination-port 8080; }
                    then {
                        static-nat { prefix 10.0.0.5/32 { mapped-port 8081; } }
                        static-nat { prefix 10.0.0.5/32 { mapped-port 9090; } }
                    }
                }
            }
        }
    }
}`)
		assertMappedPortAccept(t, tree, 9090)
	})
}

// TestStaticNATMappedPortMultiThenBlockBoundary6479 documents the boundary with
// #3850: SEPARATE `then {}` blocks are last-then-block-wins (a superseded whole
// block is dead config, not part of the effective action), so a malformed
// mapped-port in a superseded first `then` block does not gate the clean final
// block. This is DISTINCT from the sibling-target case above (siblings within one
// `then` are a merged live action and DO accumulate). Pinned so a future change
// to the per-then-block reset is a conscious decision, not an accident.
func TestStaticNATMappedPortMultiThenBlockBoundary6479(t *testing.T) {
	// Two separate then blocks: first carries a malformed nptv6 mapped-port, the
	// second is a clean prefix target. Last-then-block-wins → the effective rule
	// is the clean prefix; the superseded nptv6 block (and its mapped-port) is
	// dead config. Compiles clean.
	tree := buildHier(t, `security {
    zones { security-zone untrust; }
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.1/32; }
                    then { static-nat { nptv6-prefix 2001:db8:1::/64 { mapped-port notaport; } } }
                    then { static-nat { prefix 10.0.0.6/32; } }
                }
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("last-then-block-wins: clean final then block must compile, got %v", err)
	}
	r := cfg.Security.NAT.Static[0].Rules[0]
	if r.IsNPTv6 || r.Then != "10.0.0.6/32" || r.MappedPortPresent || r.MappedPort != 0 {
		t.Fatalf("effective rule must be the clean final then block (prefix 10.0.0.6/32, no mapped-port), got IsNPTv6=%v Then=%q present=%v port=%d",
			r.IsNPTv6, r.Then, r.MappedPortPresent, r.MappedPort)
	}
	// Sanity: the token must not leak into a warning either (it is dead config).
	if strings.Contains(strings.Join(cfg.Warnings, "\n"), "notaport") {
		t.Fatalf("superseded then-block token must not surface, got warnings %v", cfg.Warnings)
	}
}
