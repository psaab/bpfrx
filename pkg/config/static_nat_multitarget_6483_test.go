package config

import (
	"strings"
	"testing"
)

// #6483: a Junos static-NAT rule maps to EXACTLY ONE translation target — one of
// `prefix <ip>` | `prefix-name <name>` | `nptv6-prefix <p6>` | `inet`. A rule
// authoring two or more targets is invalid Junos, but compileNATStatic used to
// ACCEPT it: the child loop honors the FIRST target by a fixed priority
// (nptv6-prefix > prefix-name > prefix > inet) and drops the rest into the shared
// Then field (a later target overwrites an earlier one), so the rule compiled to
// one arbitrary target with no operator feedback. validateStaticNATSingleTarget-
// Strict now rejects a rule whose winning `then {}` block declares >1 target.
//
// PARENT-RED: neutralize the gate — guard `rule.ThenTargetCount > 1` to a
// constant false in validateStaticNATSingleTargetStrict (keep it compiling) — and
// every TestStaticNATMultiTarget6483_Reject* case goes clean-assertion RED
// (strict CompileConfig returns nil for a rule that must reject). The
// accept/residual cases stay green, proving the gate does not over-reject.

// mtBuildHier parses a full hierarchical config (its own prologue), optionally
// splicing extra flat-set lines (e.g. an address-book entry) on top.
func mtBuildHier(t *testing.T, hier string, extra ...string) *ConfigTree {
	t.Helper()
	tree := buildHier(t, hier)
	for _, line := range extra {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// assertMultiTargetReject compiles the tree strict (must hard-reject naming the
// multi-target problem) and lenient (must NOT hard-error but must warn — the
// #1960 no-brick contract).
func assertMultiTargetReject(t *testing.T, build func() *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(build())
	if err == nil {
		t.Fatalf("strict CompileConfig must reject a multi-target static-nat rule")
	}
	if !strings.Contains(err.Error(), "translation targets") ||
		!strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("strict error must name the multi-target problem, got: %v", err)
	}
	cfg, errL := CompileConfigLenient(build())
	if errL != nil {
		t.Fatalf("lenient compile must not hard-error (#1960 no-brick), got %v", errL)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "translation target") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("lenient path must warn about translation-target cardinality, got %v", cfg.Warnings)
	}
}

// assertSingleTargetAccept compiles strict, requires success, and asserts the
// rule resolved to EXACTLY ONE declared target (guards against over-rejection).
func assertSingleTargetAccept(t *testing.T, tree *ConfigTree) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig must accept a well-formed single-target rule, got %v", err)
	}
	if len(cfg.Security.NAT.Static) == 0 || len(cfg.Security.NAT.Static[0].Rules) == 0 {
		t.Fatalf("expected a static NAT rule, got %#v", cfg.Security.NAT.Static)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].ThenTargetCount; got != 1 {
		t.Fatalf("ThenTargetCount = %d, want 1 (single well-formed target)", got)
	}
}

// --- multi-target REJECT (each authoring shape) -----------------------------

func TestStaticNATMultiTarget6483_RejectPrefixPlusPrefixName(t *testing.T) {
	// Flat-set: two target lines collapse onto ONE static-nat node with two target
	// children (prefix + prefix-name). On master this compiled clean, honoring
	// prefix-name and silently dropping the prefix.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security address-book global address POOL 10.0.0.9/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name POOL")
	})
}

func TestStaticNATMultiTarget6483_RejectInetPlusPrefix(t *testing.T) {
	// Flat-set inet sibling + prefix sibling. On master the prefix (higher
	// priority) won Then, so the rule installed as a plain prefix rule and even
	// EVADED the #5859 inet reject — a doubly-silent accept.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat inet",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32")
	})
}

func TestStaticNATMultiTarget6483_RejectTwoPrefix(t *testing.T) {
	// Two mutually-exclusive prefix targets — last-wins on master, silently
	// dropping the first.
	assertMultiTargetReject(t, func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.2/32")
	})
}

func TestStaticNATMultiTarget6483_RejectHierTwoStaticNATBlocks(t *testing.T) {
	// Hierarchical `then { static-nat {…} static-nat {…} }` — one target per
	// sibling static-nat node.
	assertMultiTargetReject(t, func() *ConfigTree {
		return mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { prefix 10.0.0.1/32; } static-nat { prefix-name POOL; } } } } } } }`,
			"set security address-book global address POOL 10.0.0.9/32")
	})
}

// --- #6479 residual: a malformed mapped-port on a DROPPED target ------------

func TestStaticNATMultiTarget6483_RejectClosesMappedPortResidual(t *testing.T) {
	// Hierarchical: an `inet` sibling carrying a malformed `mapped-port notaport`
	// FIRST, then a `prefix` sibling. On master this SILENT-ACCEPTS: the inet
	// branch never runs the mapped-port fold, so the bad token is dropped, and the
	// later prefix sibling overwrites Then to a valid host — the rule compiles
	// clean with the malformed port lost. That is the #6479/C179-038 residual.
	// Rejecting the multi-target rule (inet + prefix = 2 targets) closes it: the
	// rule never compiles, so the dropped-target mapped-port cannot slip.
	build := func() *ConfigTree {
		return mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { inet mapped-port notaport; } static-nat { prefix 10.0.0.1/32; } } } } } } }`)
	}
	assertMultiTargetReject(t, build)
}

// --- single-target ACCEPT (each of the four, collapsed + hierarchical) ------

func TestStaticNATMultiTarget6483_AcceptSingleTargets(t *testing.T) {
	t.Run("prefix_flat", func(t *testing.T) {
		assertSingleTargetAccept(t, buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32"))
	})
	t.Run("prefix_flat_with_mapped_port", func(t *testing.T) {
		// A modifier (mapped-port) on the single target must NOT read as a 2nd
		// target — it is the canonical single-target-plus-modifier form.
		assertSingleTargetAccept(t, buildFlat(t,
			"set security nat static rule-set rs1 rule r1 match destination-port 80",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32 mapped-port 8080"))
	})
	t.Run("prefix_hier", func(t *testing.T) {
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { prefix 10.0.0.1/32; } } } } } } }`))
	})
	t.Run("prefix_name_flat", func(t *testing.T) {
		assertSingleTargetAccept(t, buildFlat(t,
			"set security address-book global address POOL 10.0.0.9/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix-name POOL"))
	})
	t.Run("prefix_name_hier", func(t *testing.T) {
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 203.0.113.1/32; }
						then { static-nat { prefix-name POOL; } } } } } } }`,
			"set security address-book global address POOL 10.0.0.9/32"))
	})
	t.Run("nptv6_prefix_flat", func(t *testing.T) {
		// nptv6 needs a v6 match of EQUAL prefix length (else the nptv6-length
		// gate, not the cardinality gate, would fire). Build without natBaseZone.
		tree := &ConfigTree{}
		for _, line := range []string{
			"set security zones security-zone untrust",
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 2001:db8:2::/48",
		} {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		assertSingleTargetAccept(t, tree)
	})
	t.Run("nptv6_prefix_hier", func(t *testing.T) {
		assertSingleTargetAccept(t, mtBuildHier(t,
			`security { zones { security-zone untrust; }
				nat { static { rule-set rs1 { from { zone untrust; }
					rule r1 { match { destination-address 2001:db8:1::/48; }
						then { static-nat { nptv6-prefix 2001:db8:2::/48; } } } } } } }`))
	})
	t.Run("prefix_with_routing_instance", func(t *testing.T) {
		// A trailing target routing-instance (#4292) is a modifier, not a 2nd
		// target.
		assertSingleTargetAccept(t, buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32 routing-instance FOO"))
	})
}

// TestStaticNATMultiTarget6483_SingleInetNotFlaggedMulti proves a lone `inet`
// target is NOT falsely rejected as multi-target: it counts ONE target and is
// rejected (if at all) only by the #5859 inet gate, never the cardinality gate.
func TestStaticNATMultiTarget6483_SingleInetNotFlaggedMulti(t *testing.T) {
	build := func() *ConfigTree {
		return buildFlat(t,
			"set security nat static rule-set rs1 rule r1 then static-nat inet")
	}
	// The lone inet counts exactly one target (lenient compile keeps the rule).
	cfg, errL := CompileConfigLenient(build())
	if errL != nil {
		t.Fatalf("lenient compile must not hard-error, got %v", errL)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].ThenTargetCount; got != 1 {
		t.Fatalf("lone inet ThenTargetCount = %d, want 1", got)
	}
	// Strict rejection is the #5859 inet reject, NOT the multi-target reject.
	_, err := CompileConfig(build())
	if err == nil {
		t.Fatalf("lone inet must still be rejected by the #5859 inet gate")
	}
	if strings.Contains(err.Error(), "translation targets") {
		t.Fatalf("lone inet must NOT be flagged multi-target, got: %v", err)
	}
	if !strings.Contains(err.Error(), "inet") {
		t.Fatalf("expected the #5859 inet reject, got: %v", err)
	}
}
