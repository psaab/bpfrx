package config

import (
	"strings"
	"testing"
)

// #2240/#2241: commit-time validation for NPTv6 (RFC 6296) static-NAT rules.
//
// #2240 (fail-closed): the dataplane compiler (compileNPTv6) historically
// logged a warning and `continue`d past a malformed NPTv6 rule, then called
// DeleteStaleNPTv6 over only the VALID subset — so editing one previously-good
// rule into an invalid one tore down its working translation entry with no
// replacement (a fail-OPEN that silently disabled a working translation on a
// typo). The strict commit gate now hard-rejects so the operator sees the
// misconfiguration and the previous forwarding state is preserved.
//
// #2241 (overlap): NPTv6 supports /48 and /64 rules; the runtime resolved a
// match by first-hit insertion order with no LPM, so an overlapping pair
// translated nondeterministically. The strict gate rejects overlaps.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

// nptv6Set builds an NPTv6 static-NAT rule-set with one or more rules. Each
// rule is (name, match, nptv6-prefix). The trust zone is defined to avoid
// undefined-zone warning noise.
func nptv6Set(rules ...[3]string) []string {
	lines := []string{
		"set security zones security-zone trust",
		"set security nat static rule-set rs1 from zone trust",
	}
	for _, r := range rules {
		name, match, prefix := r[0], r[1], r[2]
		lines = append(lines,
			"set security nat static rule-set rs1 rule "+name+" match destination-address "+match,
			"set security nat static rule-set rs1 rule "+name+" then static-nat nptv6-prefix "+prefix,
		)
	}
	return lines
}

// TestNPTv6ValidRulesCompile is the control: a set of valid, non-overlapping
// NPTv6 rules must compile cleanly with no NPTv6 warning.
func TestNPTv6ValidRulesCompile(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, nptv6Set(
		[3]string{"r1", "2001:db8:1::/48", "fd00:1::/48"},
		[3]string{"r2", "2001:db8:2::/48", "fd00:2::/48"},
		[3]string{"r3", "2001:db8:3:4::/64", "fd00:3:4::/64"},
	)))
	if err != nil {
		t.Fatalf("valid non-overlapping NPTv6 rules must compile, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nptv6") {
			t.Fatalf("valid NPTv6 config must not warn, got: %q", w)
		}
	}
}

// TestNPTv6OneBadRulePreservesOthers is the #2240 FAIL-ON-REVERT proof. A
// config with several VALID NPTv6 rules plus ONE malformed rule must be
// REJECTED at commit — pre-fix the malformed rule was silently dropped, the
// commit succeeded, and DeleteStaleNPTv6 tore down the valid rules' previous
// translations. Rejecting the commit preserves the previous forwarding state.
func TestNPTv6OneBadRulePreservesOthers(t *testing.T) {
	tree := buildTree(t, nptv6Set(
		[3]string{"good1", "2001:db8:1::/48", "fd00:1::/48"},
		[3]string{"good2", "2001:db8:2::/48", "fd00:2::/48"},
		[3]string{"typo", "2001:db8:9::/48", "fd00:9::/64"}, // mismatched length
		[3]string{"good3", "2001:db8:3::/48", "fd00:3::/48"},
	))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a config with one malformed NPTv6 rule must be REJECTED at commit (fail-closed); " +
			"pre-fix it silently dropped the rule and DeleteStaleNPTv6 tore down the valid rules' translations")
	}
	msg := err.Error()
	if !strings.Contains(msg, "typo") || !strings.Contains(msg, "prefix lengths must match") {
		t.Fatalf("error must name the offending rule + the mismatch, got: %v", err)
	}
}

func TestNPTv6RejectsUnparseableMatch(t *testing.T) {
	tree := buildTree(t, nptv6Set([3]string{"r1", "not-a-prefix", "fd00:1::/48"}))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("unparseable NPTv6 match prefix must be rejected")
	}
	if !strings.Contains(err.Error(), "match destination-address") ||
		!strings.Contains(err.Error(), "not a valid IPv6 prefix") {
		t.Fatalf("error must name the match slot + reason, got: %v", err)
	}
}

func TestNPTv6RejectsUnparseablePrefix(t *testing.T) {
	tree := buildTree(t, nptv6Set([3]string{"r1", "2001:db8:1::/48", "garbage/48"}))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("unparseable NPTv6 nptv6-prefix must be rejected")
	}
	if !strings.Contains(err.Error(), "nptv6-prefix") ||
		!strings.Contains(err.Error(), "not a valid IPv6 prefix") {
		t.Fatalf("error must name the nptv6-prefix slot + reason, got: %v", err)
	}
}

func TestNPTv6RejectsMismatchedLengths(t *testing.T) {
	tree := buildTree(t, nptv6Set([3]string{"r1", "2001:db8:1::/48", "fd00:1:2::/64"}))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("mismatched NPTv6 prefix lengths must be rejected")
	}
	if !strings.Contains(err.Error(), "prefix lengths must match") {
		t.Fatalf("error must say prefix lengths must match, got: %v", err)
	}
}

func TestNPTv6RejectsUnsupportedLength(t *testing.T) {
	tree := buildTree(t, nptv6Set([3]string{"r1", "2001:db8:1::/56", "fd00:1::/56"}))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("unsupported NPTv6 prefix length /56 must be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported") || !strings.Contains(err.Error(), "/48 and /64") {
		t.Fatalf("error must say the length is unsupported (only /48 and /64), got: %v", err)
	}
}

func TestNPTv6RejectsNonIPv6(t *testing.T) {
	// An IPv4 prefix in the match slot. ParseCIDR accepts it; the family check
	// must reject it as non-IPv6.
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.0/24",
		"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix 192.0.2.0/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("non-IPv6 NPTv6 prefixes must be rejected")
	}
	// /24 trips the unsupported-length gate first (it runs before the family
	// check); either rejection is acceptable — the key invariant is that an
	// IPv4 NPTv6 rule does not silently compile.
	msg := err.Error()
	if !strings.Contains(msg, "nptv6") && !strings.Contains(msg, "must be IPv6") && !strings.Contains(msg, "unsupported") {
		t.Fatalf("error must reject the IPv4 NPTv6 rule, got: %v", err)
	}
}

// TestNPTv6RejectsOverlappingInternal is the #2241 FAIL-ON-REVERT proof for the
// outbound (internal) direction: a broad /48 and a nested /64 with the same
// internal base overlap, so first-match insertion order would shadow the /64.
func TestNPTv6RejectsOverlappingInternal(t *testing.T) {
	tree := buildTree(t, nptv6Set(
		[3]string{"broad", "2001:db8:1::/48", "fd00:1::/48"},
		[3]string{"nested", "2001:db8:ffff:1234::/64", "fd00:1:0:1234::/64"},
	))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("overlapping NPTv6 internal prefixes (/48 nesting /64) must be rejected at commit; " +
			"pre-fix both installed and resolution depended on insertion order")
	}
	msg := err.Error()
	if !strings.Contains(msg, "overlaps") || !strings.Contains(msg, "nested") || !strings.Contains(msg, "broad") {
		t.Fatalf("error must name both overlapping rules, got: %v", err)
	}
}

// TestNPTv6RejectsOverlappingExternal: distinct internal prefixes but the
// external (inbound) prefixes overlap.
func TestNPTv6RejectsOverlappingExternal(t *testing.T) {
	tree := buildTree(t, nptv6Set(
		[3]string{"ext48", "2001:db8:1::/48", "fd00:1::/48"},
		[3]string{"ext64", "2001:db8:1:5678::/64", "fd00:2::/64"},
	))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("overlapping NPTv6 external prefixes must be rejected at commit")
	}
	if !strings.Contains(err.Error(), "match destination-address") ||
		!strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("error must name the inbound/external overlap, got: %v", err)
	}
}

// TestNPTv6RejectsOverlapOrderIndependent: the same overlapping pair must be
// rejected regardless of insertion order (determinism is the point of #2241).
func TestNPTv6RejectsOverlapOrderIndependent(t *testing.T) {
	forward := buildTree(t, nptv6Set(
		[3]string{"broad", "2001:db8:1::/48", "fd00:1::/48"},
		[3]string{"nested", "2001:db8:ffff:1234::/64", "fd00:1:0:1234::/64"},
	))
	reverse := buildTree(t, nptv6Set(
		[3]string{"nested", "2001:db8:ffff:1234::/64", "fd00:1:0:1234::/64"},
		[3]string{"broad", "2001:db8:1::/48", "fd00:1::/48"},
	))
	if _, err := CompileConfig(forward); err == nil {
		t.Fatal("overlap (broad-then-nested) must be rejected")
	}
	if _, err := CompileConfig(reverse); err == nil {
		t.Fatal("overlap (nested-then-broad) must also be rejected — determinism is order-independent")
	}
}

// TestNPTv6IdenticalPrefixesRejected: two rules with the same /48 prefix in a
// direction is the degenerate overlap.
func TestNPTv6IdenticalPrefixesRejected(t *testing.T) {
	tree := buildTree(t, nptv6Set(
		[3]string{"r1", "2001:db8:1::/48", "fd00:1::/48"},
		[3]string{"r2", "2001:db8:9::/48", "fd00:1::/48"}, // same internal prefix
	))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("two NPTv6 rules with the same internal prefix must be rejected (identical-prefix overlap)")
	}
}

// TestNPTv6RejectsCrossRuleSetOverlap: NPTv6 rules in DIFFERENT rule-sets are
// flattened into one first-match list by buildNptv6Snapshots, so an overlap
// across rule-sets is just as order-dependent and must be rejected. The error
// must name BOTH the offending rule-set/rule and the prior rule-set/rule so the
// operator can disambiguate a rule name reused across rule-sets.
func TestNPTv6RejectsCrossRuleSetOverlap(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security nat static rule-set rsA from zone trust",
		"set security nat static rule-set rsA rule shared match destination-address 2001:db8:1::/48",
		"set security nat static rule-set rsA rule shared then static-nat nptv6-prefix fd00:1::/48",
		"set security nat static rule-set rsB from zone trust",
		"set security nat static rule-set rsB rule shared match destination-address 2001:db8:1:1234::/64",
		"set security nat static rule-set rsB rule shared then static-nat nptv6-prefix fd00:1:0:1234::/64",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("overlapping NPTv6 prefixes across rule-sets must be rejected at commit")
	}
	msg := err.Error()
	// Both rule-sets must be named (the rule name "shared" is reused, so the
	// rule-set qualifier is what disambiguates).
	if !strings.Contains(msg, "rsB") || !strings.Contains(msg, "rsA") {
		t.Fatalf("error must name both rule-sets (rsA and rsB), got: %v", err)
	}
	if !strings.Contains(msg, "overlaps rule-set") {
		t.Fatalf("error must qualify the prior rule with its rule-set, got: %v", err)
	}
}

// TestNPTv6LenientLoadAccepts is the #1960 no-brick guarantee: a config
// committed before this gate existed (or peer-synced) carrying a malformed or
// overlapping NPTv6 rule must LOAD under the lenient path with the violation
// downgraded to a warning, never a hard compile failure.
func TestNPTv6LenientLoadAccepts(t *testing.T) {
	cases := [][]string{
		nptv6Set([3]string{"r1", "2001:db8:1::/48", "fd00:1:2::/64"}), // mismatched
		nptv6Set([3]string{"r1", "not-a-prefix", "fd00:1::/48"}),      // unparseable
		nptv6Set([3]string{"r1", "2001:db8:1::/56", "fd00:1::/56"}),   // unsupported len
		nptv6Set( // overlap
			[3]string{"broad", "2001:db8:1::/48", "fd00:1::/48"},
			[3]string{"nested", "2001:db8:ffff:1234::/64", "fd00:1:0:1234::/64"},
		),
	}
	for i, lines := range cases {
		if _, err := CompileConfig(buildTree(t, lines)); err == nil {
			t.Fatalf("case %d: strict CompileConfig must reject", i)
		}
		cfg, err := CompileConfigLenient(buildTree(t, lines))
		if err != nil {
			t.Fatalf("case %d: CompileConfigLenient must NOT fail (brick-on-restart), got: %v", i, err)
		}
		if !hasWarningContaining(cfg.Warnings, "nptv6") {
			t.Fatalf("case %d: lenient load must emit an nptv6 warning, warnings=%v", i, cfg.Warnings)
		}
		// The lenient warning must carry the "rejected by dataplane, previous
		// state kept" impact note so the operator knows it is inert, not applied.
		if !hasWarningContaining(cfg.Warnings, "previous state kept") {
			t.Fatalf("case %d: lenient warning must state the dataplane keeps the previous state, warnings=%v", i, cfg.Warnings)
		}
	}
}

// TestNPTv6LenientValidNoWarning: a valid NPTv6 config must NOT produce an
// nptv6 warning under lenient compile (no false positive).
func TestNPTv6LenientValidNoWarning(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, nptv6Set(
		[3]string{"r1", "2001:db8:1::/48", "fd00:1::/48"},
		[3]string{"r2", "2001:db8:2::/48", "fd00:2::/48"},
	)))
	if err != nil {
		t.Fatalf("valid NPTv6 lenient compile: %v", err)
	}
	if hasWarningContaining(cfg.Warnings, "nptv6") {
		t.Fatalf("valid NPTv6 config must not warn under lenient, got: %v", cfg.Warnings)
	}
}
