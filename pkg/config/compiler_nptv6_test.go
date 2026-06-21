package config

import (
	"strings"
	"testing"
)

// #2240: commit-time validation for NPTv6 (RFC 6296) static-NAT rules.
//
// The dataplane compiler (compileNPTv6) historically logged a warning and
// `continue`d past a malformed NPTv6 rule, then called DeleteStaleNPTv6 over
// only the VALID subset — so editing one previously-good rule into an invalid
// one tore down its working translation entry with no replacement (a fail-OPEN
// that silently disabled a working translation on a typo). The strict commit
// gate now hard-rejects so the operator sees the misconfiguration and the
// previous forwarding state is preserved.
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

// TestNPTv6LenientLoadAccepts is the #1960 no-brick guarantee: a config
// committed before this gate existed (or peer-synced) carrying a malformed
// NPTv6 rule must LOAD under the lenient path with the violation downgraded to
// a warning, never a hard compile failure.
func TestNPTv6LenientLoadAccepts(t *testing.T) {
	cases := [][]string{
		nptv6Set([3]string{"r1", "2001:db8:1::/48", "fd00:1:2::/64"}), // mismatched
		nptv6Set([3]string{"r1", "not-a-prefix", "fd00:1::/48"}),      // unparseable
		nptv6Set([3]string{"r1", "2001:db8:1::/56", "fd00:1::/56"}),   // unsupported len
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
