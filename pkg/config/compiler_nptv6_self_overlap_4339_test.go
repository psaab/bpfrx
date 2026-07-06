package config

import (
	"strings"
	"testing"
)

// #4339: a static-NAT rule-set with a SINGLE NPTv6 rule was rejected as
// overlapping ITSELF — "rule map-v6-neutral overlaps rule-set NPTv6-INBOUND rule
// map-v6-neutral" — whenever the rule-set carried MORE THAN ONE from-scope
// (`from zone A; from zone B`, or several interfaces). compileNATStatic
// scope-expands one logical rule into one StaticNATRuleSet entry PER from-scope,
// all sharing the rule-set name AND the rule name; validateNPTv6Strict's seen
// lists span every rule-set, so the second scope-expansion's prefixes matched
// the first's exactly and the rule was flagged as overlapping itself. This
// blocked ANY NPTv6 inbound mapping bound to more than one zone/interface.
//
// The fix skips the same (rule-set, rule) identity in the overlap check — a rule
// is never compared against itself — while still detecting a GENUINE overlap
// between DISTINCT rules.
//
// FAIL-ON-REVERT: remove the sameRule skip in validateNPTv6Strict and
// TestNPTv6SingleRuleMultiScopeCommits_4339 goes RED (self-overlap reject).

// nptv6MultiScopeSet builds a single-rule NPTv6 rule-set with TWO from-scopes.
func nptv6MultiScopeSet(rule, match, prefix string) []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat static rule-set NPTv6-INBOUND from zone trust",
		"set security nat static rule-set NPTv6-INBOUND from zone untrust",
		"set security nat static rule-set NPTv6-INBOUND rule " + rule + " match destination-address " + match,
		"set security nat static rule-set NPTv6-INBOUND rule " + rule + " then static-nat nptv6-prefix " + prefix,
	}
}

func TestNPTv6SingleRuleMultiScopeCommits_4339(t *testing.T) {
	tree := buildTree(t, nptv6MultiScopeSet("map-v6-neutral", "2602:fd41:70::/48", "2001:559:8585::/48"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a single NPTv6 rule bound to two from-scopes must COMMIT — it cannot overlap "+
			"itself (#4339), got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "overlaps rule-set") {
			t.Fatalf("no self-overlap warning may be emitted, got: %q", w)
		}
	}
}

// A GENUINE overlap between two DISTINCT rules must STILL be rejected — the fix
// only skips self-comparison, it does not disable the overlap check.
func TestNPTv6GenuineOverlapStillRejected_4339(t *testing.T) {
	// Two distinct rules whose external (match) prefixes overlap: a /48 and a
	// nested /64 under it. First-match resolution would be order-dependent.
	lines := []string{
		"set security zones security-zone trust",
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 rule broad match destination-address 2001:db8:1::/48",
		"set security nat static rule-set rs1 rule broad then static-nat nptv6-prefix fd00:1::/48",
		"set security nat static rule-set rs1 rule narrow match destination-address 2001:db8:1:2::/64",
		"set security nat static rule-set rs1 rule narrow then static-nat nptv6-prefix fd00:2::/64",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("two DISTINCT NPTv6 rules with overlapping external prefixes must be rejected (#2241/#4339)")
	}
	if !strings.Contains(err.Error(), "overlaps rule-set") {
		t.Fatalf("error must report the genuine overlap, got: %v", err)
	}
}

// The genuine-overlap check must still fire even when BOTH rules are themselves
// multi-scope — i.e. the self-skip must not accidentally suppress a real overlap
// hidden among the scope-expanded duplicates.
func TestNPTv6GenuineOverlapMultiScopeStillRejected_4339(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule a match destination-address 2001:db8:9::/48",
		"set security nat static rule-set rs1 rule a then static-nat nptv6-prefix fd00:9::/48",
		"set security nat static rule-set rs1 rule b match destination-address 2001:db8:9::/48",
		"set security nat static rule-set rs1 rule b then static-nat nptv6-prefix fd00:8::/48",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("two DISTINCT multi-scope NPTv6 rules sharing an external prefix must be rejected (#4339)")
	}
	if !strings.Contains(err.Error(), "overlaps rule-set") {
		t.Fatalf("error must report the genuine overlap, got: %v", err)
	}
}
