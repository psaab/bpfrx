package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const natBase8430 = `
system { host-name p; }
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
`

// snatWithMatch builds a scoped source-NAT rule whose match body is under test.
func snatWithMatch8430(matchBody string) string {
	return natBase8430 + `security { nat { source {
		pool p1 { address 172.16.0.5/32; }
		rule-set rs { from zone trust; to zone trust; rule r1 {
			match { ` + matchBody + ` }
			then { source-nat pool p1; } } } } } }`
}

func snatSourceAddrs8430(t *testing.T, text string) ([]string, error) {
	t.Helper()
	cfg, err := CheckText(text, 0)
	if err != nil {
		return nil, err
	}
	for _, rs := range cfg.Security.NAT.Source {
		for _, r := range rs.Rules {
			return r.Match.SourceAddresses, nil
		}
	}
	t.Fatal("config committed but produced no source-NAT rule")
	return nil, nil
}

// #8430. THE POINT OF THIS FILE. The dataplane reads an empty match set as
// UNCONSTRAINED (`if !constrained { return true }` /
// `source_constrained = !snap.source_addresses.is_empty()`), so a rule that
// constrains nothing translates EVERY source rather than none.
//
// This asserts the WIDENING, not the parse: it does not check "the typo is
// rejected", it checks that no accepted config leaves the rule with the empty
// source set the dataplane reads as match-everything. That distinction is the
// issue's own: a rejection cell passes for a fix that closes the typo route and
// leaves the valueless route open.
func TestNATRuleNeverCommitsWithAnUnconstrainedMatch_8430(t *testing.T) {
	routes := []struct{ name, match string }{
		{"typo'd leaf", "soruce-address 10.0.61.0/24;"},
		{"unknown leaf protocol", "protocol tcp;"},
		{"unknown leaf source-port", "source-port 1024;"},
		{"garbage leaf", "flooby wibble;"},
		{"valueless source-address", "source-address;"},
		{"valueless destination-address", "destination-address;"},
		{"empty match block", ""},
	}
	for _, r := range routes {
		got, err := snatSourceAddrs8430(t, snatWithMatch8430(r.match))
		if err != nil {
			continue // rejected: the rule never exists, so it cannot widen
		}
		if len(got) == 0 {
			t.Errorf("%s: COMMITTED with SourceAddresses=[] — the dataplane reads an "+
				"empty match set as UNCONSTRAINED, so this rule translates EVERY source",
				r.name)
		}
	}
}

// POSITIVE CONTROL for the cell above. Without it, a gate that rejected every
// NAT config would pass — the loop only inspects configs that COMMIT.
func TestNATValidMatchesStillCommitAndAreConstrained_8430(t *testing.T) {
	cases := map[string]string{
		"single prefix":     "source-address 10.0.61.0/24;",
		"bracket list":      "source-address [ 10.0.61.0/24 10.0.62.0/24 ];",
		"mixed shape #6693": "source-address 10.0.61.0/24 { 10.0.62.0/24; }",
		"explicit catchall": "source-address 0.0.0.0/0;",
		"destination only":  "destination-address 10.0.70.0/24;",
		"port only":         "destination-port 443;",
	}
	for name, match := range cases {
		got, err := snatSourceAddrs8430(t, snatWithMatch8430(match))
		if err != nil {
			t.Errorf("%s REJECTED: %v", name, strings.SplitN(err.Error(), "\n", 2)[0])
			continue
		}
		_ = got // the destination/port cases legitimately have no source addrs
	}
	// And the mixed shape must keep BOTH values, not just the first — that is
	// the #6693 property the closed-world flip nearly destroyed.
	got, err := snatSourceAddrs8430(t, snatWithMatch8430("source-address 10.0.61.0/24 { 10.0.62.0/24; }"))
	if err != nil {
		t.Fatalf("mixed shape rejected: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("mixed shape kept %v, want both values — closed-world must not "+
			"descend into a multi-value leaf's VALUE children", got)
	}
}

// A SCOPE-ONLY rule — no `match` container at all — is legitimate and common:
// the rule-set's own from/to is the constraint. The first version of this gate
// rejected it and nine existing cells caught that. This pins the distinction so
// a later tightening cannot quietly re-break it.
func TestNATScopeOnlyRuleStillCommits_8430(t *testing.T) {
	text := natBase8430 + `security { nat { source {
		pool p1 { address 172.16.0.5/32; }
		rule-set rs { from zone trust; to zone trust; rule r1 {
			then { source-nat pool p1; } } } } } }`
	if _, err := CheckText(text, 0); err != nil {
		t.Fatalf("a scope-only NAT rule (no `match` at all) was REJECTED: %v", err)
	}
	// CONTROL: the SAME rule with an EMPTY match container must be rejected.
	// Without this the cell above passes against a gate that does nothing.
	if _, err := CheckText(snatWithMatch8430(""), 0); err == nil {
		t.Error("`match { }` committed — the distinction between an omitted match and " +
			"an authored-but-empty one is not being made")
	}
}

// #1960 no-brick: a config persisted before this gate must still LOAD.
func TestNATUnconstrainedMatchNoBrickOnTolerantPath_8430(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, s := range []string{
		"set security nat source pool p1 address 172.16.0.5/32",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone trust",
		"set security nat source rule-set rs rule r1 then source-nat pool p1",
	} {
		p, err := config.ParseSetCommand(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", s, err)
		}
	}
	if _, err := config.CompileConfigLenient(tree); err != nil {
		t.Fatalf("tolerant compile refused a NAT config: %v", err)
	}
}

// M1 FOUND THIS. Un-flipping the closed-world subtrees was a SURVIVING mutation
// against every cell above, because the unconstrained gate catches a lone typo
// too: the match is authored and empty either way. It does NOT catch a typo
// BESIDE a valid leaf — the rule is then constrained by the valid leaf, the
// gate passes, and the typo'd leaf is silently dropped, so the rule matches
// only PART of what was authored.
//
// That is the same widening one notch narrower, and it is the only shape that
// distinguishes the two mechanisms. A test population built from "the leaf
// alone" could not see it.
func TestNATTypoBesideAValidLeafIsRejected_8430(t *testing.T) {
	cases := map[string]string{
		"typo beside a valid source-address": "source-address 10.0.61.0/24; soruce-address 10.0.99.0/24;",
		"unknown leaf beside a valid one":    "source-address 10.0.61.0/24; source-port 1024;",
		"garbage beside a valid one":         "source-address 10.0.61.0/24; flooby wibble;",
	}
	for name, match := range cases {
		got, err := snatSourceAddrs8430(t, snatWithMatch8430(match))
		if err != nil {
			continue // rejected, which is the point
		}
		t.Errorf("%s: COMMITTED with SourceAddresses=%v — the unrecognised leaf was "+
			"silently dropped, so the rule matches only part of what was authored",
			name, got)
	}
	// CONTROL: two VALID leaves together must still commit, and keep both.
	got, err := snatSourceAddrs8430(t,
		snatWithMatch8430("source-address 10.0.61.0/24; destination-address 10.0.70.0/24;"))
	if err != nil {
		t.Fatalf("two valid match leaves were rejected: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("valid two-leaf match kept SourceAddresses=%v, want exactly the one "+
			"authored source prefix", got)
	}
}
