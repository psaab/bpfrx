package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6848 (#4228 Gap 7 residual): `show class-of-service rewrite-rule`.
//
// The load-bearing property is NOT that the rules render — it is that the
// output distinguishes an ENFORCED rewrite rule from an inert one. Three of the
// four rewrite-rule families (ieee-802.1, inet-precedence, exp) commit clean and
// have no runtime effect; only dscp is applied on egress. Rendering them
// identically would reproduce, inside the command built to expose the problem,
// exactly the silence that made the problem worth fixing.

// testCoSRewriteRuleConfig builds all four rewrite-rule families. The two
// modeled families carry entry lists; inet-precedence and exp are recorded as
// NAMES only, which is how the compiler stores them (#4316) — see
// TestFormatCoSRewriteRulesNameOnlyFamiliesAreProducible for the proof that
// this shape is what the real compiler emits, not a shape invented here.
func testCoSRewriteRuleConfig() *config.Config {
	cfg := testCoSConfig()
	cfg.ClassOfService.DSCPRewriteRules = map[string]*config.CoSDSCPRewriteRule{
		"rw-dscp": {
			Name: "rw-dscp",
			Entries: []*config.CoSDSCPRewriteRuleEntry{
				// Expedited-forwarding: DSCP 46 = 101110b.
				{ForwardingClass: "bandwidth-10mb", LossPriority: "low", DSCPValue: 46},
				// No explicit loss-priority -> renders the Junos "low" default.
				{ForwardingClass: "best-effort", DSCPValue: 0},
			},
		},
	}
	cfg.ClassOfService.IEEE8021RewriteRules = map[string]*config.CoSIEEE8021RewriteRule{
		"rw-pcp": {
			Name: "rw-pcp",
			Entries: []*config.CoSIEEE8021RewriteRuleEntry{
				{ForwardingClass: "bandwidth-10mb", LossPriority: "high", PCPValue: 5},
			},
		},
	}
	cfg.ClassOfService.INetPrecedenceRewriteRules = []string{"rw-prec"}
	cfg.ClassOfService.EXPRewriteRules = []string{"rw-exp"}
	return cfg
}

// TestFormatCoSRewriteRulesRendersAllFourFamilies pins that no family is
// silently dropped — including the two stored as names only, which have no
// entries to iterate and would be the easy ones to omit.
func TestFormatCoSRewriteRulesRendersAllFourFamilies(t *testing.T) {
	out := FormatCoSRewriteRules(testCoSRewriteRuleConfig(), "", "")
	for _, want := range []string{
		"Rewrite rule: rw-dscp, Code point type: dscp",
		"Rewrite rule: rw-pcp, Code point type: ieee-802.1",
		"Rewrite rule: rw-prec, Code point type: inet-precedence",
		"Rewrite rule: rw-exp, Code point type: exp",
		// dscp code points, rendered as binary like the classifier view.
		"101110",
		"000000",
		// The 3-bit PCP code point.
		"101",
		// Loss-priority default fills in for the unset entry.
		"best-effort",
		"low",
		"high",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

// TestFormatCoSRewriteRulesMarksInertTypes is the #6848 point of the command.
//
// FAIL-ON-REVERT: make cosRewriteRuleEnforced return true unconditionally (or
// drop the Enforced column) and the three inert assertions go RED. Make it
// return false for dscp and the enforced assertion goes RED — so the test binds
// the mapping in BOTH directions rather than just "some marker is present".
func TestFormatCoSRewriteRulesMarksInertTypes(t *testing.T) {
	out := FormatCoSRewriteRules(testCoSRewriteRuleConfig(), "", "")

	// dscp IS applied on egress: it must NOT be marked inert.
	dscpLine := ruleHeaderLine(t, out, "rw-dscp")
	if !strings.Contains(dscpLine, "Enforced: yes") {
		t.Errorf("dscp rewrite rule must be reported as enforced; got header:\n%s", dscpLine)
	}

	// The other three commit clean and do nothing. Each must say so on its own
	// header line — an operator reading one rule must not have to notice the
	// absence of a marker on another.
	for _, name := range []string{"rw-pcp", "rw-prec", "rw-exp"} {
		line := ruleHeaderLine(t, out, name)
		if !strings.Contains(line, "Enforced: no") {
			t.Errorf("rule %q is accepted-but-inert and must be marked NOT enforced; got header:\n%s",
				name, line)
		}
		if !strings.Contains(line, "dataplane rewrites dscp only") {
			t.Errorf("rule %q inert marker must say WHAT the operator loses, not just "+
				"that a flag is off; got header:\n%s", name, line)
		}
	}
}

// ruleHeaderLine returns the single "Rewrite rule: <name>, ..." line for name.
// Asserting against the whole output would let a marker on ANY rule satisfy a
// per-rule claim.
func ruleHeaderLine(t *testing.T, out, name string) string {
	t.Helper()
	prefix := "Rewrite rule: " + name + ","
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("no header line for rewrite rule %q in output:\n%s", name, out)
	return ""
}

// TestFormatCoSRewriteRulesNameOnlyFamiliesRenderNoTable pins that a family
// with no modeled code points renders an explicit explanation rather than an
// empty column header — an empty table reads as "configured with nothing in
// it", which is a different and wrong claim.
func TestFormatCoSRewriteRulesNameOnlyFamiliesRenderNoTable(t *testing.T) {
	out := FormatCoSRewriteRules(testCoSRewriteRuleConfig(), "rw-prec", "")
	if !strings.Contains(out, "Code points not modeled") {
		t.Errorf("name-only family must explain that no code points are modeled:\n%s", out)
	}
	if strings.Contains(out, "Forwarding class") {
		t.Errorf("name-only family must not render an empty code-point table:\n%s", out)
	}
}

func TestFormatCoSRewriteRulesFilters(t *testing.T) {
	cfg := testCoSRewriteRuleConfig()

	// Every type filter selects its own family and excludes the others.
	for _, tc := range []struct {
		typeFilter string
		want       string
		exclude    []string
	}{
		{"dscp", "rw-dscp", []string{"rw-pcp", "rw-prec", "rw-exp"}},
		{"ieee-802.1", "rw-pcp", []string{"rw-dscp", "rw-prec", "rw-exp"}},
		{"inet-precedence", "rw-prec", []string{"rw-dscp", "rw-pcp", "rw-exp"}},
		{"exp", "rw-exp", []string{"rw-dscp", "rw-pcp", "rw-prec"}},
	} {
		out := FormatCoSRewriteRules(cfg, "", tc.typeFilter)
		if !strings.Contains(out, tc.want) {
			t.Errorf("type=%s did not select %s:\n%s", tc.typeFilter, tc.want, out)
		}
		for _, ex := range tc.exclude {
			if strings.Contains(out, ex) {
				t.Errorf("type=%s leaked %s:\n%s", tc.typeFilter, ex, out)
			}
		}
	}

	// Name filter selects one rule.
	out := FormatCoSRewriteRules(cfg, "rw-pcp", "")
	if !strings.Contains(out, "rw-pcp") || strings.Contains(out, "rw-dscp") {
		t.Errorf("name=rw-pcp filter wrong:\n%s", out)
	}

	// No match reports the filter message rather than the "none configured"
	// message — the two states are different and must not be conflated.
	out = FormatCoSRewriteRules(cfg, "nope", "")
	if !strings.Contains(out, "No class-of-service rewrite-rule matches") {
		t.Errorf("expected no-match message, got:\n%s", out)
	}
}

func TestFormatCoSRewriteRulesEmptyConfig(t *testing.T) {
	if out := FormatCoSRewriteRules(nil, "", ""); !strings.Contains(out, "No class-of-service rewrite-rules configured") {
		t.Errorf("nil config: %q", out)
	}
	cfg := testCoSConfig() // has ClassOfService but no rewrite rules
	if out := FormatCoSRewriteRules(cfg, "", ""); !strings.Contains(out, "No class-of-service rewrite-rules configured") {
		t.Errorf("no rules configured: %q", out)
	}
}
