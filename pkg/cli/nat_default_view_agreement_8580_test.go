package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/natshow"
)

// #8580: the DEFAULT `show security nat source` view — the one an operator
// reaches by typing the shortest command — rendered a disarmed pool and a
// disarmed rule identically to armed ones, and computed the rule's action and
// source match from its own copy of the switch.
//
// The annotation gap is measured against its siblings rather than asserted: the
// summary view says so, the rule views say so, the detail view says so through
// `SourceNATPoolReportablePorts`' reason, and the DESTINATION side says so in
// all five of its views. This one did not.
//
// The action and match are compared against `pkg/natshow` rather than against a
// literal, per #8258's predicate: a literal encodes which surface is trusted,
// and the defect was that the surfaces disagreed.

func natDefaultViewCfg(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set security address-book global address trusted 10.0.0.0/8",
		// A pool with NO members: SourceNATPoolUnusableReason -> empty_pool, so
		// the builder refuses it and every view must say so.
		"set security nat source pool p-empty port range 1024 2048",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r-off match source-address-name trusted",
		"set security nat source rule-set rs1 rule r-off then source-nat off",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	// Lenient: an empty pool is exactly what the strict gate refuses, and the
	// point of this view is what it shows for a config that reached it anyway.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick (#1960): %v", err)
	}
	return cfg
}

func TestNATDefaultViewAnnotatesAndAgrees_8580(t *testing.T) {
	cfg := natDefaultViewCfg(t)

	// PREMISE on the fixture, before the view is consulted: the pool really is
	// disarmed and the rule really carries the two shapes under test. Without
	// this the assertions below could pass against a fixture that produces
	// nothing to annotate.
	pool := cfg.Security.NAT.SourcePools["p-empty"]
	if pool == nil {
		t.Fatal("PREMISE: pool p-empty must compile")
	}
	if reason := sourceNATPoolNotInstalled(pool); reason == "" {
		t.Fatal("PREMISE: pool p-empty must be DISARMED, or there is nothing to annotate")
	}
	var offRule *config.NATRule
	for _, rs := range cfg.Security.NAT.Source {
		for _, r := range rs.Rules {
			if r.Name == "r-off" {
				offRule = r
			}
		}
	}
	if offRule == nil {
		t.Fatal("PREMISE: rule r-off must compile")
	}
	wantAction := natshow.SourceRuleAction(offRule)
	wantSrc := natshow.RuleMatchSource(offRule)
	if wantAction != "off" || wantSrc != "trusted" {
		t.Fatalf("PREMISE: the fixture must carry `then source-nat off` and an "+
			"address-book name; natshow renders action=%q src=%q", wantAction, wantSrc)
	}

	c := &CLI{}
	out := captureStdout(t, func() {
		if err := c.showNATSource(cfg, nil); err != nil {
			t.Fatalf("showNATSource: %v", err)
		}
	})

	if !strings.Contains(out, "NOT INSTALLED") {
		t.Fatalf("#8580: the default view rendered a DISARMED pool and rule with no "+
			"annotation, so they read as armed. Every sibling view says so.\n%s", out)
	}
	if !strings.Contains(out, "-> "+wantAction) {
		t.Fatalf("#8580: the default view must render the action pkg/natshow renders (%q). "+
			"Its private copy defaulted to \"interface\", naming a no-NAT EXEMPTION as its "+
			"opposite.\n%s", wantAction, out)
	}
	if !strings.Contains(out, "Match source-address: "+wantSrc) {
		t.Fatalf("#8580: the default view must render the source match pkg/natshow renders "+
			"(%q). Its private copy read only the singular CIDR field, which is EMPTY for an "+
			"address-book-scoped rule.\n%s", wantSrc, out)
	}
}
