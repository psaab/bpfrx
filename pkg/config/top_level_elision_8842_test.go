package config

import "testing"

// #8842: eliding the TOP-LEVEL stanza keyword lost the statement, in every
// member, with a clean commit on both compile paths.
//
//	security alg dns disable;                                       ALG stayed ENABLED
//	security flow tcp-mss all-tcp 1350;                             clamp at 0
//	routing-options static route 10.9.0.0/16 next-hop 192.168.1.1;  NO route installed
//
// Reachable exactly where the already-fixed shallower cases were: the parser
// accepts it and CompileConfigLenient — the Store.Load and SyncApply ingress —
// returned nil while dropping the value. Not a curiosity; the same severity as
// #8823 and #8835, one elision level further out.
//
// ONE MECHANISM, NOT THREE, and the data carried its own positive control:
// `policy-options prefix-list PL 10.0.0.0/8;` is the same shape and ALREADY
// WORKED, because ("policy-options","prefix-list") was the one such pair already
// admitted to the normalizer. Three pairs were missing; admitting them is the
// whole fix. Had the working member needed something else, the uniformity would
// have been coincidence rather than a lever.
//
// WHAT THIS DOES TO ACCEPTANCE, measured rather than reasoned, because a new
// rejection on the load path is the failure mode that matters most here:
//
//	                        before            after
//	SchemaValidate          accepts all       accepts all      unchanged
//	CompileConfigLenient    accepts all       accepts all      unchanged
//	strict commit           accepts all       ONE new refusal  `tcp-mss all-tcp notanint`
//
// Nothing that loads today stops loading. The single new refusal is on the
// STRICT path, for a typo that used to be swallowed silently — the operator is
// present there and is now told. That is the intended direction: folding the
// tail makes it visible to the gates that were already watching, and the gates
// disagree with the load path only where an operator is standing in front of
// them.
//
// SCOPE OF THIS FIX, bounded rather than implied. There are 80 top-level
// (stanza, child) pairs in the schema; 26 are admitted to the normalizer and 54
// are not. This change admits three of those 54 — the members #8842 names.
//
// The remaining 51 are an UPPER BOUND on the class, not a defect count, and the
// distinction is measurable rather than rhetorical: a pair only fails open if
// its compiler reads Children. `alg` at d2 works with NO fold at all, because
// compileALG reads its own packed Keys (#8823). So each unadmitted pair is a
// candidate whose verdict needs the same braced-vs-elided measurement these
// three got, and counting them as defects would be the same error as reading a
// census hit as a defect.
//
// ASSERTED ON THE COMPILED VALUE, never on "commit succeeded": every broken row
// above committed with err=nil, so an acceptance assertion is vacuous by
// construction on this defect.
func TestTopLevelElisionDeliversTheValue8842(t *testing.T) {
	compile := func(t *testing.T, src string) *Config {
		t.Helper()
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			t.Fatalf("must COMMIT: %v", err)
		}
		return cfg
	}

	// EVERY DEPTH, EVERY MEMBER. d0-d2 are the regression half: they worked
	// before and must still work, so a fix that traded depth for depth reds.
	for _, c := range []struct {
		name, src string
		check     func(*Config) bool
		want      string
	}{
		{"alg d0", `security { alg { dns { disable; } } }`, func(c *Config) bool { return c.Security.ALG.DNSDisable }, "DNSDisable"},
		{"alg d1", `security { alg { dns disable; } }`, func(c *Config) bool { return c.Security.ALG.DNSDisable }, "DNSDisable"},
		{"alg d2", `security { alg dns disable; }`, func(c *Config) bool { return c.Security.ALG.DNSDisable }, "DNSDisable"},
		{"alg d3", `security alg dns disable;`, func(c *Config) bool { return c.Security.ALG.DNSDisable }, "DNSDisable"},

		{"mss d0", `security { flow { tcp-mss { all-tcp 1350; } } }`, func(c *Config) bool { return c.Security.Flow.TCPMSSAllTCP == 1350 }, "TCPMSSAllTCP=1350"},
		{"mss d2", `security { flow tcp-mss all-tcp 1350; }`, func(c *Config) bool { return c.Security.Flow.TCPMSSAllTCP == 1350 }, "TCPMSSAllTCP=1350"},
		{"mss d3", `security flow tcp-mss all-tcp 1350;`, func(c *Config) bool { return c.Security.Flow.TCPMSSAllTCP == 1350 }, "TCPMSSAllTCP=1350"},

		{"route d0", `routing-options { static { route 10.9.0.0/16 { next-hop { 192.168.1.1; } } } }`, oneRoute8842, "one static route"},
		{"route d2", `routing-options { static route 10.9.0.0/16 next-hop 192.168.1.1; }`, oneRoute8842, "one static route"},
		{"route d3", `routing-options static route 10.9.0.0/16 next-hop 192.168.1.1;`, oneRoute8842, "one static route"},

		// The member that ALREADY worked at this depth, kept as the positive
		// control for the mechanism: it is the same shape and its pair was the
		// one already admitted.
		{"prefix top-level (control)", `policy-options prefix-list PL 10.0.0.0/8;`, func(c *Config) bool {
			p := c.PolicyOptions.PrefixLists["PL"]
			return p != nil && len(p.Prefixes) == 1
		}, "one prefix"},
	} {
		if !c.check(compile(t, c.src)) {
			t.Errorf("%s: %s missing. A statement that COMMITS and is silently discarded is "+
				"the fail-open this fixes — an ALG left enabled, a clamp at zero, or a route "+
				"never installed, each with no diagnostic", c.name, c.want)
		}
	}

	// THE SHIPPED SPELLINGS ARE THE CONTROLS. docs/ha-cluster.conf:140 and
	// test/incus/xpf-test.conf write the braced short form; if widening the
	// normalizer cost those, the fix would be worse than the defect.
	if c := compile(t, `security { flow { tcp-mss { all-tcp 1396; } allow-dns-reply; } }`); c.Security.Flow.TCPMSSAllTCP != 1396 {
		t.Errorf("shipped ha-cluster form -> TCPMSSAllTCP=%d, want 1396", c.Security.Flow.TCPMSSAllTCP)
	}

	// THE LOAD PATH MUST NOT HAVE GAINED A REFUSAL. This is the no-brick half
	// and it is asserted, not assumed: a config that loads today must still
	// load, including one carrying a typo in the newly-visible tail.
	for _, src := range []string{
		`security alg dns disabel;`,
		`security flow tcp-mss all-tcp notanint;`,
		`routing-options static route 10.9.0.0/16 nexthop 192.168.1.1;`,
	} {
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		if _, err := CompileConfigLenient(tree); err != nil {
			t.Errorf("CompileConfigLenient REFUSED %q: %v. That path is Store.Load and "+
				"SyncApply; a config that loads today must still load, or the fix trades a "+
				"silent drop for a boot failure", src, err)
		}
	}
}

func oneRoute8842(c *Config) bool { return len(c.RoutingOptions.StaticRoutes) == 1 }
