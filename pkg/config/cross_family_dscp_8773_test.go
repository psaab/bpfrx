package config

import (
	"strings"
	"testing"
)

// #8773: the two spellings of a firewall `from` match must agree, in BOTH
// address families, and a cross-family spelling must be named at commit rather
// than accepted silently.
//
// THE FIXTURE IS THE CLAIM HERE, and this cell exists partly to pin that. The
// defect was originally reported as "`traffic-class` is silently lost in the
// brace-elided spelling". That was wrong: it is lost only when written in the
// family it does not belong to. The report's fixture wrapped every case in
// `family inet` and varied only the CRITERION, so it could not see that the
// real variable was the FAMILY -- and a control that varied the criterion
// confirmed the wrong reading rather than catching it. Every case below
// therefore varies BOTH axes.
func TestCrossFamilyDSCPSpelling8773(t *testing.T) {
	dscps := func(t *testing.T, af, body string) ([]string, []string) {
		t.Helper()
		text := `firewall { family ` + af + ` { filter f1 { term t1 { ` + body + ` then accept; } } } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			t.Fatalf("family %s / %q must COMMIT: %v", af, body, err)
		}
		filters := cfg.Firewall.FiltersInet
		if af == "inet6" {
			filters = cfg.Firewall.FiltersInet6
		}
		for _, f := range filters {
			for _, term := range f.Terms {
				// The criterion under test decides which typed field carries
				// its value: dscp/traffic-class land in DSCPs, protocol/
				// next-header in Protocols. Reading the wrong one would make
				// every protocol case look like a silent drop.
				if strings.Contains(body, "protocol") || strings.Contains(body, "next-header") {
					return term.Protocols, cfg.Warnings
				}
				return term.DSCPs, cfg.Warnings
			}
		}
		t.Fatalf("family %s / %q compiled no term", af, body)
		return nil, nil
	}

	// SAME-FAMILY: both spellings work and agree. These are the control half —
	// without them a cross-family failure below could be a broken fixture.
	for _, c := range []struct{ af, leaf, val string }{
		{"inet", "dscp", "af11"},
		{"inet6", "traffic-class", "0"},
		// #8781: `next-header` in family inet6 is the CORRECT Junos spelling,
		// and it is the one that was silently dropped in the packed form — a
		// correctly-authored IPv6 term lost its protocol match entirely and
		// therefore matched EVERY protocol. It belongs in the same-family half
		// precisely because nothing about it is a cross-family curiosity.
		{"inet6", "next-header", "tcp"},
		{"inet", "protocol", "tcp"},
	} {
		packed, _ := dscps(t, c.af, "from "+c.leaf+" "+c.val+";")
		braced, _ := dscps(t, c.af, "from { "+c.leaf+" "+c.val+"; }")
		if len(packed) != 1 || packed[0] != c.val {
			t.Errorf("family %s packed `from %s %s` -> DSCPs=%v, want [%s]", c.af, c.leaf, c.val, packed, c.val)
		}
		if len(braced) != 1 || braced[0] != c.val {
			t.Errorf("family %s braced `from %s %s` -> DSCPs=%v, want [%s]", c.af, c.leaf, c.val, braced, c.val)
		}
	}

	// CROSS-FAMILY: the two spellings must AGREE, and both must warn. Before
	// #8773 braced applied the criterion and packed dropped it silently.
	for _, c := range []struct{ af, leaf, val, want string }{
		{"inet", "traffic-class", "0", "dscp"},
		{"inet6", "dscp", "af11", "traffic-class"},
		{"inet", "next-header", "tcp", "protocol"},
		{"inet6", "protocol", "tcp", "next-header"},
	} {
		packed, pw := dscps(t, c.af, "from "+c.leaf+" "+c.val+";")
		braced, bw := dscps(t, c.af, "from { "+c.leaf+" "+c.val+"; }")
		if len(packed) != 1 || packed[0] != c.val {
			t.Errorf("family %s PACKED `from %s %s` -> DSCPs=%v, want [%s]. The packed "+
				"reader resolves its tail through the schema; if the alias is gone the "+
				"criterion is dropped SILENTLY and the term matches on one fewer "+
				"dimension than written", c.af, c.leaf, c.val, packed, c.val)
		}
		if len(braced) != len(packed) {
			t.Errorf("family %s: braced and packed DISAGREE (%v vs %v). Making the two "+
				"spellings agree is the whole of #8773", c.af, braced, packed)
		}
		for _, w := range []struct {
			tag  string
			list []string
		}{{"packed", pw}, {"braced", bw}} {
			var found bool
			for _, msg := range w.list {
				if strings.Contains(msg, c.leaf) && strings.Contains(msg, "#8773") &&
					strings.Contains(msg, c.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("family %s %s `from %s`: no cross-family advisory naming the "+
					"Junos spelling %q; warnings=%v. Agreeing on ACCEPT without saying so "+
					"trades a silent drop for a silent acceptance",
					c.af, w.tag, c.leaf, c.want, w.list)
			}
		}
	}

	// NEGATIVE CONTROL: a same-family spelling must NOT warn, for EVERY aliased
	// field. Without this the advisory could fire on everything and still pass
	// every case above; with only one field checked it could fire on all of the
	// other field's correct spellings unnoticed.
	for _, c := range []struct{ af, body string }{
		{"inet", "from dscp af11;"},
		{"inet6", "from traffic-class 0;"},
		{"inet6", "from next-header tcp;"},
		{"inet", "from protocol tcp;"},
	} {
		_, w := dscps(t, c.af, c.body)
		for _, msg := range w {
			if strings.Contains(msg, "#8773") || strings.Contains(msg, "#8781") {
				t.Errorf("family %s same-family `%s` raised a cross-family advisory: %q. "+
					"A warning that fires on correct configuration is worse than none — "+
					"operators stop reading them", c.af, c.body, msg)
			}
		}
	}
}

// #8781 follow-up: the flat `set` spelling is a SEPARATE CASE, not an assumed
// equivalent of the hierarchical one.
//
// CLAUDE.md documents the dual AST shape and forbids using NewParser as a
// stand-in for a `set` session, and the cell above uses NewParser exclusively —
// so on its own it says nothing about what the CLI produces. That gap is not
// hypothetical: on #8778 a fix for the hierarchical packed form left the flat
// `set` spelling still failing open, with a passing hierarchical test beside
// it, because flat `set` builds a CHAIN where the fixture built siblings.
//
// The outcome asserted here is the ENFORCED one — `Protocols` is exactly
// [tcp] — never that two spellings agree. An IPv6 term whose protocol match is
// dropped matches EVERY protocol, so two dropped spellings agree perfectly
// while the filter is wide open; an agreement assertion is satisfied by the
// regression it is supposed to catch.
//
// WHAT THIS CELL BINDS, AND WHAT IT DOES NOT — measured, because a coverage
// cell that is assumed to guard the fix is worse than no cell:
//
//	removing `next-header` from compileFilterFrom's switch arm   -> RED
//	removing the inet6 `next-header` schema declaration          -> still green
//
// The flat `set` path does not go through the schema at all: SetPath builds a
// real child node and the compiler reads it from node.Children. So this cell
// binds the COMPILER ARM, and the packed hierarchical path's dependency on the
// schema DECLARATION is bound by TestCrossFamilyDSCPSpelling8773 above. Two
// paths, two dependencies, one cell each — and neither substitutes for the
// other. Do not cite this cell as covering #8781's schema fix.
func TestFlatSetNextHeaderIsEnforced8781(t *testing.T) {
	compile := func(t *testing.T, cmds []string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			path, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			t.Fatalf("flat set must COMMIT: %v", err)
		}
		return cfg
	}
	protocols := func(t *testing.T, cfg *Config) []string {
		t.Helper()
		for _, f := range cfg.Firewall.FiltersInet6 {
			for _, term := range f.Terms {
				return term.Protocols
			}
		}
		t.Fatal("flat set compiled no inet6 filter term")
		return nil
	}

	base := "set firewall family inet6 filter f1 term t1 "
	for _, leaf := range []string{"next-header", "protocol"} {
		got := protocols(t, compile(t, []string{base + "from " + leaf + " tcp", base + "then accept"}))
		if len(got) != 1 || got[0] != "tcp" {
			t.Errorf("flat set `from %s tcp` -> Protocols=%v, want exactly [tcp]. An empty "+
				"list is not a weaker match, it is NO match: the term matches every "+
				"protocol, so a filter meant to accept TCP accepts everything and one "+
				"meant to discard TCP discards everything (#8781)", leaf, got)
		}
	}

	// The one-line spelling, where `next-header` is multi:true and absorbs the
	// trailing tokens onto its own Keys. It must FAIL CLOSED — a commit error
	// naming the bad token — rather than compile with a mangled match. The
	// `protocol` case is the control: this is long-established behaviour of
	// multi-value leaves, not something the #8781 declaration introduced, and
	// asserting both keeps a future change from quietly making one of them
	// compile.
	for _, leaf := range []string{"next-header", "protocol"} {
		tree := &ConfigTree{}
		path, err := ParseSetCommand(base + "from " + leaf + " tcp then accept")
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("one-line `from %s tcp then accept` COMPILED. `%s` is multi:true, so "+
				"it absorbs `then accept` onto its own Keys; accepting that silently "+
				"would compile a term whose action and protocol set are both wrong. It "+
				"must be refused at commit", leaf, leaf)
		}
	}
}
