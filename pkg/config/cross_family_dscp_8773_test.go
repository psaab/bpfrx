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

	// NEGATIVE CONTROL: a same-family spelling must NOT warn. Without this the
	// advisory could fire on everything and still pass every case above.
	_, w := dscps(t, "inet", "from dscp af11;")
	for _, msg := range w {
		if strings.Contains(msg, "#8773") {
			t.Errorf("same-family `from dscp` in family inet raised a cross-family "+
				"advisory: %q. A warning that fires on correct configuration is worse "+
				"than none -- operators stop reading them", msg)
		}
	}
}
