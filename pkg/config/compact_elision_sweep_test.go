package config

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// Full sweep of UNADMITTED top-level (stanza, child) pairs.
//
//	braced   S { C { <leaf> <value>; } }
//	elided   S C <leaf> <value>;
//
// Reports a RATIO, not a hit list. A candidate is a pair whose two spellings
// disagree; a defect is a candidate whose disagreement is a dropped value.
func TestSweepFull(t *testing.T) {
	dig := func(c *Config) string {
		if c == nil {
			return "<nil>"
		}
		c.Warnings = nil
		b, _ := json.Marshal(c)
		return string(b)
	}
	compile := func(text string) (*Config, bool) {
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 || tr == nil {
			return nil, false
		}
		cfg, err := CompileConfigLenient(tr)
		if err != nil || cfg == nil {
			return nil, false
		}
		return cfg, true
	}
	// GATE CHECK. A dropped value that the STRICT path refuses, or that raises a
	// warning, is HANDLED — the operator is told. From the compiled value alone
	// a handled drop is indistinguishable from an unhandled one, which is how
	// `system login` (#6662/#6706: LoginDroppedByPacking + strict reject +
	// warning) sat in the candidate set looking exactly like a defect.
	gated := func(text string) string {
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 || tr == nil {
			return "?"
		}
		if _, err := compileConfigWithOpts(tr, compileOpts{}); err != nil {
			return "STRICT-REJECTS"
		}
		tr2, _ := NewParser(text).Parse()
		if cfg, err := CompileConfigLenient(tr2); err == nil && cfg != nil && len(cfg.Warnings) > 0 {
			return "WARNS"
		}
		return "SILENT"
	}
	// firstDiff names the JSON field that differs, so a row can be adjudicated
	// rather than counted.
	firstDiff := func(a, b string) string {
		n := len(a)
		if len(b) < n {
			n = len(b)
		}
		for i := 0; i < n; i++ {
			if a[i] != b[i] {
				lo := i - 45
				if lo < 0 {
					lo = 0
				}
				return strings.ReplaceAll(a[lo:i+1], "\"", "")
			}
		}
		return "<length only>"
	}

	type row struct{ pair, verdict, detail string }
	var rows []row
	seen := map[string]bool{}
	counts := map[string]int{}

	for _, s := range collectCompactSites() {
		if len(s.container) < 2 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		stanza, child := s.container[0], s.container[1]
		pair := stanza + " " + child
		if seen[pair] || compactNormalizeInScope(stanza, child) {
			continue
		}
		v1, _, ok := synthPair(s.node)
		if !ok {
			continue
		}
		seen[pair] = true
		parent := s.container[:len(s.container)-1]
		stanzaLeaf := s.container[len(s.container)-1]
		inner := contextFor(parent) + stanzaLeaf + " " + s.leaf + " " + v1 + ";"
		bc, bok := compile(nest(parent, inner))
		ec, eok := compile(strings.Join(s.container, " ") + " " + s.leaf + " " + v1 + ";")
		var v, d string
		switch {
		case !bok:
			v, d = "NO-REFERENCE", "braced form does not compile — fixture cannot answer"
		case !eok:
			v, d = "ELIDED-REFUSED", "elided refused at commit — loud, not a silent drop"
		case dig(bc) == dig(ec):
			v, d = "SAME", "elided delivers what braced delivers"
		default:
			g := gated(strings.Join(s.container, " ") + " " + s.leaf + " " + v1 + ";")
			v = "CANDIDATE-DROP/" + g
			d = firstDiff(dig(bc), dig(ec))
		}
		counts[v]++
		rows = append(rows, row{pair, v, d})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].verdict != rows[j].verdict {
			return rows[i].verdict < rows[j].verdict
		}
		return rows[i].pair < rows[j].pair
	})
	for _, r := range rows {
		t.Logf("SW %-38s %-32s %s", r.pair, r.verdict, r.detail)
	}
	t.Logf("SW === %d pairs swept: %v", len(rows), counts)
}
