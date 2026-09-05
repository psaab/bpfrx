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
//	elided   S C { <leaf> <value>; }
//
// Reports a RATIO, not a hit list. A candidate is a pair whose two spellings
// disagree; a defect is a candidate whose disagreement is a dropped value.
//
// EXACTLY ONE BRACE DIFFERS BETWEEN THE ARMS, and that is the brace of the pair
// the row is NAMED for. The population is not all depth-2: 19 of the 64 pairs
// sit under a container three or four elements deep, e.g.
//
//	[security address-book global]        named "security address-book"
//	[snmp v3 usm local-engine]            named "snmp v3"
//
// An earlier form of this sweep packed the WHOLE container, so for those rows it
// elided several braces at once while the row was still named (S, C) and the
// un-admitted filter still only asked compactNormalizeInScope(S, C). A
// CANDIDATE-DROP could then be produced by a DEEPER link than the one the row
// claimed -- a fixture recording the last link of a chain while the row names
// the first.
//
// That was not hypothetical. Isolating the named pair moved five rows:
//
//	class-of-service interfaces/classifiers   CANDIDATE-DROP        -> SAME
//	firewall policer/if-exceeding             CANDIDATE-DROP        -> SAME
//	routing-options rib/static                CANDIDATE-DROP        -> SAME
//	schedulers scheduler/daily                CANDIDATE-DROP/WARNS  -> SAME
//	interfaces .../aggregated-ether-options   SILENT                -> STRICT-REJECTS
//
// Four were not drops at all; one was not silent but refused loudly at commit.
// Totals moved 43/1/1/18/1 to 39 SILENT / 2 STRICT-REJECTS / 0 WARNS / 22 SAME /
// 1 NO-REFERENCE.
//
// A CONSEQUENCE WORTH KNOWING: the WARNS branch of the gate check now has NO
// member, because its only row turned out not to be a defect. The branch is
// therefore unexercised by this sweep -- it is not dead code (the #6662/#6706
// warning path is real) but nothing here proves it still fires. STRICT-REJECTS
// keeps two members, `system login` among them, and remains the positive
// control that stops a handled drop being scored as a defect.
//
// The SAME and NO-REFERENCE rows are the negative controls and are kept
// deliberately: an instrument that flagged all 64 would be measuring itself.
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
		// ELIDE EXACTLY THE PAIR THIS ROW IS NAMED FOR, and nothing deeper.
		//
		// The earlier form packed the WHOLE container -- `strings.Join(s.container,
		// " ")` -- so for a container deeper than two it elided several braces
		// while the row was still named `(stanza, child)` and the un-admitted
		// filter still only asked `compactNormalizeInScope(stanza, child)`. A
		// CANDIDATE-DROP could then be caused by a deeper link than the one it
		// named: a fixture recording the LAST link of a chain while the row
		// claims the FIRST.
		//
		// MEASURED, which is why this is not a stylistic change. 19 of the rows
		// have containers deeper than two, and isolating the named pair moves
		// FIVE of them:
		//
		//	class-of-service interfaces/classifiers   CANDIDATE-DROP -> SAME
		//	firewall policer/if-exceeding             CANDIDATE-DROP -> SAME
		//	routing-options rib/static                CANDIDATE-DROP -> SAME
		//	schedulers scheduler/daily                CANDIDATE-DROP/WARNS -> SAME
		//	interfaces .../aggregated-ether-options   SILENT -> STRICT-REJECTS
		//
		// So four were not drops at all and one was not silent -- it is refused
		// loudly at commit. Those five were the whole of the WARNS column and
		// part of the SILENT column in the table this instrument published.
		//
		// The depth-2 rows are unaffected: their parent is a single element and
		// the expression below reduces to exactly the previous text. Checked
		// separately: no depth-2 row has a non-empty contextFor(parent), so the
		// braced arm carries no sibling context that the elided arm drops.
		var elidedText string
		if len(parent) >= 2 {
			elidedText = nest(append([]string{parent[0] + " " + parent[1]}, parent[2:]...), inner)
		} else {
			elidedText = parent[0] + " " + inner
		}
		ec, eok := compile(elidedText)
		var v, d string
		switch {
		case !bok:
			v, d = "NO-REFERENCE", "braced form does not compile — fixture cannot answer"
		case !eok:
			v, d = "ELIDED-REFUSED", "elided refused at commit — loud, not a silent drop"
		case dig(bc) == dig(ec):
			v, d = "SAME", "elided delivers what braced delivers"
		default:
			g := gated(elidedText)
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
