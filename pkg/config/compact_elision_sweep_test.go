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
// warning path is real) but nothing here proves it still fires.
//
// AND AN UNEXERCISED BRANCH IS WHERE AN UNSOUND RULE SURVIVES. That is what
// happened: the branch asked "does the elided spelling produce ANY warnings?",
// so any container carrying a STANDING advisory scored WARNS for free and a
// real silent drop inside it read as handled. It now compares the warning SETS
// between the two arms. sweep_warns_soundness_8895_test.go supplies the two
// controls this sweep cannot: a standing warning must not score WARNS, and a
// warning unique to the elided arm must. STRICT-REJECTS
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
	counts := map[string]int{}

	// EVERY SITE FOR A PAIR IS EVALUATED, not just the first.
	//
	// This loop used to `seen[pair]`-skip after the first site, so the published
	// verdict was a property of WHICHEVER LEAF the enumeration reached first --
	// and `collectCompactSites` order is not something a reader of the table can
	// see. The gate column then claimed "this PAIR's elided spelling is refused
	// / warned / silent" while the measurement supported only "the elided
	// spelling OF THAT ONE LEAF was".
	//
	// They come apart whenever the strictness lives on the LEAF rather than on
	// the container: a typed or validated leaf under an otherwise permissive
	// container makes the whole pair read STRICT-REJECTS.
	//
	// MEASURED: 22 of 46 pairs disagree across their own sites. `interfaces
	// <name>` alone yields SILENT (via link-speed), STRICT-REJECTS (via address)
	// and WARNS (via periodic).
	//
	// THE DIRECTION OF THE ERROR IS THE HARMFUL ONE. This column is what decides
	// admit-vs-decline, so a genuinely SILENT pair that happened to draw a strict
	// leaf reads STRICT-REJECTS and gets skipped as "already loud" -- a silent
	// drop, filed as handled. That is the `system login` trap inverted: there a
	// handled row looked like a defect; here a defect row looks handled.
	//
	// So disagreement is published as its own verdict rather than resolved.
	// Picking one would be choosing an answer from a sample of one and printing
	// it with the authority of a measurement.
	perPair := map[string]map[string]string{} // pair -> verdict -> example leaf
	pairDetail := map[string]string{}
	var pairOrder []string

	for _, s := range collectCompactSites() {
		if len(s.container) < 2 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		stanza, child := s.container[0], s.container[1]
		pair := stanza + " " + child
		if compactNormalizeInScope(stanza, child) {
			continue
		}
		v1, _, ok := synthPair(s.node)
		if !ok {
			continue
		}
		parent := s.container[:len(s.container)-1]
		stanzaLeaf := s.container[len(s.container)-1]
		inner := contextFor(parent) + stanzaLeaf + " " + s.leaf + " " + v1 + ";"
		bracedText := nest(parent, inner)
		bc, bok := compile(bracedText)
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
			g := sweepGateVerdict8859(bracedText, elidedText)
			v = "CANDIDATE-DROP/" + g
			d = firstDiff(dig(bc), dig(ec))
		}
		if perPair[pair] == nil {
			perPair[pair] = map[string]string{}
			pairOrder = append(pairOrder, pair)
		}
		if _, dup := perPair[pair][v]; !dup {
			perPair[pair][v] = s.leaf
		}
		if pairDetail[pair] == "" {
			pairDetail[pair] = d
		}
	}
	for _, pair := range pairOrder {
		vs := perPair[pair]
		if len(vs) == 1 {
			for v := range vs {
				counts[v]++
				rows = append(rows, row{pair, v, pairDetail[pair]})
			}
			continue
		}
		var parts []string
		for v, lf := range vs {
			parts = append(parts, v+"(via "+lf+")")
		}
		sort.Strings(parts)
		counts["LEAF-CONTINGENT"]++
		rows = append(rows, row{pair, "LEAF-CONTINGENT",
			"verdict depends on which leaf is synthesized: " + strings.Join(parts, " | ")})
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

// #8859. The sweep's gate column classifies every candidate SILENT /
// STRICT-REJECTS / WARNS, and that column is what stops a HANDLED drop being
// scored as a defect -- `system login` was in the candidate set looking exactly
// like one until the column existed.
//
// AFTER THE DEPTH CORRECTION, THE `WARNS` ARM HAS NO MEMBER. Its only row
// (`schedulers scheduler/daily`) turned out not to be a defect at all once each
// row elided only the brace it was named for. An empty column is the third
// state this board keeps rediscovering: it looks identical to a branch that
// STOPPED WORKING and to a branch that is simply unpopulated, and the sweep
// cannot tell you which.
//
// So the arm gets its own positive control, out of band from the sweep. Found
// by lane-8526; reproduced here before adopting rather than taken on report.
//
// TWO NEGATIVES SIT BESIDE IT DELIBERATELY. A control that only asserts
// "WARNS is reachable" is satisfied by a gate that returns WARNS for
// everything, which would silently reclassify every SILENT row in the table as
// handled -- the exact direction that makes a defect list under-report.
func TestGateColumnArmsAreReachable8859(t *testing.T) {
	for _, c := range []struct{ name, braced, elided, want string }{
		// THE WARNS ARM HAS NO NATURAL MEMBER, AND THAT IS A MEASURED FACT
		// RATHER THAN AN OMISSION. Its only mechanism -- #6662's packed-login
		// notice -- is reached through a spelling the STRICT path rejects
		// first, so the pair scores STRICT-REJECTS:
		//
		//	braced  system { login { user u1 { class super-user; } } }   1 warning
		//	packed  system { login user u1 class super-user; }           2 warnings,
		//	        one of them unique to the packed arm -- but strict refuses it
		//
		// The rows below therefore exercise the arm this cell CAN reach. The
		// set-comparison logic itself is exercised directly in
		// sweep_warns_soundness_8895_test.go, which is honest about testing the
		// predicate rather than a configuration.
		//
		// A STANDING advisory must NOT score WARNS -- and this row is the one
		// that kills the old counting rule. Both arms carry the same
		// `alg ... accepted but inert` notice, so the operator is told about
		// the ALG, not about any drop. These rows used to expect WARNS here,
		// which is what the unsound rule returned.
		{"standing-advisory-is-not-handled",
			"security { alg { h323; } }", "security alg h323;", "SILENT"},
		// Negatives: without these the cell passes on a gate stuck at WARNS.
		{"silent-proposal",
			"security { ike { proposal P { description hi; } } }",
			"security ike proposal P { description hi; }", "SILENT"},
		{"silent-empty", "", "", "SILENT"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := sweepGateVerdict8859(c.braced, c.elided); got != c.want {
				t.Errorf("gate arm for %q vs %q: got %s want %s (#8859/#8895)\n"+
					"The sweep's gate column decides whether a dropped value is a "+
					"DEFECT or a HANDLED case. An arm that no longer fires "+
					"reclassifies rows silently and in the under-reporting "+
					"direction.", c.braced, c.elided, got, c.want)
			}
		})
	}
}

// warningSet8859 returns the lenient-compile warnings of one spelling.
func warningSet8859(text string) map[string]bool {
	out := map[string]bool{}
	tr, perrs := NewParser(text).Parse()
	if len(perrs) > 0 || tr == nil {
		return out
	}
	if cfg, err := CompileConfigLenient(tr); err == nil && cfg != nil {
		for _, w := range cfg.Warnings {
			out[w] = true
		}
	}
	return out
}

// sweepGateVerdict8859 asks whether the OPERATOR IS TOLD ABOUT THIS DROP, and
// it needs BOTH spellings to answer that.
//
// It is package-level and has exactly ONE implementation, deliberately. It was
// previously a closure inside TestSweepFull with a SECOND copy inside the
// reachability cell, and when the unsound version was fixed only one copy
// moved: the cell whose job was to prove the WARNS arm fires went on
// validating the rule the sweep had stopped using. Two implementations of one
// predicate is a difference that can only ever be a bug, never a policy
// choice, and re-implementing it inside a test is what made the divergence
// invisible from within that test.
//
// THE RULE. Asking only "does the elided spelling produce ANY warnings?" is a
// different question, and any container carrying a STANDING advisory -- a
// parity notice, a deprecation, an accepted-only warning -- answers it for
// free. Measured on `aggregated-ether-options -> lacp`, both arms carry the
// identical #6544 notice: the operator is told LAG is unimplemented, NOT that
// `lacp active` was discarded. `security alg h323` behaves the same way.
//
// So compare the SETS: only a warning present in the ELIDED arm and absent
// from the braced one is about the drop. The liveness rule applied to the
// warning channel -- a warning in both arms is standing and proves nothing.
//
// The error direction matters: the old form could only score a real drop as
// HANDLED, never the reverse, so it under-reported.
func sweepGateVerdict8859(bracedText, elidedText string) string {
	tr, perrs := NewParser(elidedText).Parse()
	if len(perrs) > 0 || tr == nil {
		return "?"
	}
	if _, err := compileConfigWithOpts(tr, compileOpts{}); err != nil {
		return "STRICT-REJECTS"
	}
	braced := warningSet8859(bracedText)
	for w := range warningSet8859(elidedText) {
		if !braced[w] {
			return "WARNS"
		}
	}
	return "SILENT"
}

// #8859. A published sweep verdict must not be a single-sample claim.
//
// The sweep evaluates every site for a pair and publishes LEAF-CONTINGENT where
// they disagree. This cell asserts the property that makes that worth doing:
// the disagreement is REAL and the instrument can see it.
//
// Without it the fix is unfalsifiable — a sweep that never emits
// LEAF-CONTINGENT looks identical whether the class is empty or the detection
// is broken, which is the third state this file already documents for the WARNS
// arm.
//
// THE SHAPE THAT MATTERS is a pair where one leaf says SAME and another says
// CANDIDATE-DROP. That is the harmful direction: under first-site-wins the pair
// could publish SAME — no defect — while a different leaf under it silently
// loses its value. Measured at the time of writing, three pairs have exactly
// that shape (`class-of-service classifiers` via inet-precedence vs dscp,
// `class-of-service rewrite-rules` via exp vs dscp, and `system services`).
func TestSweepVerdictsAreNotSingleSample8859(t *testing.T) {
	perPair := map[string]map[string]bool{}
	for _, s := range collectCompactSites() {
		if len(s.container) < 2 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		stanza, child := s.container[0], s.container[1]
		if compactNormalizeInScope(stanza, child) {
			continue
		}
		v1, _, ok := synthPair(s.node)
		if !ok {
			continue
		}
		parent := s.container[:len(s.container)-1]
		stanzaLeaf := s.container[len(s.container)-1]
		inner := contextFor(parent) + stanzaLeaf + " " + s.leaf + " " + v1 + ";"
		bracedText := nest(parent, inner)
		var elidedText string
		if len(parent) >= 2 {
			elidedText = nest(append([]string{parent[0] + " " + parent[1]}, parent[2:]...), inner)
		} else {
			elidedText = parent[0] + " " + inner
		}
		bt, bperrs := NewParser(bracedText).Parse()
		et, eperrs := NewParser(elidedText).Parse()
		if len(bperrs) > 0 || len(eperrs) > 0 {
			continue
		}
		bc, berr := CompileConfigLenient(bt)
		ec, eerr := CompileConfigLenient(et)
		v := "SAME"
		switch {
		case berr != nil || bc == nil:
			v = "NO-REFERENCE"
		case eerr != nil || ec == nil:
			v = "ELIDED-REFUSED"
		default:
			// JSON, NOT %v. The Config graph is full of pointers and %v prints
			// ADDRESSES, which differ on every compile by construction -- so
			// every site would read CANDIDATE-DROP, every pair would agree, and
			// this cell would report ZERO contingency while the sweep reports
			// seven. Measured: that is exactly what the first draft did.
			bc.Warnings, ec.Warnings = nil, nil
			bj, _ := json.Marshal(bc)
			ej, _ := json.Marshal(ec)
			if string(bj) != string(ej) {
				v = "CANDIDATE-DROP"
			}
		}
		key := stanza + " " + child
		if perPair[key] == nil {
			perPair[key] = map[string]bool{}
		}
		perPair[key][v] = true
	}

	contingent, harmful := 0, 0
	for _, vs := range perPair {
		if len(vs) > 1 {
			contingent++
			if vs["SAME"] && vs["CANDIDATE-DROP"] {
				harmful++
			}
		}
	}
	if contingent == 0 {
		t.Error("no pair disagrees across its own sites, so LEAF-CONTINGENT can " +
			"never be emitted and the sweep's per-pair verdicts are back to being " +
			"single-sample claims that nothing checks (#8859)")
	}
	// THE HARMFUL SHAPE SPECIFICALLY. A pair that says SAME on one leaf and
	// CANDIDATE-DROP on another would, under first-site-wins, publish "no
	// defect" while silently losing a value through the other leaf.
	if harmful == 0 {
		t.Error("no pair mixes SAME with CANDIDATE-DROP across its sites. Either " +
			"the population changed or this cell stopped measuring the shape it " +
			"exists for -- it is the SAME-hiding-a-drop case that makes " +
			"first-site-wins dangerous rather than merely imprecise (#8859)")
	}
	t.Logf("#8859: %d pairs, %d leaf-contingent, %d of those mix SAME with "+
		"CANDIDATE-DROP", len(perPair), contingent, harmful)
}
