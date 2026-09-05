package config

import (
	"sort"
	"strings"
	"testing"
)

// A COUNTED RATCHET over pairs that are admitted to the brace-elision scope but
// whose container CANNOT SPLIT a multi-statement packed run.
//
// THERE ARE TWO FAILURE MODES AND THEY SPLIT ON THIS PREDICATE'S OWN
// DISJUNCTION, which is why `multi || args >= N` is not one population wearing
// two hats:
//
//	multi leaves      INJECTION -- the repeated statement's KEYWORD is absorbed
//	                  as a list value, so the packed arm has MORE members than
//	                  the braced one, one of them a phantom named after the
//	                  keyword.
//	args >= 2 keys    TRUNCATION -- later instances are simply lost, so the
//	                  packed arm has FEWER.
//
// A CELL THAT COMPARES LENGTHS SCORES INJECTION AS INCREASED COVERAGE. "3 vs 2"
// reads as a gain until you print the members and see that one of the three is
// a phantom. Every comparison here is on rendered CONTENTS for that reason.
//
// SEVERITY IS NOT A PROPERTY OF THE MODE. Injection is SILENT in a NAT pool and
// in the resolver list, REJECTED for a WireGuard peer, and WARNED for an
// address-set. Whether the operator hears about it depends entirely on whether
// some unrelated downstream validator happens to trip over the phantom, so the
// gate verdict has to be measured per pair and cannot be inferred from the mode.
//
// A `STRICT-REJECTS` VERDICT ONLY MEANS "HANDLED" IF THE BRACED ARM WAS
// ACCEPTED. A fixture whose braced arm also fails makes the packed rejection
// evidence of nothing -- the liveness rule pointed at reject verdicts rather
// than at equality ones. Each member below asserts its braced reference first.
//
// THE DEFECT CLASS, with a live member measured at this base:
//
//	system { name-server 1.1.1.1 name-server 8.8.8.8; }
//	  packed  1.1.1.1 | name-server | 8.8.8.8
//	  braced  1.1.1.1 | 8.8.8.8
//
// The second statement is not merely lost. The multi leaf absorbs the following
// statement's KEYWORD as one of its own values, so the box ends up with a
// resolver literally named `name-server`. A dropped entry breaks whatever
// referenced it and somebody notices; a garbage entry sits in the list.
//
// WHY A RATCHET RATHER THAN 462 ADJUDICATIONS. Landing the count is what makes
// the population's GROWTH visible on the commit that causes it. The #8850
// address-book fix was partial for hours precisely because nothing counted this
// class: the scope entry was added, the container could not split, and the only
// signal was a two-entry fixture nobody had written yet.
//
// THIS IS NOT #8876, AND CONFLATING THEM MAKES BOTH UNFALSIFIABLE.
//
//	#8876   the container's PARENT EDGE is missing, so the container is never
//	        created at all (163 missing edges, 32 load-bearing)
//	here    the container IS reachable and IS admitted, and folds a
//	        multi-statement run into ONE
//
// A row that drifts between them is evidence for neither.
//
// THE NUMBER IS AN OVER-APPROXIMATION AND THE CEILING IS NOT MEASURED IN EITHER
// DIRECTION. A pair is only actually broken if a multi-statement packed run
// REACHES that container in a config someone writes, which this census does not
// model; some leaf-lists are also correct not to split. And the threshold below
// is itself a judgement -- see the two counts.
//
// STATE THE INSTRUMENT, NOT JUST THE BASE. Both 95 and 462 are true at the same
// commit; what separates them is the predicate and the traversal. A bare "N at
// master <sha>" does not identify which number you measured, and the walk here
// descends into `wildcard` nodes -- an earlier version did not, and silently
// missed ("peer","allowed-ips"), a WireGuard peer's CIDR list reachable only
// through an instance slot.
// The bool value is whether the leaf is `multi`, recorded AT THE NODE THAT
// QUALIFIED. Looking it up afterwards by (keyword, leaf) is ambiguous -- the
// same pair is reachable by several schema paths, and a first-match walk
// attributed the wrong node, giving 87 where the in-walk count gives 89.
func unsplittablePairs8880(minArgs int) (map[string]bool, map[string]bool) {
	uniq := map[string]bool{}
	conflict := map[string]bool{}
	seen := map[string]bool{}
	var walk func(path, kw string, n *schemaNode)
	walk = func(path, kw string, n *schemaNode) {
		if n == nil || seen[path] {
			return
		}
		seen[path] = true
		for name, c := range n.children {
			if c == nil {
				continue
			}
			// Admitted to the brace-elision scope, container cannot split a
			// packed run, leaf carries a value that a second statement would
			// collide with.
			if kw != "" && compactNormalizeInScope(kw, name) &&
				!n.packedStatements && (c.multi || c.args >= minArgs) {
				key := kw + " " + name
				if was, seenBefore := uniq[key]; seenBefore && was != c.multi {
					// LAST-WRITE-WINS HERE IS NON-DETERMINISTIC: Go randomises map
					// iteration, so which path writes last varies per run. The
					// pair COUNT is unaffected (the key is the same either way),
					// but any per-pair property read off it drifts -- measured, a
					// multi/non-multi split reported 87 then 93 on one unchanged
					// tree. Conflicting pairs are excluded from the split rather
					// than resolved arbitrarily.
					conflict[key] = true
				}
				uniq[key] = c.multi
			}
			walk(path+"/"+name, name, c)
		}
		// An instance slot keeps the PARENT's keyword: a wildcard is a name, not
		// a container keyword.
		if n.wildcard != nil {
			walk(path+"/*", kw, n.wildcard)
		}
	}
	for k, c := range setSchema.children {
		walk(k, k, c)
	}
	return uniq, conflict
}

func TestUnsplittablePairRatchet8880(t *testing.T) {
	// Measured at master e2018595f, twice, with the counts asserted equal.
	//
	// TWO THRESHOLDS, BOTH ASSERTED, because picking one silently would hide the
	// judgement. `args >= 2` was the original predicate. `args >= 1` is the one
	// the analogous #8768 population had to be widened to after an
	// `args == 1 && !multi` leaf (`address-set`) was found losing its second
	// instance live -- the argument that a fixed-arity leaf's "boundary is not
	// in question" answered a narrower question than the comparison asks.
	//
	// Both move together under an ordinary scope widening; they diverge when
	// something changes the arity model.
	const (
		wantArgs2 = 95
		wantArgs1 = 460
	)
	pairs2, _ := unsplittablePairs8880(2)
	pairs1, conflict1 := unsplittablePairs8880(1)
	got2, got1 := len(pairs2), len(pairs1)

	// STABILITY. A census that is not run twice is a number, not a measurement;
	// this package has produced 79/112/121 on one unchanged tree before, from
	// node-keyed dedup plus Go's randomised map order.
	p2b, _ := unsplittablePairs8880(2)
	p1b, _ := unsplittablePairs8880(1)
	if a, b := len(p2b), len(p1b); a != got2 || b != got1 {
		t.Fatalf("census is NOT STABLE across two runs in one process: "+
			"args>=2 %d then %d, args>=1 %d then %d. Fix the instrument before "+
			"reading any number off it (#8880)", got2, a, got1, b)
	}
	// STABILITY OF EVERY NUMBER REPORTED, not just the headline counts. The
	// first version of this check compared only the two lengths, and passed
	// while the multi/non-multi split drifted 87 -> 93 on an unchanged tree. A
	// stability assertion is only as wide as the values it reads.
	countMulti := func(pairs, conf map[string]bool) int {
		n := 0
		for k, isMulti := range pairs {
			if !conf[k] && isMulti {
				n++
			}
		}
		return n
	}
	_, conf1b := unsplittablePairs8880(1)
	if x, y := countMulti(pairs1, conflict1), countMulti(p1b, conf1b); x != y {
		t.Fatalf("the multi/non-multi split is NOT STABLE across two runs: "+
			"%d then %d. A pair whose multi-ness depends on which schema path "+
			"wrote last is being resolved by Go's map order (#8880)", x, y)
	}

	for _, c := range []struct {
		label     string
		got, want int
	}{{"args>=2", got2, wantArgs2}, {"args>=1", got1, wantArgs1}} {
		if c.got == c.want {
			continue
		}
		dir := "GREW"
		if c.got < c.want {
			dir = "SHRANK"
		}
		t.Errorf("unsplittable-pair population %s %s: got %d, want %d (#8880)\n"+
			"GREW means a pair was admitted to the brace-elision scope whose "+
			"container cannot split a multi-statement run -- the #8850 "+
			"address-book shape, where the scope entry alone folds two "+
			"statements into one and keeps only the first.\n"+
			"THE REMEDY DEPENDS ON THE LEAF AND `packedStatements` IS NOT ALWAYS "+
			"ONE. Measured: giving `system` packedStatements does NOT fix "+
			"`name-server`, because a multi leaf absorbs the rest of the run in "+
			"consumeNodeKeys, so the split still yields one statement and the "+
			"tail is returned whole. Of this population 89 are multi and 373 are "+
			"not; the opt-in is a candidate remedy for the 373 and is known "+
			"insufficient for the 89.\n"+
			"SHRANK means something was fixed: TIGHTEN THIS CONSTANT. Leaving it "+
			"loose gives the next regression that much room to hide.\n"+
			"THE NUMBER IS AN OVER-APPROXIMATION: a pair is only broken if a "+
			"multi-statement packed run actually reaches that container, which "+
			"this census does not model. Ceiling unmeasured in both directions.\n"+
			"NOT #8876: that is a missing parent EDGE so the container is never "+
			"created; this is a container that IS reachable and admitted.",
			c.label, dir, c.got, c.want)
	}

	// ADEQUACY, not just liveness. An empty or all-inclusive population would
	// satisfy the equality above at the wrong constant, so the predicate is
	// checked to actually DISCRIMINATE: a container that HAS opted in must be
	// absent, or the `!n.packedStatements` clause has stopped doing anything.
	set2 := pairs2
	if len(set2) == 0 {
		t.Error("population is EMPTY, so the equality above asserts nothing (#8880)")
	}
	// THESE ANCHORS MUST EXIST AT THIS BASE. The first pair written here was
	// ("address-book","address"), which is admitted only on the still-open #8866
	// -- so at master it is absent from the population for a reason that has
	// nothing to do with the clause under test, and the check could never fire.
	// A control that cannot fail is not a control. Both below are admitted AND
	// their container declares packedStatements at e2018595f; there are 32 such
	// pairs, so this is a sample of a real set rather than a lucky pick.
	for _, optedIn := range []string{"gateway local-identity", "dead-peer-detection interval"} {
		if set2[optedIn] {
			t.Errorf("%q is in the population, but its container declares "+
				"packedStatements -- the clause that makes this census mean "+
				"anything has stopped filtering (#8880)", optedIn)
		}
	}

	// LIVE MEMBERS. A counted ratchet with no demonstrated member is a number.
	// These two are adjudicated: the packed spelling does not merely lose the
	// second statement, it absorbs that statement's KEYWORD as a value.
	// TRUNCATION MODE, kept beside the injection ones so a reader does not
	// generalise from a single mode. This is issue #8880: with the `policies`
	// brace elided, the SECOND from-zone/to-zone block is discarded entirely,
	// on a clean commit with zero warnings -- the product's primary enforcement
	// surface losing a whole zone-pair policy set silently.
	t.Run("member/policies from-zone (truncation)", func(t *testing.T) {
		const rule = "policy p1 { match { source-address any; destination-address " +
			"any; application any; } then { permit; } }"
		const zones = "security-zone a { } security-zone b { } security-zone c { } " +
			"security-zone d { }"
		const blocks = "from-zone a to-zone b { " + rule + " } from-zone c to-zone d { " + rule + " }"
		pairs := func(txt string) []string {
			tree, errs := NewParser(txt).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			var out []string
			for _, p := range cfg.Security.Policies {
				out = append(out, p.FromZone+"->"+p.ToZone)
			}
			sort.Strings(out)
			return out
		}
		// BOTH ARMS CARRY THE SAME TWO BLOCKS. An earlier version of this
		// fixture gave the braced arm two rule bodies and the packed arm one,
		// so "1 vs 2" would have been the fixture rather than the fold -- right
		// by accident, which is worse than wrong.
		braced := pairs("security { zones { " + zones + " } policies { " + blocks + " } }")
		packed := pairs("security { zones { " + zones + " } policies " + blocks + " }")
		if len(braced) != 2 {
			t.Fatalf("the BRACED reference produced %v, not two zone pairs, so "+
				"this member demonstrates nothing", braced)
		}
		if strings.Join(packed, "|") == strings.Join(braced, "|") {
			t.Errorf("policies/from-zone no longer truncates (packed %v == braced "+
				"%v), so it is FIXED and must leave this cell -- and the counts "+
				"above re-derived (#8880)", packed, braced)
		}
		if len(packed) >= len(braced) {
			t.Errorf("policies/from-zone still differs but no longer LOSES a "+
				"block (packed %v, braced %v). This member is the TRUNCATION "+
				"mode; if it has become injection the mode split above is wrong "+
				"and must be re-derived, not edited (#8880)", packed, braced)
		}
	})

	for _, c := range []struct {
		pair, packed, braced string
		read                 func(*Config) []string
	}{
		{"system name-server",
			"system { name-server 1.1.1.1 name-server 8.8.8.8; }",
			"system { name-server 1.1.1.1; name-server 8.8.8.8; }",
			func(c *Config) []string { return c.System.NameServers }},
		{"system domain-search",
			"system { domain-search a.example domain-search b.example; }",
			"system { domain-search a.example; domain-search b.example; }",
			func(c *Config) []string { return c.System.DomainSearch }},
	} {
		t.Run("member/"+c.pair, func(t *testing.T) {
			compile := func(txt string) []string {
				tree, errs := NewParser(txt).Parse()
				if len(errs) > 0 {
					t.Fatalf("parse %q: %v", txt, errs)
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("compile %q: %v", txt, err)
				}
				return c.read(cfg)
			}
			braced, packed := compile(c.braced), compile(c.packed)
			// LIVENESS: both arms empty would satisfy any comparison.
			if len(braced) != 2 {
				t.Fatalf("the BRACED reference produced %v, not two entries, so "+
					"this member demonstrates nothing", braced)
			}
			if strings.Join(packed, "|") == strings.Join(braced, "|") {
				t.Errorf("%s no longer diverges (packed %v == braced %v), so it "+
					"is FIXED and must be removed from this cell -- and the "+
					"counts above re-derived (#8880)", c.pair, packed, braced)
			}
			// The specific harm: the next statement's KEYWORD became a value.
			kw := strings.SplitN(c.pair, " ", 2)[1]
			var found bool
			for _, v := range packed {
				if v == kw {
					found = true
				}
			}
			if !found {
				t.Errorf("%s still diverges but no longer absorbs %q as a VALUE "+
					"(packed %v). The failure mode changed; re-adjudicate this "+
					"member rather than leaving a stale description (#8880)",
					c.pair, kw, packed)
			}
		})
	}

	var sample []string
	for k := range set2 {
		sample = append(sample, k)
	}
	sort.Strings(sample)
	if len(sample) > 6 {
		sample = sample[:6]
	}
	multi, resolved := 0, 0
	for k, isMulti := range pairs1 {
		if conflict1[k] {
			continue // multi-ness differs by path; excluded, see below
		}
		resolved++
		if isMulti {
			multi++
		}
	}
	// A pair whose multi-ness DIFFERS between the schema paths that reach it has
	// no single remedy, so it is counted separately rather than averaged into
	// one bucket. Reported, not asserted: the count is a property of the schema,
	// not a regression, and folding it into the ratchet constant would make an
	// unrelated schema edit look like a population change.
	if len(conflict1) > 0 {
		var c []string
		for k := range conflict1 {
			c = append(c, k)
		}
		sort.Strings(c)
		t.Logf("#8880: %d pair(s) qualify with DIFFERENT multi-ness on "+
			"different schema paths, so the remedy split does not resolve for "+
			"them: %v", len(conflict1), c)
	}
	t.Logf("#8880: %d pairs at args>=2, %d at args>=1 (of %d whose remedy "+
		"resolves: %d multi, %d not), wildcard-traversing, master e2018595f; "+
		"e.g. %v", got2, got1, resolved, multi, resolved-multi, sample)
}
