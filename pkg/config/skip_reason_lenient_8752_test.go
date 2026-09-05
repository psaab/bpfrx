package config

import "testing"

// #8752: a conservation exemption justified by "REFUSED at commit" is a
// STRICT-path fact, and dupConservationSkipped8436 governs BOTH compile paths.
//
// `Store.Load` and `Store.SyncApply` compile leniently — that is the whole point
// of them, since they read configurations the operator did not just author — and
// the lenient path does not refuse. So an entry skipped on a rejection is
// unexamined on the path where a conservation defect actually bites, and a skip
// with a stated reason reads as settled: nobody re-derives it.
//
// This pins the LENIENT-path behaviour of the three entries in that group, so
// the annotation is a measurement rather than prose. Two of them accept the
// duplicate and silently keep both objects; one refuses on both paths and is
// correctly skipped. If any of those three answers changes, this reds — and a
// new entry added to that group owes the same measurement before its reason can
// say "refused".
func TestSkippedOnRefusalStillNeedsTheLenientAnswer8752(t *testing.T) {
	cases := []struct {
		name          string
		text          string
		lenientAccept bool
		wantObjects   int
	}{
		{
			name: "security policies from-zone <a> <b> <c> policy",
			text: `security { zones { security-zone trust; security-zone untrust; }
				policies { from-zone trust to-zone untrust {
					policy p1 { match { source-address any; destination-address any; application any; } then { permit; } }
					policy p1 { then { deny; } }
				} } }`,
			lenientAccept: true, wantObjects: 2,
		},
		{
			name: "security policies global policy",
			text: `security { policies { global {
					policy g1 { match { source-address any; destination-address any; application any; } then { permit; } }
					policy g1 { then { deny; } }
				} } }`,
			lenientAccept: true, wantObjects: 2,
		},
		{
			// Correctly skipped: refused on BOTH paths, so the exemption does
			// not rest on a strict-path-only fact.
			name: "class-of-service fairness rss-expectation interface <i> queue",
			text: `class-of-service { fairness { rss-expectation { interface ge-0/0/0 {
					queue 0 { expectation balanced; }
					queue 0 { expectation any; }
				} } } }`,
			lenientAccept: false, wantObjects: 0,
		},
	}

	for _, c := range cases {
		tree, perrs := NewParser(c.text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: fixture must parse: %v", c.name, perrs)
		}
		// The strict path is expected to refuse all three — that is the stated
		// reason for the skip, and asserting it keeps this cell honest about
		// what it is adding rather than re-litigating.
		if _, err := compileConfigWithOpts(tree, compileOpts{}); err == nil {
			t.Errorf("%s: the STRICT path accepted the duplicate, so the skip entry's stated "+
				"reason (\"REFUSED at commit\") is no longer true and the entry needs "+
				"re-deriving on both paths", c.name)
		}

		cfg, err := compileConfigWithOpts(tree, lenientCompileOpts())
		gotAccept := err == nil && cfg != nil
		if gotAccept != c.lenientAccept {
			t.Errorf("%s: LENIENT accept = %v, want %v. That is the path Store.Load and "+
				"Store.SyncApply use, so a change here changes whether a config already on "+
				"disk loads with a silent duplicate", c.name, gotAccept, c.lenientAccept)
			continue
		}
		if !gotAccept {
			continue
		}
		n := 0
		for _, z := range cfg.Security.Policies {
			n += len(z.Policies)
		}
		n += len(cfg.Security.GlobalPolicies)
		if n != c.wantObjects {
			t.Errorf("%s: lenient compile produced %d objects, want %d. Fewer means the fold "+
				"now merges (good — update this expectation and the skip annotation "+
				"together); more means it duplicates further", c.name, n, c.wantObjects)
		}
	}
}

// TestTheDuplicatePolicyPoisonsTheSnapshot8752 pins the CONSEQUENCE of the
// duplicate that the cell above pins the EXISTENCE of.
//
// lane-8015's cell establishes that the lenient path accepts the duplicate and
// produces two objects. That is the finding. This one records what those two
// objects DO, because the census annotation originally said "the duplicate
// WINS", and a reader acting on that would make the FIRST occurrence
// authoritative -- which leaves the real harm in place.
//
// The spurious policy sits second and never wins a first-match evaluation. What
// matters is that compiling it sets LenientContentDropped, because
// policies_lower.go poisons such a rule with the __unsupported__ sentinel so
// the Rust integrity preflight rejects the WHOLE snapshot (previous-good
// retained; fresh-boot default-deny). The operator's entire configuration fails
// to load -- a strictly worse and differently-shaped outcome than a policy set
// that merely evaluates wrong.
//
// THE OTHER HALF OF THAT CHAIN IS ALREADY PINNED, AND THIS CELL DELIBERATELY
// DOES NOT RE-ASSERT IT. The claim spans two packages, so it needs two cells:
//
//	this cell (pkg/config)                        duplicate  -> LenientContentDropped
//	TestLenientWidenedPolicyLowersToSentinel5575  flag       -> __unsupported__ sentinel
//	 (pkg/dataplane/userspace/lenient_permit_widening_5575_test.go)
//
// Cited as a CELL rather than as a line in policies_lower.go, because a line
// number is prose the moment the file moves and a cell is runnable. That is the
// same rule the register applies to its own `wrong-remedy` class -- a claim
// without a runnable cite is prose -- turned on this comment. The original
// draft of this note cited policies_lower.go:194 and would have rotted at the
// next edit to that file.
//
// If this cell is ever the ONLY one left of the two, the consequence paragraph
// in the census annotation has become unfalsifiable again: half a cross-package
// chain asserts nothing about the chain.
//
// This cell is therefore the acceptance criterion for the #8752 fold: folding
// the occurrences into one policy carrying the operator's criteria must clear
// LenientContentDropped. An implementation that removes the duplicate OBJECT
// but leaves the flag set has not fixed the thing operators feel.
func TestTheDuplicatePolicyPoisonsTheSnapshot8752(t *testing.T) {
	const text = `security {
  policies {
    from-zone trust to-zone untrust {
      policy p1 { match { source-address 10.0.0.0/8; destination-address any; application any; } then { permit; } }
      policy p1 { then { deny; } }
    }
  }
  zones { security-zone trust { } security-zone untrust { } }
}`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("the TOLERANT path must accept this (it is the path Store.Load uses): %v", err)
	}
	var pols []*Policy
	for _, pr := range cfg.Security.Policies {
		pols = append(pols, pr.Policies...)
	}
	if len(pols) != 2 {
		t.Fatalf("want the duplicate present as 2 objects, got %d. If this is now 1 the "+
			"#8752 fold has landed — re-point this cell at the folded policy and assert "+
			"LenientContentDropped is FALSE, which is the property the fold exists to "+
			"deliver", len(pols))
	}
	// The operator's occurrence keeps its criteria and is NOT poisoned.
	if got := pols[0].Match.SourceAddresses; len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Errorf("policy[0] lost the operator's source criteria: %v", got)
	}
	if pols[0].LenientContentDropped {
		t.Errorf("policy[0] is poisoned, but it carries a complete match — the harm would " +
			"then not be attributable to the duplicate at all")
	}
	// The spurious occurrence is match-ANY (every dimension empty) and second.
	if n := len(pols[1].Match.SourceAddresses) + len(pols[1].Match.DestinationAddresses) +
		len(pols[1].Match.Applications); n != 0 {
		t.Errorf("policy[1] has %d match tokens, want 0. The annotation's \"match-less\" "+
			"description, and the match-ANY reading that follows from it, depend on this", n)
	}
	// THE CLAIM THAT MATTERS. If this stops holding, the census annotation's
	// consequence paragraph is wrong and the #8752 fix is aimed at the wrong
	// harm.
	if !pols[1].LenientContentDropped {
		t.Errorf("policy[1] does NOT carry LenientContentDropped. The census annotation " +
			"(duplicate_block_conservation_inventory_8436.go) states that this flag is what " +
			"makes policies_lower.go poison the rule with the __unsupported__ sentinel, so " +
			"the Rust preflight rejects the WHOLE snapshot and the operator's config does " +
			"not load. Without the flag that entire consequence paragraph is unsupported — " +
			"correct the annotation rather than deleting this assertion (#8752)")
	}
}
