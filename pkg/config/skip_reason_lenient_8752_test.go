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
