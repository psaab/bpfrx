package config

import "testing"

// #8690: `security policies … policy <p> scheduler-name` — the normalizer is the
// WRONG REMEDY for this site, and three measurements were needed to establish
// that because each earlier one used a different spelling.
//
// WHERE THE DUPLICATE SHAPE COMES FROM, stated precisely because an earlier
// version of this comment got it wrong. It is NOT what a CLI session produces:
// flat `set … policy p1 match …` followed by `set … policy p1 scheduler-name S`
// MERGES into one policy carrying both, measured in both orderings and on both
// compile paths. Attributing the duplicate to a pair of `set` lines was hand-
// written hierarchical text standing in for the flat-set spelling — the trap
// CLAUDE.md names ("ALWAYS use ParseSetCommand() + tree.SetPath(), NEVER
// NewParser()"), and the third instance of it on this one file in a day.
//
// It arrives as a config FILE with the two statements as siblings: hand-edited,
// written by an older build, or pushed by an un-upgraded primary. That is
// narrower than "an operator typed two set lines" — and it is exactly the
// population Store.Load and Store.SyncApply exist to accept, which is why the
// lenient path is still the right place to point at.
//
// THE HARM IS REAL. On the LENIENT path — which is what production uses on Load and
// SyncApply (configstore/store.go: boot config load and HA config sync) — that
// compiles to TWO policies named p1:
//
//	pol#1  sched=""   src=[any]  PERMIT    <- the operator's policy, schedule LOST
//	pol#2  sched=""   src=[]     DENY      <- a spurious match-less duplicate
//
// So a policy written as TIME-LIMITED runs PERMANENTLY ACTIVE. That much of the
// original forwarding concern was right.
//
// BUT NORMALIZING DOES NOT FIX IT. With ("policy","scheduler-name") ADMITTED —
// and that admission is load-bearing: at master, with the pair excluded, pol#2
// carries sched="" under BOTH skipNorm settings, because the pass touches 0
// nodes and the two runs are the same — the pass moves the packed tail into the
// DUPLICATE's body:
//
//	pol#1  sched=""   src=[any]  PERMIT    <- STILL scheduleless
//	pol#2  sched="S"  src=[]     DENY      <- the schedule lands here
//
// The schedule is restored onto the wrong policy. The defect is that the second
// `policy p1 …` statement DUPLICATES rather than merging — a policy-level
// defect (#3473 duplicate policy name; lane-8526's #8436 duplicate-block work),
// not a brace-elision one. Normalizing this pair changes only the inert
// census spelling, where the policy has no body and does nothing either way.
//
// THAT IS WHY IT MUST NOT BE SWEPT: admitting it removes two lines from the
// #2419 inventory and looks like progress, while the reachable harm is
// untouched. A remedy that clears the evidence without fixing the defect is
// worse than none.
//
// Why the earlier measurements disagreed, recorded so the next reader does not
// repeat them: the STRICT path REJECTS the elided spelling, so cfg is nil and
// there is nothing to inspect — a gate firing is the absence of a compiled
// result, not evidence about one. And any skipNorm comparison taken while the
// pair is EXCLUDED is vacuous, because the pass touches 0 nodes and both sides
// are the same run.
func TestSchedulerNameNormalizingRestoresTheScheduleOntoTheWrongPolicy8690(t *testing.T) {
	const sched = `schedulers { scheduler S { daily { start-time 09:00; stop-time 17:00; } } }`
	const head = `security { zones { security-zone trust; security-zone untrust; } `
	const body = `match { source-address any; destination-address any; application any; } then { permit; }`

	// The reachable spelling: a real policy, plus the brace-elided statement a
	// second `set` line produces.
	reachable := sched + head + `policies { from-zone trust to-zone untrust { policy p1 { ` + body + ` } policy p1 scheduler-name S; } } }`
	// The reference: the schedule written inside the policy.
	reference := sched + head + `policies { from-zone trust to-zone untrust { policy p1 { ` + body + ` scheduler-name S; } } } }`

	policies := func(t *testing.T, text string) []*Policy {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tree, lenientCompileOpts())
		if err != nil || cfg == nil {
			t.Fatalf("the LENIENT path must accept this — that is the whole point of it: %v", err)
		}
		var out []*Policy
		for _, z := range cfg.Security.Policies {
			out = append(out, z.Policies...)
		}
		return out
	}

	// POSITIVE HALF: written inside the policy, the schedule is carried. Without
	// this the comparison below is between two empties.
	ref := policies(t, reference)
	if len(ref) != 1 || ref[0].SchedulerName != "S" {
		t.Fatalf("the reference spelling must produce ONE policy carrying the schedule; got %d, sched=%q",
			len(ref), func() string {
				if len(ref) > 0 {
					return ref[0].SchedulerName
				}
				return ""
			}())
	}

	got := policies(t, reachable)
	if len(got) != 2 {
		t.Fatalf("the reachable spelling must produce TWO policies (the operator's, plus the "+
			"duplicate the elided statement creates); got %d. If it now MERGES, the "+
			"policy-level defect was fixed and this site's classification needs "+
			"re-deriving rather than deleting", len(got))
	}

	// THE HARM: the operator's policy — the one with the match criteria — has
	// lost its schedule.
	var operators *Policy
	for _, p := range got {
		if len(p.Match.SourceAddresses) > 0 {
			operators = p
		}
	}
	if operators == nil {
		t.Fatal("neither compiled policy carries the match criteria; the fixture no longer " +
			"distinguishes the operator's policy from the duplicate")
	}
	if operators.SchedulerName != "" {
		t.Fatalf("the operator's policy carries scheduler-name %q — the drop this site is "+
			"classified on no longer happens, so the classification needs re-deriving",
			operators.SchedulerName)
	}

	// AND THE REASON NORMALIZING IS THE WRONG REMEDY: the pass would put the
	// schedule on the OTHER policy. Pinned as the current state, so that
	// admitting the pair reds here and says why it does not help.
	if compactNormalizeInScope("policy", "scheduler-name") {
		t.Fatal("(\"policy\", \"scheduler-name\") has been ADMITTED to the normalizer's " +
			"scope. Measured, that does NOT fix this site: the pass moves the packed tail " +
			"into the DUPLICATE policy's body, so the operator's policy stays scheduleless " +
			"and permanently active while the schedule lands on a match-less deny.\n\n" +
			"It removes two lines from the #2419 inventory and looks like progress. The " +
			"actual defect is that the second `policy p1 …` statement DUPLICATES rather " +
			"than merging — #3473 / the #8436 duplicate-block work — and that is what has " +
			"to be fixed. See the `wrong-remedy` entry in " +
			"testdata/compact_block_permanent_exclusions_8690.txt.")
	}
}
