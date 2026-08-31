package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #7776: `show security policies hit-count` renders a well-formed "0" for every
// row when policy-stats is disabled system-wide, which an operator reads as
// "this policy has not matched" when the truth is "this view was never asked to
// look". The counters are not read at all on that path — the same class as the
// AF_XDP capture blindness in docs/testing.md: an instrument answering
// "nothing" when it means "I cannot see".
//
// The fixture is MIXED on purpose, and that is what makes the assertion
// falsifiable rather than decorative. `plain-allow` carries no `count`, while
// `scheduled-allow` and `global-scheduled` do — and a rule with `count` IS read
// even when the system-wide knob is off. So the note must report 2 (plain-allow
// plus the implicit default policy), NOT 4. A note that said "every count reads
// 0" would be false for exactly this config, and a fixture where every rule
// looked alike could not tell the two wordings apart.
func newStatsDisabledGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// Identical to newSchedulerCounterGRPCStore's config EXCEPT the
	// `policy-stats { system-wide enable; }` stanza, which is the single
	// variable under test.
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    zones {
        security-zone dmz;
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone dmz {
            policy plain-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        from-zone trust to-zone untrust {
            policy scheduled-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
            }
        }
        global {
            policy global-scheduled {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if cfg := store.ActiveConfig(); cfg == nil || cfg.Security.PolicyStatsEnabled {
		t.Fatal("fixture precondition: policy-stats must be DISABLED, else this cell measures the control path")
	}
	return store
}

func TestHitCountTextNotesStatsDisabledRatherThanRenderingBareZeros_7776(t *testing.T) {
	s := &Server{store: newStatsDisabledGRPCStore(t), dp: &warmupPolicyGRPCDP{Manager: dataplane.New()}}

	var buf strings.Builder
	s.showPoliciesHitCount("", &buf)
	out := buf.String()

	if !strings.Contains(out, "policy-stats is disabled") {
		t.Fatalf("hit-count text renders zeros with no note that policy-stats is off; "+
			"an operator cannot tell \"no traffic matched\" from \"nothing was measured\". got:\n%s", out)
	}
	// The COUNT is the assertion, not merely the presence of a note. 2 = the
	// count-less `plain-allow` plus the implicit default policy; the two
	// `count`-bearing rules are still read and must NOT be reported as
	// unmeasured.
	if !strings.Contains(out, "note: 2 policy count(s) read 0") {
		t.Errorf("note does not report exactly 2 unmeasured rows — a rule carrying `count` is read "+
			"even with the system-wide knob off, so counting it here would make the note false. got:\n%s", out)
	}
	if !strings.Contains(out, "set security policy-stats system-wide enable") {
		t.Errorf("note omits the remedy, which is the whole reason to print it. got:\n%s", out)
	}
}

// CONTROL: with policy-stats ENABLED the note must be absent. Without this the
// cell above passes for an unconditional note that always prints, which would
// be a new false statement rather than a fix.
func TestHitCountTextOmitsTheStatsDisabledNoteWhenEnabled_7776(t *testing.T) {
	s := warmupPolicyGRPCServer(t) // its store carries `system-wide enable`

	var buf strings.Builder
	s.showPoliciesHitCount("", &buf)
	if out := buf.String(); strings.Contains(out, "policy-stats is disabled") {
		t.Errorf("hit-count text prints the stats-disabled note while policy-stats is ENABLED; "+
			"the note is unconditional and therefore says nothing. got:\n%s", out)
	}
}

// The gRPC read condition carries `readPolicy != nil` as well, so its else
// branch is reachable a SECOND way: an unloaded dataplane. Both terms of the
// `!statsEnabled && !pol.Count` guard are load-bearing for that path, and the
// fixtures above cannot see it because their dataplane is loaded.
//
// This cell closes that hole. It was written because a mutation ESCAPED:
// dropping `!pol.Count` left every cell above green, which means those cells
// were not testing the term at all. With policy-stats ENABLED and no dataplane,
// a bare `else` (or one missing `!statsEnabled`) counts every row and prints a
// note claiming policy-stats is disabled when it is enabled — a new false
// statement in place of the one #7776 removed.
func TestHitCountTextDoesNotBlameStatsWhenTheDataplaneIsUnloaded_7776(t *testing.T) {
	// statsEnabled = true, dp = nil -> readPolicy is nil, so the else branch is
	// taken for every row, and the guard is the only thing keeping the note off.
	s := &Server{store: newSchedulerCounterGRPCStore(t), dp: nil}

	var buf strings.Builder
	s.showPoliciesHitCount("", &buf)
	if out := buf.String(); strings.Contains(out, "policy-stats is disabled") {
		t.Errorf("hit-count text blames policy-stats for zeros caused by an UNLOADED dataplane, "+
			"while policy-stats is enabled — the note must name the cause it can prove. got:\n%s", out)
	}
}

// The `!pol.Count` term binds the remaining corner: policy-stats DISABLED and
// no dataplane, with a rule that carries `count`. That row read 0, but not
// because of the knob — a `count` rule is read regardless of it, so the row
// would have had a value had the dataplane been loaded. Attributing it to
// policy-stats names a cause that is not this row's cause, which is the exact
// failure #7776 exists to remove rather than relocate.
//
// This cell exists because dropping `!pol.Count` ESCAPED every other cell in
// this file. An escape is the measurement: without it the term was decoration.
func TestHitCountTextDoesNotBlameStatsForACountRuleWithNoDataplane_7776(t *testing.T) {
	s := &Server{store: newStatsDisabledGRPCStore(t), dp: nil}

	var buf strings.Builder
	s.showPoliciesHitCount("", &buf)
	out := buf.String()

	// plain-allow and the default policy ARE stats-gated, so a note is correct
	// here — what must not happen is counting the two `count`-bearing rules.
	if strings.Contains(out, "note: 4 policy count(s) read 0") {
		t.Errorf("note counts the `count`-bearing rules as stats-disabled; those are read "+
			"regardless of the knob, so their 0 has a different cause. got:\n%s", out)
	}
	if !strings.Contains(out, "note: 2 policy count(s) read 0") {
		t.Errorf("note should attribute exactly the 2 stats-gated rows (plain-allow + the "+
			"implicit default policy). got:\n%s", out)
	}
}
