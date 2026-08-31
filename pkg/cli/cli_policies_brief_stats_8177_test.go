package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #8177 row 3: the `show security policies brief` Hits column renders a
// well-formed "0" for every row when policy-stats is off, with nothing saying
// the column was never read. Same defect #7776 fixed on the hit-count table,
// one dispatch branch over.
func TestCLIBriefNotesStatsDisabled_8177(t *testing.T) {
	store := newMixedStatsCLIStore(t, false)

	// The fixture must be MIXED, or the count below cannot tell a precise note
	// from a blanket one — a note claiming every count reads 0 is false for any
	// config where some rule carries `count`.
	cfg := store.ActiveConfig()
	var counted, uncounted int
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			if pol.Count {
				counted++
			} else {
				uncounted++
			}
		}
	}
	if counted == 0 || uncounted == 0 {
		t.Fatalf("fixture is not mixed (counted=%d uncounted=%d)", counted, uncounted)
	}

	c := &CLI{store: store, dp: &policyCounterCLIDP{Manager: dataplane.New()}}
	out := captureStdout(t, func() { _ = c.handleShowSecurity([]string{"policies", "brief"}) })

	// 1, not 2. `allow-web` carries no count; `counted-web` is read even with
	// the knob off; and the brief view renders NO implicit default-policy row,
	// which the hit-count table does. The surfaces legitimately count different
	// populations, so the shared invariant is the WORDING, not the number —
	// asserting the hit-count table's 2 here would demand a wrong number.
	if !strings.Contains(out, "note: 1 policy count(s) read 0 because policy-stats is disabled") {
		t.Errorf("brief view does not carry the stats-disabled note with its own count.\ngot:\n%s", out)
	}
	if !strings.Contains(out, "set security policy-stats system-wide enable") {
		t.Errorf("note omits the remedy, which is the whole reason to print it.\ngot:\n%s", out)
	}
}

// CONTROL: an unconditional note is a new false statement, not a fix.
func TestCLIBriefOmitsTheNoteWhenStatsEnabled_8177(t *testing.T) {
	store := newMixedStatsCLIStore(t, true)
	c := &CLI{store: store, dp: &policyCounterCLIDP{Manager: dataplane.New()}}
	out := captureStdout(t, func() { _ = c.handleShowSecurity([]string{"policies", "brief"}) })
	if strings.Contains(out, "policy-stats is disabled") {
		t.Errorf("brief view prints the stats-disabled note while policy-stats is ENABLED.\ngot:\n%s", out)
	}
}
