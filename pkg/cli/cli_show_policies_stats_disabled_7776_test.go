package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #7776: with policy-stats disabled system-wide, the local-CLI hit-count table
// renders a well-formed "0" for every unmeasured row. An operator reads that as
// "this policy has not matched" when the truth is "this view was never asked to
// look" — reported from the field on a node that was demonstrably denying
// packets while this table showed all zeros.
//
// The fixture is MIXED, which is what makes the assertion discriminating: a
// rule carrying `count` IS read even when the system-wide knob is off, so the
// note must report only the rules that were genuinely not measured. A uniform
// fixture (every rule count-less) cannot tell the precise wording from a
// blanket "every count reads 0", and the blanket version would be FALSE for
// this config.
func newMixedStatsCLIStore(t *testing.T, statsEnabled bool) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	cmds := []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		// Not measured when the knob is off.
		"security policies from-zone trust to-zone untrust policy allow-web match source-address any",
		"security policies from-zone trust to-zone untrust policy allow-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy allow-web match application any",
		"security policies from-zone trust to-zone untrust policy allow-web then permit",
		// Carries `count`, so it IS measured regardless of the knob.
		"security policies from-zone trust to-zone untrust policy counted-web match source-address any",
		"security policies from-zone trust to-zone untrust policy counted-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy counted-web match application any",
		"security policies from-zone trust to-zone untrust policy counted-web then permit",
		"security policies from-zone trust to-zone untrust policy counted-web then count",
	}
	if statsEnabled {
		cmds = append(cmds, "security policy-stats system-wide enable")
	}
	for _, cmd := range cmds {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Security.PolicyStatsEnabled != statsEnabled {
		t.Fatalf("PolicyStatsEnabled precondition not met (want %v)", statsEnabled)
	}
	return store
}

func TestCLIHitCountNotesStatsDisabledRatherThanRenderingBareZeros_7776(t *testing.T) {
	store := newMixedStatsCLIStore(t, false)
	cfg := store.ActiveConfig()

	// Precondition: the mixed shape actually exists, or the count below
	// would be measuring a uniform fixture and prove nothing about precision.
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
		t.Fatalf("fixture is not mixed (counted=%d uncounted=%d); this cell cannot "+
			"distinguish the precise note from a blanket one", counted, uncounted)
	}

	c := &CLI{store: store, dp: &policyCounterCLIDP{Manager: dataplane.New()}}
	var callErr error
	out := captureStdout(t, func() { callErr = c.showPoliciesHitCount(cfg, "", "") })
	if callErr != nil {
		t.Fatalf("showPoliciesHitCount() error = %v", callErr)
	}

	if !strings.Contains(out, "policy-stats is disabled") {
		t.Fatalf("hit-count table renders zeros with no note that policy-stats is off; "+
			"an operator cannot tell \"no traffic matched\" from \"nothing was measured\". got:\n%s", out)
	}
	// 2 = `allow-web` (no count) + the implicit default policy. `counted-web`
	// is read and must NOT be reported as unmeasured.
	if !strings.Contains(out, "note: 2 policy count(s) read 0") {
		t.Errorf("note does not report exactly 2 unmeasured rows; a rule carrying `count` is read "+
			"even with the system-wide knob off, so counting it would make the note false. got:\n%s", out)
	}
	if !strings.Contains(out, "set security policy-stats system-wide enable") {
		t.Errorf("note omits the remedy, which is the whole reason to print it. got:\n%s", out)
	}
}

// CONTROL: with policy-stats ENABLED the note must be absent. Without this the
// cell above passes for an unconditional note, which would be a new false
// statement rather than a fix.
func TestCLIHitCountOmitsTheStatsDisabledNoteWhenEnabled_7776(t *testing.T) {
	store := newMixedStatsCLIStore(t, true)
	cfg := store.ActiveConfig()
	c := &CLI{store: store, dp: &policyCounterCLIDP{Manager: dataplane.New()}}

	var callErr error
	out := captureStdout(t, func() { callErr = c.showPoliciesHitCount(cfg, "", "") })
	if callErr != nil {
		t.Fatalf("showPoliciesHitCount() error = %v", callErr)
	}
	if strings.Contains(out, "policy-stats is disabled") {
		t.Errorf("hit-count table prints the stats-disabled note while policy-stats is ENABLED; "+
			"the note is unconditional and therefore says nothing. got:\n%s", out)
	}
}
