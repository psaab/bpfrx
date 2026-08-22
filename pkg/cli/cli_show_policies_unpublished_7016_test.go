// #7016 (local CLI): `show security policies hit-count` and the `brief` table
// must not report an UNPUBLISHED per-rule counter as a counter read FAILURE,
// and must not render its 0 as an authoritative hit count.
//
// #6743 activated the #3965 bulk reader, whose unpublished-per-rule signal is
// ErrPolicyCounterUnpublished. Both tables folded it into readErr and printed
// "warning: policy counter read failed" — naming a fault that does not exist —
// over a "0" an operator reads as "this rule matched no traffic". The window is
// reachable before the first 1 Hz status poll lands (the shim is loaded, so
// IsLoaded() is already true) and under config skew after a non-abort-class
// apply failure (#5679).
//
// FAIL-ON-REVERT: restoring `} else if readErr == nil { readErr = err }` at any
// read site brings the "read failed" warning back and the assertions go RED. A
// genuine read failure must still warn — the control below.
package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// warmupPolicyCLIDP is LOADED with an EMPTY bulk snapshot — the measured
// warm-up state of the real userspace Manager (pinned in
// pkg/dataplane/userspace TestWarmUpBulkSnapshotIsEmptyAndReadsUnpublished).
// The per-policy fallback panics: the adapter carries the bulk probe in
// production, so a fallback call would mean this exercises a different path.
type warmupPolicyCLIDP struct {
	dataplane.DataPlane
}

func (d *warmupPolicyCLIDP) IsLoaded() bool { return true }

func (d *warmupPolicyCLIDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return map[uint32]dataplane.CounterValue{}, nil
}

func (d *warmupPolicyCLIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	panic("per-policy fallback must not run: the bulk probe resolves")
}

// bulkFailPolicyCLIDP is LOADED and its bulk snapshot read genuinely FAILS.
type bulkFailPolicyCLIDP struct {
	dataplane.DataPlane
}

func (d *bulkFailPolicyCLIDP) IsLoaded() bool { return true }

func (d *bulkFailPolicyCLIDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return nil, errors.New("counter bridge degraded")
}

func (d *bulkFailPolicyCLIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	panic("per-policy fallback must not run: the bulk probe resolves")
}

// newUnpublishedPolicyCLIStore extends the shared hit-count fixture with a
// GLOBAL policy. Without one, the global-rule read site in each table is never
// reached, so a mutation there cannot be observed -- both global cells came
// back GREEN on the #7016 mutation matrix against the shared fixture, which
// measures the fixture, not the code.
func newUnpublishedPolicyCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies from-zone trust to-zone untrust policy allow-web match source-address any",
		"security policies from-zone trust to-zone untrust policy allow-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy allow-web match application any",
		"security policies from-zone trust to-zone untrust policy allow-web then permit",
		"security policies global policy global-allow match source-address any",
		"security policies global policy global-allow match destination-address any",
		"security policies global policy global-allow match application any",
		"security policies global policy global-allow then permit",
		"security policy-stats system-wide enable",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || !cfg.Security.PolicyStatsEnabled {
		t.Fatal("policy-stats precondition not met")
	}
	if len(cfg.Security.GlobalPolicies) == 0 {
		t.Fatal("global policy precondition not met: the global read site would not be exercised")
	}
	return store
}

func TestShowPoliciesHitCountMarksUnpublishedRatherThanWarning(t *testing.T) {
	store := newUnpublishedPolicyCLIStore(t)
	c := &CLI{store: store, dp: &warmupPolicyCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(store.ActiveConfig(), "", ""); err != nil {
			t.Fatalf("showPoliciesHitCount() error = %v", err)
		}
	})

	if strings.Contains(out, "policy counter read failed") {
		t.Errorf("hit-count table claims a counter READ FAILED for an unpublished counter; nothing failed (#7016). got:\n%s", out)
	}
	if !strings.Contains(out, "not yet published") {
		t.Errorf("hit-count table lacks the unpublished note; the omission must be explained, not silent. got:\n%s", out)
	}
	// The zone-pair rule, the GLOBAL rule, and the implicit default-policy row
	// all read n/a -- one assertion per read site in the table.
	for _, name := range []string{"allow-web", "global-allow", dataplane.DefaultPolicyName} {
		row := cliRowContaining(out, name)
		if row == "" {
			t.Fatalf("%s row missing from the hit-count table; got:\n%s", name, out)
		}
		if !strings.Contains(row, "n/a") {
			t.Errorf("%s row = %q, want an n/a count cell rather than an authoritative 0", name, row)
		}
	}
}

func TestShowPoliciesBriefMarksUnpublishedRatherThanWarning(t *testing.T) {
	c := &CLI{store: newUnpublishedPolicyCLIStore(t), dp: &warmupPolicyCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies", "brief"}); err != nil {
			t.Fatalf("handleShowSecurity(policies brief) error = %v", err)
		}
	})

	if strings.Contains(out, "policy counter read failed") {
		t.Errorf("brief table claims a counter READ FAILED for an unpublished counter; nothing failed (#7016). got:\n%s", out)
	}
	if !strings.Contains(out, "not yet published") {
		t.Errorf("brief table lacks the unpublished note; got:\n%s", out)
	}
	for _, name := range []string{"allow-web", "global-allow"} {
		row := cliRowContaining(out, name)
		if row == "" {
			t.Fatalf("%s row missing from the brief table; got:\n%s", name, out)
		}
		if !strings.Contains(row, "n/a") {
			t.Errorf("%s brief row = %q, want an n/a hits cell rather than an authoritative 0\nfull:\n%s", name, row, out)
		}
	}
}

// CONTROL: a genuine bulk-snapshot read failure must still print the #3408
// warning on BOTH tables. Without this, "no warning" could be satisfied by
// dropping the warning entirely.
func TestShowPoliciesStillWarnsOnGenuineReadError(t *testing.T) {
	store := newUnpublishedPolicyCLIStore(t)

	hit := captureStdout(t, func() {
		c := &CLI{store: store, dp: &bulkFailPolicyCLIDP{}}
		if err := c.showPoliciesHitCount(store.ActiveConfig(), "", ""); err != nil {
			t.Fatalf("showPoliciesHitCount() error = %v", err)
		}
	})
	if !strings.Contains(hit, "policy counter read failed") {
		t.Errorf("hit-count table lost its #3408 read-failure warning; got:\n%s", hit)
	}

	brief := captureStdout(t, func() {
		c := &CLI{store: store, dp: &bulkFailPolicyCLIDP{}}
		if err := c.handleShowSecurity([]string{"policies", "brief"}); err != nil {
			t.Fatalf("handleShowSecurity(policies brief) error = %v", err)
		}
	})
	if !strings.Contains(brief, "policy counter read failed") {
		t.Errorf("brief table lost its #3408 read-failure warning; got:\n%s", brief)
	}
}

func cliRowContaining(out, needle string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}
