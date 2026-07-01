package cli

import (
	"strings"
	"testing"
)

// TestLocalPolicySimulatorRejectsDuplicate is the #3709 RED-on-revert guard for
// the LOCAL CLI `show security match-policies` and `test policy` surfaces. Both
// route the selector vector through policymatch.ParseSelectorArgs, which now
// rejects a DUPLICATE selector. Before the fix a repeated selector silently
// LAST-won and the simulator certified a verdict for a different packet than the
// operator typed.
//
// FAIL-ON-REVERT: dropping the duplicate guard in ParseSelectorArgs makes these
// inputs return nil (with the last value applied) instead of an error, so both
// surface assertions flip red.
func TestLocalPolicySimulatorRejectsDuplicate(t *testing.T) {
	c := newPolicyMatchCLIStore(t)
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}

	dupArgs := []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "80", "source-port", "443"}

	t.Run("show", func(t *testing.T) {
		var err error
		captureStdout(t, func() { err = c.showMatchPolicies(cfg, dupArgs) })
		if err == nil || !strings.Contains(err.Error(), "specified more than once") {
			t.Fatalf("showMatchPolicies(dup) err = %v, want a duplicate-selector error", err)
		}
	})
	t.Run("test", func(t *testing.T) {
		var err error
		captureStdout(t, func() { err = c.testPolicy(dupArgs) })
		if err == nil || !strings.Contains(err.Error(), "specified more than once") {
			t.Fatalf("testPolicy(dup) err = %v, want a duplicate-selector error", err)
		}
	})
}
