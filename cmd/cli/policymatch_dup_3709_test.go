package main

import (
	"strings"
	"testing"
)

// TestRemotePolicySimulatorRejectsDuplicate is the #3709 RED-on-revert guard for
// the REMOTE CLI `show security match-policies` and `test policy` surfaces. Both
// route the selector vector through policymatch.ParseSelectorArgs, which now
// rejects a DUPLICATE selector, so neither surface forwards an ambiguous (silent
// last-win) query to the backend.
//
// FAIL-ON-REVERT: dropping the duplicate guard lets the malformed input build a
// request/topic and dial the backend with no error, flipping the want-error +
// no-RPC assertions red.
func TestRemotePolicySimulatorRejectsDuplicate(t *testing.T) {
	dupArgs := []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "80", "source-port", "443"}

	t.Run("show", func(t *testing.T) {
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		err := c.showMatchPolicies(dupArgs)
		if err == nil || !strings.Contains(err.Error(), "specified more than once") {
			t.Fatalf("showMatchPolicies(dup) err = %v, want a duplicate-selector error", err)
		}
		if fake.matchPoliciesCalls != 0 {
			t.Fatalf("MatchPolicies issued %d times on duplicate input; want 0", fake.matchPoliciesCalls)
		}
	})
	t.Run("test", func(t *testing.T) {
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		err := c.testPolicy(dupArgs)
		if err == nil || !strings.Contains(err.Error(), "specified more than once") {
			t.Fatalf("testPolicy(dup) err = %v, want a duplicate-selector error", err)
		}
		if fake.showTextCalls != 0 {
			t.Fatalf("ShowText issued %d times on duplicate input; want 0", fake.showTextCalls)
		}
	})
}

// TestRemoteTestPolicyRejectsCommaZone is the #3709 RED-on-revert guard for the
// comma-in-zone-name round-trip gap on the REMOTE `test policy` surface. Config
// permits a zone name containing a comma (only exact reserved tokens are
// rejected), but the legacy `test-policy:` ShowText topic is a comma/equals
// delimited key=value string that cannot carry such a name — the server would
// split it into bogus segments and misparse it. The surface now fails closed
// with a clear error before dialing the backend, rather than silently corrupting
// the query.
//
// FAIL-ON-REVERT: removing the delimiter guard lets testPolicy build a corrupted
// topic and call ShowText, flipping the want-error + no-RPC assertions red.
func TestRemoteTestPolicyRejectsCommaZone(t *testing.T) {
	cases := [][]string{
		{"from-zone", "trust,blue", "to-zone", "untrust"},
		{"from-zone", "trust", "to-zone", "a=b"},
	}
	for _, args := range cases {
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		err := c.testPolicy(args)
		if err == nil || !strings.Contains(err.Error(), "cannot carry") {
			t.Fatalf("testPolicy(%v) err = %v, want a delimiter-round-trip error", args, err)
		}
		if fake.showTextCalls != 0 {
			t.Fatalf("ShowText issued %d times on un-round-trippable zone; want 0", fake.showTextCalls)
		}
	}
}
