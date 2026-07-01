package cli

import (
	"strings"
	"testing"
)

// TestLocalPolicySimulatorStrictParse is the #3696 RED-on-revert guard for the
// LOCAL CLI `show security match-policies` and `test policy` surfaces. Both used
// to parse selectors with a per-surface `if i+1 < len(args)` loop and no default
// arm, so a value-taking selector present WITHOUT a value silently widened the
// query to the wildcard and an unknown/misspelled selector token was silently
// dropped. Both now route through the strict SSOT policymatch.ParseSelectorArgs.
//
// FAIL-ON-REVERT: restoring the loose per-surface loop makes the missing-value,
// unknown-selector, and empty-typed-value cases return nil (a silently widened /
// dropped query) instead of an error, flipping the want-error cases red.
func TestLocalPolicySimulatorStrictParse(t *testing.T) {
	c := newPolicyMatchCLIStore(t)
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}

	cases := []struct {
		name    string
		args    []string
		wantErr string // "" = valid, want no error
	}{
		{"missing value trailing selector", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port"}, "requires a value"},
		{"unknown selector typo", []string{"from-zone", "trust", "to-zone", "untrust", "protcol", "tcp"}, "unknown selector"},
		{"empty typed value", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", ""}, "requires a value"},
		{"valid full query", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "443"}, ""},
	}
	for _, tc := range cases {
		t.Run("show/"+tc.name, func(t *testing.T) {
			var err error
			captureStdout(t, func() { err = c.showMatchPolicies(cfg, tc.args) })
			checkStrict3696(t, "showMatchPolicies", tc.args, err, tc.wantErr)
		})
		t.Run("test/"+tc.name, func(t *testing.T) {
			var err error
			captureStdout(t, func() { err = c.testPolicy(tc.args) })
			checkStrict3696(t, "testPolicy", tc.args, err, tc.wantErr)
		})
	}
}

func checkStrict3696(t *testing.T, fn string, args []string, err error, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil {
			t.Fatalf("%s(%v) err = %v, want nil (valid query regressed)", fn, args, err)
		}
		return
	}
	if err == nil {
		t.Fatalf("%s(%v) err = nil, want %q (silent widen / drop)", fn, args, wantErr)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("%s(%v) err = %v, want substring %q", fn, args, err, wantErr)
	}
}
