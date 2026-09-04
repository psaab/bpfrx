package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8289 END TO END: an operator's anchored `deny-commands` must not be
// defeated by appending a sibling keyword to the denied command.
//
// This is the cell that makes the cmdtree change a SECURITY fix rather than a
// tidy-up, and it is written here because the bypass needs BOTH halves: the
// authorizer decides on the joined canonical string
// (`rules.Evaluate(strings.Join(canon, " "))`) while the dispatcher runs
// something shorter. Neither half is wrong alone.
//
// WHY THE ANCHORED FORM IS THE ONE THAT MATTERS. Matching is unanchored partial
// by default (TestMatchingIsUnanchoredPartial7172), so a plain
// `deny-commands "show version"` still matches inside the longer string and
// never had the hole. The operator who followed Junos's own advice — "You must
// use anchors when specifying complex regular expressions" — is the one who got
// bypassed. A test using only the unanchored form would pass on the broken
// code, which is exactly the shape of test that let this survive.
func TestAnchoredDenySurvivesATrailingSibling8289(t *testing.T) {
	for _, tc := range []struct {
		deny     string
		line     string
		wantDeny bool
		why      string
	}{
		{"^show version$", "show version", true, "the baseline the operator wrote the rule for"},
		{"^show version$", "show version configuration", true,
			"THE BYPASS: the box runs `show version` either way, so appending a " +
				"sibling keyword must not escape a deny on it"},
		{"^show version$", "show ver conf", true,
			"prefix abbreviations canonicalize to the same words, so the bypass " +
				"must not survive being spelled shorter"},

		// Unanchored: already denied before this fix. Kept so a regression that
		// re-broke only the anchored form cannot hide behind these.
		{"show version", "show version", true, "unanchored, matched a substring already"},
		{"show version", "show version configuration", true, "unanchored, matched already"},

		// CONTROLS: the deny must stay narrow. A fix that denied more would
		// satisfy every row above and lock operators out of lawful commands.
		{"^show version$", "show configuration", false,
			"a DIFFERENT command must not be caught by this rule"},
		{"^show version$", "show route", false, "unrelated command"},
		{"^show route$", "show version", false, "the rule must bind to its own command"},
	} {
		t.Run(tc.deny+" / "+tc.line, func(t *testing.T) {
			rules, err := config.CompileLoginRegexes(
				config.LoginRegexPlainFamily, "", false, tc.deny, true)
			if err != nil {
				t.Fatalf("CompileLoginRegexes(%q): %v", tc.deny, err)
			}
			err = evaluateCommandRegex(rules, "restricted", tc.line, "")
			if tc.wantDeny && err == nil {
				t.Fatalf("deny=%q line=%q was ALLOWED, want denied.\n%s",
					tc.deny, tc.line, tc.why)
			}
			if !tc.wantDeny && err != nil {
				t.Fatalf("deny=%q line=%q was DENIED (%v), want allowed.\n%s\n"+
					"Over-denying locks an operator out of a lawful command.",
					tc.deny, tc.line, err, tc.why)
			}
		})
	}
}
