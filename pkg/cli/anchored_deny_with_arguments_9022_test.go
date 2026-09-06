package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9022: AN ANCHORED deny-commands REGEX WAS DEFEATED BY APPENDING ANY
// ARGUMENT. With `deny-commands "^show log$"` the bare form was denied and
// every argument-bearing form RAN:
//
//	show log 100        -> journalctl -u xpfd -n 100
//	show log messages   -> tails a syslog file
//	show log FOO extra  -> `extra` silently dropped, tails a syslog file
//
// `Canonicalize`'s AcceptsArgs arm passes trailing tokens through (#8304,
// deliberately, so a restricted class is not refused outright), so the string
// the rule matched carried them and `$` no longer matched. Any AcceptsArgs node
// under an anchored rule was affected — including `show configuration system`,
// which discloses the whole committed stanza.
//
// This is NOT #8289, which is the trailing-SIBLING-keyword case: that yields
// CanonicalUnknown and already fails closed. Both are covered here, because a
// fix to one must not regress the other.
func TestAnchoredDenyCoversArguments9022(t *testing.T) {
	for _, tc := range []struct {
		deny     string
		line     string
		wantDeny bool
		why      string
	}{
		// The defect: all five must deny under one anchored rule.
		{"^show log$", "show log", true, "the bare form — denied before this fix too"},
		{"^show log$", "sh log", true, "abbreviated; canonicalizes to `show log`"},
		{"^show log$", "show log 100", true,
			"runs journalctl -u xpfd -n 100 — the SAME command the denied bare form runs"},
		{"^show log$", "show log messages", true, "tails a syslog file"},
		{"^show log$", "show log FOO extra", true,
			"`extra` is silently dropped and a syslog file is tailed"},

		// THE ISSUE'S SECOND EXAMPLE IS A DIFFERENT MECHANISM AND IS NOT A
		// BYPASS. Measured: `show configuration` is NOT AcceptsArgs — it has 16
		// declared children and `system` is one of them, so `show configuration
		// system` is a DISTINCT COMMAND with its own handler, and
		// canonicalPrefix returns the whole string rather than a shorter run.
		//
		// An anchored rule correctly not matching a different command is the
		// same property as `^show version$` not matching `show route`. Denying
		// it here would mean an anchored rule silently covers a subtree, which
		// is the over-denying direction and would lock operators out.
		//
		// The distinction this fix rests on: `show log 100` runs the SAME
		// handler as `show log` (journalctl -u xpfd -n 100), so it is the same
		// command with an argument. `show configuration system` runs a
		// different one. That is why the widening uses canonicalPrefix — the
		// resolved KEYWORD run — and not "the first two words".
		{"^show configuration$", "show configuration", true, "bare form"},
		{"^show configuration$", "show configuration system", false,
			"a DISTINCT command node, not an argument — an anchored rule binds to its own command"},

		// UNANCHORED rules were never affected — matching is partial. Kept so a
		// regression that re-breaks only the anchored form cannot hide here.
		{"show log", "show log 100", true, "unanchored, matched a substring already"},

		// CONTROLS. The deny must stay NARROW: a fix that simply denied more
		// would satisfy every row above and lock operators out.
		{"^show log$", "show route", false, "an unrelated command"},
		{"^show log$", "show version", false, "an unrelated command"},
		{"^show log$", "show configuration", false,
			"a DIFFERENT command that merely shares the `show` prefix"},
		{"^show route$", "show log 100", false, "the rule must bind to its own command"},

		// #8289's control, unchanged: a trailing SIBLING KEYWORD yields
		// CanonicalUnknown and fails closed for a different reason. Asserted
		// here so this fix cannot be credited with it, and cannot break it.
		{"^show version$", "show version configuration", true,
			"CanonicalUnknown — fails closed via the #8289 path, not this one"},
	} {
		t.Run(tc.deny+" / "+tc.line, func(t *testing.T) {
			rules, err := config.CompileLoginRegexes(
				config.LoginRegexPlainFamily, "", false, tc.deny, true)
			if err != nil {
				t.Fatalf("CompileLoginRegexes(%q): %v", tc.deny, err)
			}
			err = evaluateCommandRegex(rules, "restricted", tc.line, "")
			if tc.wantDeny && err == nil {
				t.Fatalf("deny=%q line=%q was ALLOWED, want denied.\n%s", tc.deny, tc.line, tc.why)
			}
			if !tc.wantDeny && err != nil {
				t.Fatalf("deny=%q line=%q was DENIED (%v), want allowed.\n%s\n"+
					"Over-denying locks an operator out of a lawful command.",
					tc.deny, tc.line, err, tc.why)
			}
		})
	}
}

// TestDenyWithExceptionsSurvives9022 is the cell that rejects the OBVIOUS fix.
//
// "Deny if either the full string or the prefix matches a deny pattern" closes
// the hole above and BREAKS the deny-with-exceptions idiom the feature exists
// to support, because the prefix of the allowed form matches the deny.
//
// Taking the longest match PER SIDE across both forms instead lets the
// documented longest-match precedence decide: deny matches 8 characters on the
// prefix, allow matches 12 on the full string, tier 2 gives it to allow.
func TestDenyWithExceptionsSurvives9022(t *testing.T) {
	for _, tc := range []struct {
		allow, deny string
		line        string
		wantDeny    bool
		why         string
	}{
		{"^show log 100$", "^show log$", "show log 100", false,
			"the operator explicitly allowed this exact form; a `deny if either` fix denies it"},
		{"^show log 100$", "^show log$", "show log", true,
			"the bare form is denied and the exception does not cover it"},
		{"^show log 100$", "^show log$", "show log 200", true,
			"a DIFFERENT argument is not the allowed exception"},

		// Tier 2 in the other direction, unchanged by this fix: a longer DENY
		// beats a shorter ALLOW. "allow always wins" is false and must stay so.
		{"^show log$", "^show log 100$", "show log 100", true,
			"the longer deny wins over the shorter allow"},
	} {
		t.Run(tc.line+" allow="+tc.allow+" deny="+tc.deny, func(t *testing.T) {
			rules, err := config.CompileLoginRegexes(
				config.LoginRegexPlainFamily, tc.allow, true, tc.deny, true)
			if err != nil {
				t.Fatalf("CompileLoginRegexes: %v", err)
			}
			err = evaluateCommandRegex(rules, "restricted", tc.line, "")
			if tc.wantDeny && err == nil {
				t.Fatalf("line=%q was ALLOWED, want denied.\n%s", tc.line, tc.why)
			}
			if !tc.wantDeny && err != nil {
				t.Fatalf("line=%q was DENIED (%v), want allowed.\n%s", tc.line, err, tc.why)
			}
		})
	}
}

// TestNoRegexesConfiguredIsUnchanged9022 is the negative control for the whole
// change: a class with no allow/deny regexes must be untouched by it.
func TestNoRegexesConfiguredIsUnchanged9022(t *testing.T) {
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, "", false)
	if err != nil {
		t.Fatalf("CompileLoginRegexes: %v", err)
	}
	for _, line := range []string{"show log", "show log 100", "show configuration system"} {
		if err := evaluateCommandRegex(rules, "unrestricted", line, ""); err != nil {
			t.Errorf("%q was denied for a class with no regexes configured: %v", line, err)
		}
	}
}
