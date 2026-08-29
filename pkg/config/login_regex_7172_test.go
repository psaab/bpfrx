package config

import (
	"strings"
	"testing"
)

// #7172 cut 2 — the fine-grained allow/deny matcher core.
//
// These cells are pure: patterns and a command in, a decision out. No dispatch
// surface. This is the piece where a mistake is a privilege escalation rather
// than a bug, so it is tested on its own before any wiring exists.

func mustCompileLoginRegexes(t *testing.T, allow string, allowSet bool, deny string, denySet bool) CompiledLoginRegexes {
	t.Helper()
	c, err := CompileLoginRegexes(LoginRegexPlainFamily, allow, allowSet, deny, denySet)
	if err != nil {
		t.Fatalf("CompileLoginRegexes(%q,%v,%q,%v): %v", allow, allowSet, deny, denySet, err)
	}
	return c
}

// ── Tier 2, and the fixture that proves "allow always wins" is not what
// shipped. This is the case a flat allow-precedence implementation gets wrong,
// and it is a FAIL-OPEN when it does.
func TestLongerDenyBeatsShorterAllow7172(t *testing.T) {
	c := mustCompileLoginRegexes(t, "commit", true, "commit synchronize", true)
	got := c.Evaluate("commit synchronize")
	if got.Allowed {
		t.Fatalf("`commit synchronize` was ALLOWED with allow=%q deny=%q. Junos's longest-match "+
			"tier means a longer DENY beats a shorter ALLOW; permitting it here is the "+
			"fail-open that a flat \"allow always wins\" implementation produces. got %+v",
			"commit", "commit synchronize", got)
	}
	if got.DecidedBy != LoginRegexDeny {
		t.Errorf("expected the deny leaf to carry the decision, got %v", got.DecidedBy)
	}
	// And the mirror: the shorter command, which only the allow matches.
	if d := c.Evaluate("commit"); !d.Allowed {
		t.Errorf("`commit` must be allowed — only the allow regex matches it: %+v", d)
	}
}

// Juniper's own worked example, in the direction they state it: a class that
// may run `commit synchronize` but not `commit`.
func TestJunipersWorkedExampleAllowsTheLongerVariant7172(t *testing.T) {
	c := mustCompileLoginRegexes(t, "commit synchronize", true, "commit", true)
	if d := c.Evaluate("commit synchronize"); !d.Allowed {
		t.Errorf("`commit synchronize` must be ALLOWED — the allow regex matches a longer "+
			"extent than the deny: %+v", d)
	}
	if d := c.Evaluate("commit"); d.Allowed {
		t.Errorf("`commit` must be DENIED — only the deny regex matches it: %+v", d)
	}
}

// ── THE MIDDLE ROW for the length metric.
//
// `commit` / `commit synchronize` passes under BOTH readings of "longest" and
// therefore proves nothing about which one shipped. These patterns separate
// them: matched-substring length gives allow (".*" matches all 18 characters,
// "commit" matches 6), while longest-PATTERN length would give deny ("commit"
// is 6 characters of pattern, ".*" is 2).
func TestLongestMeansMatchedSubstringNotPatternLength7172(t *testing.T) {
	c := mustCompileLoginRegexes(t, ".*", true, "commit", true)
	got := c.Evaluate("commit synchronize")
	if !got.Allowed {
		t.Fatalf("expected ALLOW: `.*` matches the whole 18-character command while `commit` "+
			"matches 6, so matched-substring length picks allow. A deny here means the "+
			"implementation is comparing PATTERN lengths (2 vs 6), which is the other "+
			"reading of \"longest match\". got %+v", got)
	}
	if !strings.Contains(got.Reason, "longer extent") {
		t.Errorf("reason should name the extent comparison, got %q", got.Reason)
	}
}

// ── Tier 1: identical patterns. Juniper states allow wins; a flat "tie -> deny"
// rule would invert a documented case, so this pins it explicitly.
func TestIdenticalPatternsAllowWins7172(t *testing.T) {
	c := mustCompileLoginRegexes(t, "request system reboot", true, "request system reboot", true)
	got := c.Evaluate("request system reboot")
	if !got.Allowed {
		t.Fatalf("identical allow and deny patterns must resolve to ALLOW for the plain "+
			"family — Juniper: \"if you configure the same command for both ... the allow "+
			"operation takes precedence\". This is Junos parity, NOT a fail-open; see the "+
			"reviewer warning on Evaluate. got %+v", got)
	}
	if got.DecidedBy != LoginRegexAllow {
		t.Errorf("expected the allow leaf to carry it, got %v", got.DecidedBy)
	}
}

// ── Tier 3, ours: equal extents, DIFFERENT patterns -> deny (fail-closed).
// Distinct from tier 1, which is the identical-pattern case.
func TestEqualExtentDifferentPatternsDenies7172(t *testing.T) {
	// Both match exactly "commit" (6 chars) but are not the same pattern.
	c := mustCompileLoginRegexes(t, "commit", true, "commi.", true)
	got := c.Evaluate("commit")
	if got.Allowed {
		t.Fatalf("equal-extent matches from DIFFERENT patterns must deny — upstream is silent "+
			"on this tie and xpf resolves it fail-closed. got %+v", got)
	}
	if !strings.Contains(got.Reason, "underspecified") {
		t.Errorf("the reason must mark this as xpf's interpretation rather than Junos "+
			"behaviour, so a later reader knows which sentence to go and verify: %q", got.Reason)
	}
}

// ── The empty-pattern trap. An empty POSIX regex matches everything, so an
// empty deny denies EVERYTHING. The natural defensive line —
// `if pattern == "" { return noRestriction }` — is the exact opposite, and is
// the line a reviewer would add as tidying.
func TestEmptyDenyPatternDeniesEverything7172(t *testing.T) {
	c := mustCompileLoginRegexes(t, "", false, "", true) // deny PRESENT, empty value
	for _, cmd := range []string{"show interfaces", "request system reboot", ""} {
		if d := c.Evaluate(cmd); d.Allowed {
			t.Errorf("`deny-commands \"\"` must deny %q. An empty POSIX regex matches every "+
				"command, so an empty deny is the most restrictive thing the grammar allows "+
				"— treating it as \"no restriction\" turns a total lockout into a total "+
				"permit. got %+v", cmd, d)
		}
	}
}

// Presence is not value: an ABSENT deny must deny nothing, which is the
// opposite of an empty one. If these two collapse, one of them is a fail-open.
func TestAbsentDenyIsNotAnEmptyDeny7172(t *testing.T) {
	absent := mustCompileLoginRegexes(t, "", false, "", false)
	if d := absent.Evaluate("request system reboot"); !d.Allowed {
		t.Errorf("no regexes configured must allow: %+v", d)
	}
	empty := mustCompileLoginRegexes(t, "", false, "", true)
	if d := empty.Evaluate("request system reboot"); d.Allowed {
		t.Errorf("an empty deny must deny — it is not the same as an absent one: %+v", d)
	}
}

// ── THE MIDDLE ROW for anchoring.
//
// `allow-commands "show interfaces"` against the input `show interfaces` passes
// under BOTH readings and proves nothing. `show interfaces terse` is the
// discriminator: it matches under partial (unanchored) matching and does not
// under anchored matching.
//
// Junos: "You must use anchors when specifying complex regular expressions with
// the allow-commands statement", with `(^monitor)|(^ping)|(^show)|(^exit)` as
// the example — explicit anchors would be redundant under implicit anchoring.
func TestMatchingIsUnanchoredPartial7172(t *testing.T) {
	c := mustCompileLoginRegexes(t, "show interfaces", true, "", false)
	if d := c.Evaluate("show interfaces terse"); !d.Allowed {
		t.Fatalf("`show interfaces terse` must match the allow pattern `show interfaces` — "+
			"matching is UNANCHORED, so the pattern matches a substring. A deny here means "+
			"the implementation anchored the match, which would also make an operator's "+
			"explicit `^` redundant. got %+v", d)
	}
	// And the operator's own anchor must still narrow, or anchors are useless.
	anchored := mustCompileLoginRegexes(t, "^show interfaces$", true, "", false)
	if d := anchored.Evaluate("show interfaces terse"); d.Allowed {
		t.Errorf("`^show interfaces$` must NOT match `show interfaces terse` — anchors are "+
			"the operator's tool for narrowing: %+v", d)
	}
	if d := anchored.Evaluate("show interfaces"); !d.Allowed {
		t.Errorf("`^show interfaces$` must match `show interfaces`: %+v", d)
	}
}

// An allow regex, once configured, is an ALLOWLIST — non-matching commands are
// denied even with no deny regex present.
func TestAllowRegexEstablishesAnAllowlist7172(t *testing.T) {
	c := mustCompileLoginRegexes(t, "^show", true, "", false)
	if d := c.Evaluate("show interfaces"); !d.Allowed {
		t.Errorf("a matching command must be allowed: %+v", d)
	}
	got := c.Evaluate("request system reboot")
	if got.Allowed {
		t.Fatalf("a command NOT matching the allow regex must be denied even with no deny "+
			"regex configured — a configured allow is an allowlist, not a hint: %+v", got)
	}
	if got.DecidedBy != LoginRegexAllow {
		t.Errorf("the allow leaf is what denied this; audit must say so, got %v", got.DecidedBy)
	}
}

// Invalid syntax must fail at COMPILE (admission), so evaluation can never
// panic or fall open at runtime.
func TestInvalidRegexFailsAtCompileNotRuntime7172(t *testing.T) {
	for _, tc := range []struct {
		name, allow, deny string
		allowSet, denySet bool
	}{
		{name: "bad allow", allow: "([unclosed", allowSet: true},
		{name: "bad deny", deny: "*leading-star", denySet: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileLoginRegexes(LoginRegexPlainFamily,
				tc.allow, tc.allowSet, tc.deny, tc.denySet)
			if err == nil {
				t.Fatal("an unparseable pattern must fail at compile time; deferring it to " +
					"evaluation is how a regex authz gate falls open at runtime")
			}
			if !strings.Contains(err.Error(), "POSIX") {
				t.Errorf("the error should name the dialect so an operator knows which "+
					"syntax is expected: %v", err)
			}
		})
	}
}

// PER-FAMILY DATA, not a constant (#7971). The `-regexps` family inverts tier 1;
// a core that hardcodes "allow wins" would be reused by whoever adds it, and the
// reuse would look responsible while inverting the rule on the leaf that matters.
func TestPrecedenceIsPerFamilyData7172(t *testing.T) {
	// Same inputs, opposite family rule, opposite verdict.
	denyWins := LoginRegexFamily{Name: "test-regexps-like", IdenticalPatternWinner: LoginRegexDeny}
	c, err := CompileLoginRegexes(denyWins, "commit", true, "commit", true)
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Evaluate("commit"); d.Allowed {
		t.Fatalf("a family declaring deny as the identical-pattern winner must DENY, "+
			"proving the tier-1 rule is read from family data rather than hardcoded: %+v", d)
	}
	// The shipped family is the other way round — the pair is what proves the
	// field is consulted rather than incidentally agreeing with a constant.
	plain := mustCompileLoginRegexes(t, "commit", true, "commit", true)
	if d := plain.Evaluate("commit"); !d.Allowed {
		t.Fatalf("the plain family must ALLOW on identical patterns: %+v", d)
	}
}

// ── LONGEST MATCH ANYWHERE, not the leftmost one.
//
// This cell exists because a mutation ESCAPED without it: narrowing
// longestMatchLen to the first match only (`FindAllStringIndex(s, 1)`) left
// every other cell green. Every fixture above uses a pattern whose leftmost
// match IS its longest, so none of them could tell the two apart — the
// distinction was asserted in a doc comment and bound by nothing.
//
// An alternation is where they diverge, and it diverges in the FAIL-OPEN
// direction: measuring a deny by its leftmost (shorter) match understates its
// extent, so a competing allow wins a comparison it should have lost.
//
//	command: "show configuration security"
//	deny:    "show|configuration security"  leftmost "show" (4), longest (21)
//	allow:   "show configuration"           (18)
//
// longest -> deny 21 > allow 18 -> DENY. leftmost -> deny 4 < allow 18 -> ALLOW.
func TestLongestMatchIsAnywhereNotLeftmost7172(t *testing.T) {
	c := mustCompileLoginRegexes(t,
		"show configuration", true,
		"show|configuration security", true)
	got := c.Evaluate("show configuration security")
	if got.Allowed {
		t.Fatalf("expected DENY: the deny pattern's LONGEST match is `configuration security` "+
			"(21 chars), which beats the allow's 18. Permitting this means match extent is "+
			"being measured from the LEFTMOST match (`show`, 4 chars), which understates a "+
			"deny built from an alternation — the fail-open direction. got %+v", got)
	}
	if got.DecidedBy != LoginRegexDeny {
		t.Errorf("the deny leaf must carry it, got %v", got.DecidedBy)
	}
}
