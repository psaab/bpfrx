package config

import (
	"regexp"
	"strings"
	"testing"
)

// #8449. A community member carrying a regex metacharacter renders into an FRR
// `expanded` community-list and is compiled by regcomp. One that does not
// compile is a CMD_WARNING_CONFIG_FAILED, which exits the whole vtysh
// add-batch non-zero and fails the ENTIRE frr-reload — the failure mode #6686
// fixed for as-path, in the sibling that never got a gate.

func TestValidCommunityMemberTable_8449(t *testing.T) {
	cases := []struct {
		member string
		valid  bool
		why    string
	}{
		{"65000:100", true, "plain literal"},
		{"no-export", true, "well-known name"},
		{"no-advertise", true, "well-known name"},
		{"65000:.*", true, "valid wildcard regex"},
		{"^65000:", true, "valid anchor"},
		{"65000:1{2,3}", true, "valid POSIX bound"},
		// These two committed CLEAN before the gate and were rendered verbatim.
		{"65000:[", false, "unbalanced bracket"},
		{"*65000", false, "dangling repeat"},
		{"", false, "empty member renders an incomplete command"},
		{"   ", false, "whitespace-only member"},
	}
	for _, c := range cases {
		err := ValidCommunityMember(c.member)
		if (err == nil) != c.valid {
			t.Errorf("ValidCommunityMember(%q) err=%v, want valid=%v (%s)",
				c.member, err, c.valid, c.why)
		}
	}
}

// The gate must agree with Go's own POSIX compiler on every member it
// classifies as a regex. Pinning a hand-written list of "bad patterns" would
// drift; asserting the AGREEMENT cannot.
func TestValidCommunityMemberAgreesWithRegcomp_8449(t *testing.T) {
	members := []string{
		"65000:100", "no-export", "65000:.*", "^65000:", "65000:1{2,3}",
		"65000:[", "*65000", "65000:(", `65000:\`, "65000:a{3,1}",
		"(65000|65001):100", "65000:1+", "?bad",
	}
	checkedRegexKind := 0
	for _, m := range members {
		if !CommunityMemberIsRegex(m) {
			continue // standard-kind members are not compiled by FRR
		}
		checkedRegexKind++
		_, reErr := regexp.CompilePOSIX(m)
		gateErr := ValidCommunityMember(m)
		if (reErr == nil) != (gateErr == nil) {
			t.Errorf("member %q: regcomp err=%v but gate err=%v — the gate and the "+
				"engine FRR uses disagree", m, reErr, gateErr)
		}
	}
	// ANTI-VACUITY: if the classifier stopped calling any of these a regex, the
	// loop above would compare nothing and pass.
	if checkedRegexKind < 8 {
		t.Fatalf("only %d members classified as regex-kind; the table no longer "+
			"exercises the compiled path", checkedRegexKind)
	}
}

// The classification is per-DEFINITION, and the render belt must omit the WHOLE
// definition. This pins the property the belt depends on: one bad member makes
// the definition unrenderable even when every other member is fine.
func TestOneBadMemberCondemnsTheDefinition_8449(t *testing.T) {
	members := []string{"65000:100", "no-export", "65000:["}
	bad := 0
	for _, m := range members {
		if ValidCommunityMember(m) != nil {
			bad++
		}
	}
	if bad != 1 {
		t.Fatalf("expected exactly 1 unrenderable member in %v, got %d", members, bad)
	}
	// And the definition's list kind is expanded BECAUSE of that member, which
	// is what routes every sibling through regcomp too.
	if !CommunityMemberIsRegex("65000:[") {
		t.Error("`65000:[` no longer forces the expanded list kind — the members " +
			"that break regcomp would no longer be compiled by FRR, and this " +
			"gate would be guarding a path nothing takes")
	}
}

// The renderer's list-kind decision and this gate must read the SAME character
// set. Two literals in two packages is the pair that drifts.
func TestCommunityRegexCharsCoversTheMetacharacters_8449(t *testing.T) {
	for _, c := range []string{"*", ".", "+", "?", "^", "$", "[", "]", "(", ")", "|", `\`, "{", "}"} {
		if !strings.Contains(CommunityRegexChars, c) {
			t.Errorf("CommunityRegexChars is missing %q — a member using it would render "+
				"into a STANDARD community-list, which FRR rejects outright", c)
		}
	}
}
