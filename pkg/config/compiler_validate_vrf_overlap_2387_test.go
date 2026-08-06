package config

import (
	"strings"
	"testing"
)

// #2387 (Track A.1): the userspace-dp session/flow identity is the bare 5-tuple
// with no routing-instance/VRF discriminator (userspace-dp/src/session/key.rs),
// so two flows in different routing-instances that share a 5-tuple collide in
// the conntrack map. The collision is LIVE under PBR `then routing-instance`.
// validateVRFOverlap emits a commit WARNING (never a reject) when two DISTINCT
// routing-instances carry overlapping L3 address space.
//
// These tests pin: (1) two RIs with overlapping addresses on their member
// interface units WARN, naming both RIs + the prefix; (2) non-overlapping RIs
// do NOT warn (no false positive); (3) a single RI / no RI does NOT warn;
// (4) the PBR-term source (`then routing-instance`) also feeds the overlap set;
// (5) the warning states the CURRENT limitation and points at the tracking
// issue instead of promising a fix, and (6) losing the promise did not cost the
// diagnostic any of its substance.
//
// fail-on-revert: removing the validateVRFOverlap call (or its detection body)
// drops the warning, so TestVRFOverlapWarnsOnOverlappingRIs goes RED.
//
// The mutation that ISOLATES the promise dimension is a TAIL-ONLY substitution:
// replace "…may cross-forward. See #2387 for the status of this limitation"
// with "…may cross-forward until the session identity is VRF-aware", KEEPING
// the "the session identity carries no routing-instance discriminator, so"
// clause. That reds TestVRFOverlapWarningStatesStatusNotPromise on the "until"
// token while TestVRFOverlapWarningKeepsDiagnosticSubstance stays GREEN, which
// is what distinguishes "the promise is gone" from "the diagnostic is gone".
//
// A LITERAL revert to the pre-PR string reds BOTH, and that is correct, not a
// failure of the pair: the old string ALSO lacked the discriminator clause, so
// reverting changes two things at once — it re-adds the promise AND removes the
// diagnosis. Do not read a both-red result as "the tests do not separate"; run
// the tail-only mutation above to see them separate. (That the old text trips
// the substance test at all is the useful part: the replacement is strictly
// more informative than what it replaced, and this test is what pins that.)

// vrf2387Warnings returns the compile warnings that mention #2387.
func vrf2387Warnings(t *testing.T, cmds []string) []string {
	t.Helper()
	tree := buildTree(t, cmds)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var out []string
	for _, w := range cfg.Warnings {
		// Filter on the DIAGNOSIS, not on "#2387". Filtering on the issue
		// reference made the "points at the tracking issue" assertion below
		// unreachable: every warning reaching it had already been selected for
		// containing the very substring it then checked for. Dropping #2387
		// from a format string failed the fixture's count assertion instead,
		// with a message about the wrong thing. This phrase is carried by both
		// overlap format strings and by neither the truncation notice nor any
		// other warning, so the selection stays arm-neutral.
		if strings.Contains(w, "overlapping L3 across routing-instances") {
			out = append(out, w)
		}
	}
	return out
}

func TestVRFOverlapWarnsOnOverlappingRIs(t *testing.T) {
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 1 {
		t.Fatalf("expected exactly one #2387 overlap warning, got %d: %v", len(warns), warns)
	}
	w := warns[0]
	for _, want := range []string{`"RI-A"`, `"RI-B"`, "10.0.0.0/24", "NOT session-isolated"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning missing %q: %s", want, w)
		}
	}
}

func TestVRFOverlapNoWarnNonOverlapping(t *testing.T) {
	// Distinct address space per VRF — the common multi-VRF deployment. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("non-overlapping RIs should not warn, got: %v", warns)
	}
}

func TestVRFOverlapNoWarnSingleRI(t *testing.T) {
	// A single RI cannot overlap another RI. No warn even with two interfaces
	// carrying the same subnet inside the SAME instance.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-A interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("single RI should not warn, got: %v", warns)
	}
}

func TestVRFOverlapNoWarnNoRI(t *testing.T) {
	// No routing-instances at all — plain master-table config. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
	})
	if len(warns) != 0 {
		t.Fatalf("no-RI config should not warn, got: %v", warns)
	}
}

func TestVRFOverlapWarnsViaPBRTerms(t *testing.T) {
	// The same destination prefix steered into two different routing-instances
	// by two PBR `then routing-instance` terms is the exact reachable-via-PBR
	// trigger — overlap detected from the filter-term source.
	warns := vrf2387Warnings(t, []string{
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-B instance-type virtual-router",
		"set firewall family inet filter fbf term to-a from destination-address 172.16.9.0/24",
		"set firewall family inet filter fbf term to-a then routing-instance RI-A",
		"set firewall family inet filter fbf term to-b from destination-address 172.16.9.0/24",
		"set firewall family inet filter fbf term to-b then routing-instance RI-B",
	})
	if len(warns) != 1 {
		t.Fatalf("expected one #2387 overlap warning from PBR terms, got %d: %v", len(warns), warns)
	}
	for _, want := range []string{`"RI-A"`, `"RI-B"`, "172.16.9.0/24"} {
		if !strings.Contains(warns[0], want) {
			t.Errorf("PBR warning missing %q: %s", want, warns[0])
		}
	}
}

func TestVRFOverlapV6NoCrossFamilyFalsePositive(t *testing.T) {
	// A v4 subnet in one RI and a v6 subnet in another never overlap. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet6 address 2001:db8::1/64",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("cross-family (v4 vs v6) must not warn, got: %v", warns)
	}
}

// vrfOverlapForwardLookingTokens are the wordings that turn the advisory from a
// statement of the CURRENT limitation into a promise about a future one. #2387
// is held on a maintainer risk-appetite call: neither candidate end-state (the
// hard-reject posture, or the VRF-aware session key) is decided, so the warning
// must not assert that either one arrives. The original text said colliding
// 5-tuples may cross-forward "until the session identity is VRF-aware", and the
// #2387 plan then cited that sentence back as evidence the widening was already
// settled — a promise the open decision may never keep.
// This list is a BLOCKLIST and is therefore incomplete by construction: it
// catches the spellings someone thought of, and a future author can always
// phrase a promise a way it does not match. Do not read a green result as
// "the warning contains no promise" — read it as "the warning contains none of
// these". The entries below the first group were added after a review
// demonstrated each one passing the test while reintroducing a promise, so
// treat any addition the same way: prove it green first, then add it.
var vrfOverlapForwardLookingTokens = []string{
	"until",
	"will be",
	"planned",
	"future",
	"deferred",
	"upcoming",
	"roadmap",
	"once the session",
	"when the session",
	// Measured escapes — each was inserted into the warning and observed to
	// leave the test GREEN before it was listed here.
	//
	// "temporarily" earns its own entry: it does NOT contain "temporary" as a
	// substring, so the shorter token does not cover it.
	//
	// A cautionary one, kept as a worked example rather than removed: an
	// earlier round added "work is under way", which fires only on that exact
	// four-word spelling and does NOT match "work is underway" or "work is in
	// progress" — the phrasing actually measured. Reaching for a phrase you
	// imagined instead of the one you observed buys nothing. "in progress"
	// below is the token that does the work.
	"not yet",
	"pending",
	"temporary",
	"temporarily",
	"in a later release",
	"for now",
	"interim",
	"to be addressed",
	"work is under way",
	"underway",
	"in progress",
	"soon",
	"shortly",
	"eventually",
	"plan to",
	"will gain",
	"is expected to",
	"shall",
	"going to",
	"next release",
	"targeted for",
	"tracked for",
}

// vrfOverlapBothFormStrings returns one warning from EACH of the two format
// strings in validateVRFOverlap: the equal-prefix form (both RIs carry the
// identical prefix) and the unequal-overlap form (the prefixes overlap without
// being equal). A fixture that hits only one arm leaves the other's wording
// unbound, so every wording assertion below runs against both.
func vrfOverlapBothFormStrings(t *testing.T) (equal, unequal string) {
	t.Helper()

	eq := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(eq) != 1 {
		t.Fatalf("equal-prefix fixture: want 1 warning, got %d: %v", len(eq), eq)
	}
	// 10.0.0.0/24 vs 10.0.0.0/25 overlap but are not equal, so this reaches the
	// second format string. Assert the arm separation actually held rather than
	// trusting the fixture: if both fixtures produced the same form, every
	// "both format strings" claim below would be vacuous.
	un := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/25",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(un) != 1 {
		t.Fatalf("unequal-overlap fixture: want 1 warning, got %d: %v", len(un), un)
	}
	if !strings.Contains(eq[0], "both carry") {
		t.Fatalf("equal-prefix fixture did not reach the equal-prefix format string: %s", eq[0])
	}
	if !strings.Contains(un[0], "carry overlapping L3") {
		t.Fatalf("unequal fixture did not reach the unequal-overlap format string: %s", un[0])
	}
	return eq[0], un[0]
}

// TestVRFOverlapWarningStatesStatusNotPromise pins that BOTH format strings
// describe the current limitation and point at the tracking issue, without
// asserting that any particular fix arrives. Restoring the old "…may
// cross-forward until the session identity is VRF-aware" wording reds this on
// the "until" token.
func TestVRFOverlapWarningStatesStatusNotPromise(t *testing.T) {
	equal, unequal := vrfOverlapBothFormStrings(t)
	for _, tc := range []struct {
		form string
		warn string
	}{
		{"equal-prefix", equal},
		{"unequal-overlap", unequal},
	} {
		lower := strings.ToLower(tc.warn)
		for _, tok := range vrfOverlapForwardLookingTokens {
			if strings.Contains(lower, tok) {
				t.Errorf("%s form promises a fix via %q; #2387 is an open decision, so the warning must state the limitation and point at the issue: %s",
					tc.form, tok, tc.warn)
			}
		}
		if !strings.Contains(tc.warn, "#2387") {
			t.Errorf("%s form does not point at the tracking issue: %s", tc.form, tc.warn)
		}
	}
}

// TestVRFOverlapWarningKeepsDiagnosticSubstance is the negative control for
// TestVRFOverlapWarningStatesStatusNotPromise. Dropping the promise must not
// cost the operator the diagnosis: the warning still has to say WHAT is wrong
// (no routing-instance discriminator in the session identity) and WHAT the
// consequence is (colliding 5-tuples may cross-forward). Without this pair, the
// forward-looking-token test above is satisfied just as well by deleting the
// warning text wholesale.
func TestVRFOverlapWarningKeepsDiagnosticSubstance(t *testing.T) {
	equal, unequal := vrfOverlapBothFormStrings(t)
	for _, tc := range []struct {
		form string
		warn string
		// ident is the WHICH of the diagnosis: which routing-instances, reached
		// through which config source, over which prefix.
		//
		// These are ORDERED PAIRINGS held as one contiguous substring, not a
		// list of tokens to find somewhere in the message. Presence and
		// association are different properties, and only the second is useful:
		// a token list is satisfied while every identifier is attached to the
		// WRONG object. Both format strings are 6-argument Sprintf calls
		// carrying three (name, origin, prefix) triples, which is exactly where
		// an argument transposition happens — and `go vet` cannot see it,
		// because every argument is a string or Stringer feeding %q/%s, so the
		// printf checker reports nothing.
		//
		// Measured on the token-list version: swapping the two origins, or the
		// two RI names, or the two prefixes, left `go test ./pkg/config/
		// -count=1` fully green and `go vet ./pkg/config/` silent, while the
		// operator was sent to the wrong interface or told the wrong prefix
		// sits on the wrong instance. Fixture truth is
		// RI-A <- ge-0/0/1.0 @ 10.0.0.0/24 and RI-B <- ge-0/0/2.0 @ 10.0.0.0/25.
		//
		// The pairing form is a strict replacement, not an addition: a strip
		// breaks the contiguous substring too, so it still catches everything
		// the token list caught.
		ident []string
	}{
		{
			form: "equal-prefix",
			warn: equal,
			ident: []string{
				`"RI-A" (interface "ge-0/0/1.0") and "RI-B" (interface "ge-0/0/2.0") both carry 10.0.0.0/24`,
			},
		},
		{
			form: "unequal-overlap",
			warn: unequal,
			// One pairing per instance: this arm's whole reason to exist is
			// that the two prefixes DIFFER, so each must stay bound to its own
			// instance and origin.
			ident: []string{
				`"RI-A" (interface "ge-0/0/1.0", 10.0.0.0/24)`,
				`"RI-B" (interface "ge-0/0/2.0", 10.0.0.0/25)`,
			},
		},
	} {
		// The explanation: what is wrong and what follows from it.
		for _, want := range []string{
			"NOT session-isolated",
			"no routing-instance discriminator",
			"cross-forward",
		} {
			if !strings.Contains(tc.warn, want) {
				t.Errorf("%s form lost diagnostic substance %q: %s", tc.form, want, tc.warn)
			}
		}
		// The identification: which objects the explanation is about.
		for _, want := range tc.ident {
			if !strings.Contains(tc.warn, want) {
				t.Errorf("%s form no longer states the pairing %q — the warning explains the hazard "+
					"but not which routing-instance sits on which source and prefix: %s",
					tc.form, want, tc.warn)
			}
		}
	}
}
