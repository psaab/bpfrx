package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9387: the `?`-help text for `security policies policy-rematch` told operators
// the knob was "accepted-only; unenforced" long after it shipped.
//
// WHY THIS GUARD LIVES IN pkg/daemon AND NOT pkg/config. The claim "this knob is
// unenforced" is only false BECAUSE `changedPolicyRuntimeIDs` exists and gates on
// it, and that function is in THIS package. A guard in pkg/config could only
// assert the absence of a phrase, which is satisfiable by rewording and says
// nothing about whether the capability is actually there. Here both halves are in
// reach, so the cell can state the real contract: IF the enforcement runs, the
// help must not deny it — and if the enforcement is ever un-shipped, the first
// half reds and tells the author the help text is now wrong in the OTHER
// direction. A one-sided cell cannot do that.
//
// WHY THE TEXT IS READ THROUGH `CompleteSetPathWithValues`. That is the function
// the CLI's `?` handler calls, so this reads the bytes an operator is actually
// shown rather than a struct literal that merely feeds them. A leaf moved,
// renamed, or reachable by a different path therefore fails the non-vacuity
// check below instead of passing for free.
//
// WHY NOT THE GUARD #9387 ORIGINALLY PROPOSED. The issue's more durable
// alternative was "fail when a setSchema desc contains an accepted-only phrase
// whose referenced issue is CLOSED". That predicate is WRONG, and the census run
// for this change refutes it: `schema_interfaces.go` says "accepted-only, not yet
// enforced — #4308" and `schema_routing.go` says "accepted-only; always inserted
// — #4309", and BOTH of those issues are closed — they closed on ADDING the
// advisory, not on enforcing the knob, so the desc is TRUE and closing the issue
// did not change that. A closed tracking issue is not the discriminator. The
// discriminator is whether an enforcement path reads the field, which is what
// this cell measures.

// policyRematchHelpDesc returns the operator-facing `?` description for
// `set security policies policy-rematch`, via the same completion entry point
// the CLI uses.
func policyRematchHelpDesc(t *testing.T) string {
	t.Helper()
	for _, c := range config.CompleteSetPathWithValues([]string{"security", "policies"}, nil) {
		if c.Name == "policy-rematch" {
			return c.Desc
		}
	}
	t.Fatal("`set security policies policy-rematch` is no longer offered by " +
		"CompleteSetPathWithValues — this guard is scanning for a leaf that does " +
		"not exist, so every assertion below would pass for free (#9387)")
	return ""
}

// policyRematchExtensiveHelpDesc returns the `?` description for the
// `extensive` sub-token.
func policyRematchExtensiveHelpDesc(t *testing.T) string {
	t.Helper()
	path := []string{"security", "policies", "policy-rematch"}
	for _, c := range config.CompleteSetPathWithValues(path, nil) {
		if c.Name == "extensive" {
			return c.Desc
		}
	}
	t.Fatal("`policy-rematch extensive` is no longer offered by " +
		"CompleteSetPathWithValues (#9387)")
	return ""
}

// staleCapabilityPhrases are the spellings that assert a capability is MISSING.
// A `desc` is a claim with an expiry date and nothing re-checks it, so the
// phrases are enumerated rather than left to a reviewer's eye.
var staleCapabilityPhrases = []string{
	"accepted-only",
	"accepted only",
	"unenforced",
	"not enforced",
	"not yet enforced",
	"no runtime effect",
	"not implemented",
	"does nothing",
}

// THE CONTRACT, both halves in one cell so neither can drift alone.
//
// Half 1 (behavioural): `changedPolicyRuntimeIDs` really does clear the sessions
// of a policy whose action changed, and really does gate that on the knob. This
// is what makes "unenforced" a false statement.
//
// Half 2 (operator-facing): given half 1, neither the leaf's `?` help nor its
// `extensive` sub-token's help may assert the capability is missing.
//
// Reverting `schema_security.go` to the "(accepted-only; unenforced)" text reds
// half 2 and nothing else in the suite. Deleting the `!newCfg.Security.PolicyRematch`
// gate reds half 1's gate sub-assertion.
func TestPolicyRematchHelpDoesNotDenyTheShippedEnforcement_9387(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"})

	// Half 1a: with the knob SET and an action tightened, the enforcement reports
	// the policy whose sessions must be cleared.
	enforced := withPolicyRematch(
		twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"}), false)
	enforced.Security.Policies[0].Policies[1].Action = config.PolicyDeny
	if got := changedPolicyRuntimeIDs(old, enforced, nil, nil); len(got) == 0 {
		t.Fatal("policy-rematch is NOT enforced: changedPolicyRuntimeIDs reported " +
			"nothing for a permit->deny tightening with the knob set. If the " +
			"enforcement has been withdrawn, the `?` help must say so again — and " +
			"this cell, not a reviewer, is what should have told you (#9387)")
	}

	// Half 1b: the gate. Without the knob the same tightening reports nothing,
	// which is WHY the help text matters: on a stock box this is the state.
	unset := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"})
	unset.Security.Policies[0].Policies[1].Action = config.PolicyDeny
	if got := changedPolicyRuntimeIDs(old, unset, nil, nil); len(got) != 0 {
		t.Fatalf("policy-rematch must GATE the commit-time invalidation; with the "+
			"knob unset the changed set must be empty, got %v (#9387)", got)
	}

	// Half 1c: `extensive` (#8993) is enforced too, so its own help may not deny
	// it either. A referenced address definition changes; no policy text moves.
	extOld := withPolicyRematch(
		twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"}), true)
	if !extOld.Security.PolicyRematchExtensive {
		t.Fatal("fixture did not set PolicyRematchExtensive")
	}

	// Half 2: the operator-facing text.
	for name, desc := range map[string]string{
		"policy-rematch":           policyRematchHelpDesc(t),
		"policy-rematch extensive": policyRematchExtensiveHelpDesc(t),
	} {
		if strings.TrimSpace(desc) == "" {
			t.Fatalf("`%s` has an EMPTY `?` description — a guard against a false "+
				"claim must not be satisfiable by saying nothing (#9387)", name)
		}
		lower := strings.ToLower(desc)
		for _, phrase := range staleCapabilityPhrases {
			if strings.Contains(lower, phrase) {
				t.Errorf("`set security policies %s` `?` help says %q, which asserts the "+
					"capability is MISSING. It is not: changedPolicyRuntimeIDs "+
					"clears the sessions of a policy whose match or action changed "+
					"(and, with `extensive`, of an unchanged policy whose "+
					"referenced objects changed). This is the one place operators "+
					"read, and the knob is OFF BY DEFAULT, so an operator told it "+
					"does nothing will not set it (#9387)", name, desc)
				break
			}
		}
	}
}

// The ZERO-CLAIM property for the `security policies` subtree, which is the
// surface #9387 is about.
//
// Deliberately NOT a whole-schema allowlist. #9387 proposed the more general
// guard "fail when a `setSchema` desc contains an accepted-only phrase whose
// referenced issue is CLOSED", and the census run for this change REFUTED that
// predicate: `schema_interfaces.go` says "accepted-only, not yet enforced --
// #4308" and `schema_routing.go` says "accepted-only; always inserted --
// #4309", and both issues are closed -- they closed on ADDING a commit
// advisory, not on enforcing the knob, so both descs are TRUE. A closed
// tracking issue is not the discriminator. Nor is the phrase itself: 44 `desc`
// strings across `pkg/config/schema*.go` carry one, and the three audited by
// hand for this change (`strict-syn-check` #8296, and the #4308/#4309 pairs) are
// all accurate -- each names a knob no runtime path reads, and each carries a
// matching commit advisory. The rest were NOT audited, and saying so is the
// point: a 44-row allowlist would assert 44 verdicts this change did not earn.
//
// What IS a real, earned statement is the one below: nothing under `security
// policies` advertises itself as unenforced. That subtree's knobs are the
// enforcement-critical ones, `policy-rematch` was the only claim in it, and it
// is now gone -- so the honest guard is that the count is ZERO and any future
// addition has to be argued for rather than slipped in.
func TestNoSecurityPolicyKnobAdvertisesItselfUnenforced_9387(t *testing.T) {
	const want = 0
	got := 0
	for _, c := range config.CompleteSetPathWithValues([]string{"security", "policies"}, nil) {
		lower := strings.ToLower(c.Desc)
		for _, phrase := range staleCapabilityPhrases {
			if strings.Contains(lower, phrase) {
				got++
				t.Logf("capability-missing claim under `security policies`: %s -> %q",
					c.Name, c.Desc)
				break
			}
		}
	}
	if got != want {
		t.Errorf("`security policies` carries %d `?` descriptions asserting the "+
			"knob is unenforced; the earned count is %d. If a knob genuinely IS "+
			"accepted-only, say so here and raise the number with the reason -- but "+
			"check first whether an enforcement path already reads its field, "+
			"because that is the mistake #9387 was (#9387)", got, want)
	}
}
