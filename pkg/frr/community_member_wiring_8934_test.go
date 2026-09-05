package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMalformedCommunityNeverReachesFRRConf8934 binds the WIRING, not the
// predicate.
//
// A unit test on ValidCommunityMember would pass while the render path stayed
// reachable by some other route. The #8934 defect was demonstrated end to end
// — operator text, strict commit, rendered frr.conf line — so that is where it
// is asserted:
//
//	members "@evil"  ->  CompileConfig ACCEPTED  ->  bgp community-list standard C1 permit @evil
//
// The render-side belt could not catch it because it shares its predicate with
// the commit gate ("ValidCommunityMember is shared so the two cannot drift").
// Shared means they cannot disagree — and that they cannot cover for each
// other, so what reads as defence in depth is one check invoked twice.
// Extending the shared predicate is what makes BOTH ends hold, which is why
// this cell asserts the far end rather than the near one.
func TestMalformedCommunityNeverReachesFRRConf8934(t *testing.T) {
	render := func(t *testing.T, members []string) string {
		t.Helper()
		m := &Manager{frrConf: "/dev/null"}
		po := &config.PolicyOptionsConfig{
			Communities: map[string]*config.CommunityDef{
				"C1": {Name: "C1", Members: members},
			},
		}
		return m.generatePolicyOptions(po)
	}

	// LIVENESS first: a legitimate member must still render, or "nothing
	// reached frr.conf" below would be satisfied by rendering nothing at all —
	// consistency achieved by levelling down.
	okOut := render(t, []string{"65000:100"})
	if !strings.Contains(okOut, "bgp community-list standard C1 permit 65000:100") {
		t.Fatalf("a LEGITIMATE community member no longer renders; every "+
			"assertion below would pass vacuously. Got:\n%s", okOut)
	}

	for _, bad := range []string{"@evil", "65000:a@b", "65000:100%x"} {
		t.Run(bad, func(t *testing.T) {
			out := render(t, []string{bad})
			if strings.Contains(out, bad) {
				t.Errorf("%q reached frr.conf:\n%s\nFRR rejects a malformed "+
					"standard community-list literal at config load, and a "+
					"single CMD_WARNING_CONFIG_FAILED exits the whole vtysh "+
					"add-batch non-zero — failing the ENTIRE frr-reload and "+
					"leaving every dynamic routing change stale (#8934).",
					bad, out)
			}
		})
	}

	// And a REGEX carrying the same character must still render: rejecting it
	// there would false-reject something FRR's regcomp accepts, which is the
	// over-approximation the gate's scope note warns about.
	reOut := render(t, []string{"65000:.*@x"})
	if !strings.Contains(reOut, "expanded") {
		t.Errorf("a REGEX member containing `@` no longer renders as an "+
			"expanded community-list:\n%s\nThe reject is deliberately limited "+
			"to NON-regex members; widening it to regexes would refuse "+
			"patterns FRR compiles fine (#8934).", reOut)
	}
}
