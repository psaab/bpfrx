package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGeneratePolicyOptions_SkipsOversizedRouteMap_5701 proves the #5701
// render-side belt: a policy whose per-term Cartesian expansion exceeds the FRR
// route-map sequence ceiling does NOT render that expansion, so a leniently-
// loaded / peer-synced oversized policy (the strict commit gate only warns on
// those paths, #1960) cannot emit a `route-map` line past sequence 65535 and
// poison the whole frr-reload. A normal sibling policy still renders.
//
// #6807 UPDATED THE SHAPE, NOT THE PROPERTY. The pre-#6807 belt emitted
// NOTHING for the oversized policy, and this test asserted the absence of any
// `route-map BIG ` line. That absence was the bug: BGP rendering still emits
// `neighbor <ip> route-map BIG in|out`, and FRR DENIES a route-map name it
// cannot resolve. The belt now emits a bounded explicit deny under the same
// name, so the assertion moves from "no line names BIG" to the strictly
// STRONGER "exactly one line names BIG, and it is the bounded deny" — the
// expansion is still absent, which is the #5701 property, and the name is now
// defined, which is #6807's.
//
// FAIL-ON-REVERT: dropping the RouteMapSequenceCount > MaxRouteMapSequences
// branch makes the oversized policy render its full expansion (thousands of
// sequences, past 65535), so the exactly-one-header assertion fires RED.
func TestGeneratePolicyOptions_SkipsOversizedRouteMap_5701(t *testing.T) {
	// One term with (MaxRouteMapSequences+1) from-prefix-list OR values → one
	// sequence per value → over the ceiling.
	over := make([]string, config.MaxRouteMapSequences+1)
	for i := range over {
		over[i] = fmt.Sprintf("pl%d", i)
	}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"BIG": {Name: "BIG", Terms: []*config.PolicyTerm{{Name: "t1", PrefixList: over}}},
			"OK":  {Name: "OK", Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept"}}},
		},
	}
	got := New().generatePolicyOptions(po)

	// #5701: the oversized EXPANSION must not be rendered. Asserted as a
	// header COUNT rather than a substring absence, so the cell distinguishes
	// "the expansion was skipped" from "nothing at all was emitted" — the two
	// the pre-#6807 assertion could not tell apart.
	headers := routeMapHeaders6807(got, "BIG")
	if len(headers) != 1 {
		t.Fatalf("oversized policy BIG must render exactly ONE route-map line "+
			"(the bounded #6807 quarantine deny), got %d:\n%v\nfull:\n%s",
			len(headers), headers, got)
	}
	// #6807: and that one line is the bounded explicit deny, not a fragment of
	// the expansion.
	if want := fmt.Sprintf("route-map BIG deny %d", quarantineDenySeq); headers[0] != want {
		t.Fatalf("oversized policy BIG must render the bounded explicit deny %q "+
			"so its surviving `neighbor ... route-map BIG in/out` attachment "+
			"resolves deliberately instead of dangling, got %q", want, headers[0])
	}
	if !strings.Contains(got, "route-map OK ") {
		t.Fatalf("normal policy OK must still render its route-map, got:\n%s", got)
	}
}

// routeMapHeaders6807 returns every `route-map <name> <action> <seq>` HEADER
// line in got for exactly route-map name, in order. Matching on the header
// keeps a policy named as a prefix of another (BIG vs BIGGER) from being
// counted, which a bare strings.Contains cannot do.
func routeMapHeaders6807(got, name string) []string {
	var out []string
	for _, line := range strings.Split(got, "\n") {
		f := strings.Fields(line)
		if len(f) == 4 && f[0] == "route-map" && f[1] == name {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}
