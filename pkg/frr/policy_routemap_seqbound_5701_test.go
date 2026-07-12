package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGeneratePolicyOptions_SkipsOversizedRouteMap_5701 proves the #5701
// render-side belt: a policy whose per-term Cartesian expansion exceeds the FRR
// route-map sequence ceiling is SKIPPED at render time (it emits no route-map),
// so a leniently-loaded / peer-synced oversized policy (the strict commit gate
// only warns on those paths, #1960) cannot render a `route-map` line past
// sequence 65535 and poison the whole frr-reload. A normal sibling policy still
// renders.
//
// FAIL-ON-REVERT: dropping the RouteMapSequenceCount > MaxRouteMapSequences
// skip in generatePolicyOptions makes the oversized policy render a route-map
// (and, with seq past 65535, poison the reload), so the "must NOT contain"
// assertion fires RED.
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

	if strings.Contains(got, "route-map BIG ") {
		t.Fatalf("oversized policy BIG must be SKIPPED (no route-map emitted), got:\n%s", got)
	}
	if !strings.Contains(got, "route-map OK ") {
		t.Fatalf("normal policy OK must still render its route-map, got:\n%s", got)
	}
}
