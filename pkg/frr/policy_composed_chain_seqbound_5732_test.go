package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRenderComposedRouteMap_SkipsOversizedChain_5732 proves the #5732
// render-side belt: renderComposedRouteMap renders NOTHING for a composed BGP
// policy chain whose members' summed route-map sequence count exceeds the FRR
// ceiling, so a leniently-loaded / peer-synced oversized chain (the strict
// commit gate only warns there, #1960) cannot emit a `route-map` line past seq
// 65535 and poison the reload. A normal chain still renders.
//
// FAIL-ON-REVERT: dropping the config.ComposedChainSequenceCount >
// config.MaxRouteMapSequences skip makes renderComposedRouteMap emit a route-map
// with sequences past 65535, so the "must be empty" assertion fires RED.
func TestRenderComposedRouteMap_SkipsOversizedChain_5732(t *testing.T) {
	// Two members that individually pass the per-policy ceiling but SUM over it.
	half := config.MaxRouteMapSequences/2 + 100 // each ~3376 <= 6552; sum ~6752 > 6552
	mk := func(n int) *config.PolicyStatement {
		pl := make([]string, n)
		for i := range pl {
			pl[i] = fmt.Sprintf("pl%d", i)
		}
		return &config.PolicyStatement{Terms: []*config.PolicyTerm{{Name: "t", PrefixList: pl}}}
	}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": mk(half),
			"B": mk(half),
		},
	}
	// Sanity: each member is in-bounds, the composed chain is not.
	if config.RouteMapSequenceCount(po.PolicyStatements["A"]) > config.MaxRouteMapSequences {
		t.Fatalf("member A must be within the per-policy ceiling")
	}
	if config.ComposedChainSequenceCount(po.PolicyStatements, []string{"A", "B"}) <= config.MaxRouteMapSequences {
		t.Fatalf("composed A+B must exceed the ceiling")
	}

	got := New().renderComposedRouteMap(po, "A-B"+config.ReservedChainSuffix, []string{"A", "B"})
	if strings.TrimSpace(got) != "" {
		t.Fatalf("oversized composed chain must render NOTHING (skipped), got:\n%s", got)
	}

	// A normal short chain still renders a composed route-map.
	poOK := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
			"B": {Terms: []*config.PolicyTerm{{Name: "t", Action: "reject"}}},
		},
	}
	okName := "A-B" + config.ReservedChainSuffix
	if out := New().renderComposedRouteMap(poOK, okName, []string{"A", "B"}); !strings.Contains(out, "route-map "+okName+" ") {
		t.Fatalf("a normal composed chain must render its route-map, got:\n%s", out)
	}
}
