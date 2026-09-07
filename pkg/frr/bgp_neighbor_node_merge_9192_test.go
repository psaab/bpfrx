package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9192 — the RENDERED consequence of one authored neighbor compiling to two
// *BGPNeighbor entries.
//
// The duplication produced a redundant `remote-as` line. FRR accepts a repeated
// `remote-as`, so nothing was broken for the operator — which is exactly why
// this needs a cell rather than being assumed fixed: the symptom is quiet, and
// the two obvious remedies at this layer both made it worse. A duplicate-address
// check keyed on `Address` alone false-rejects a legitimate config with
// "configured in more than one group (G and G)"; a first-wins dedup at
// `validNeighbors` silently drops the policy-bearing entry along with its
// `activate` and `route-map … in` lines. The fix belongs at compile time, and
// this cell is what says the render is now clean AND still complete.
func TestBGPNeighborMergeRendersOneDeclaration9192(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set policy-options policy-statement PS term t1 then accept",
		"set protocols bgp local-as 65000",
		"set protocols bgp group G type external",
		"set protocols bgp group G peer-as 65001",
		"set protocols bgp group G neighbor 10.0.2.2",
		"set protocols bgp group G neighbor 10.0.2.2 import PS",
	} {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	m := &Manager{}
	out := m.generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, &cfg.PolicyOptions, nil)

	count := func(sub string) int { return strings.Count(out, sub) }

	// POSITIVE CONTROL FIRST. If the peer is not declared at all, every "exactly
	// one" assertion below is satisfied by ZERO and the cell reports a clean
	// render of nothing.
	if n := count("neighbor 10.0.2.2 remote-as 65001"); n == 0 {
		t.Fatalf("POSITIVE CONTROL: the peer is not declared in the rendered config at all, "+
			"so the counts below cannot distinguish a deduplicated render from an empty "+
			"one:\n%s", out)
	} else if n != 1 {
		t.Errorf("#9192: %d `neighbor 10.0.2.2 remote-as 65001` lines, want 1. One authored "+
			"neighbor is compiling to more than one BGPNeighbor entry again", n)
	}
	// THE OTHER HALF, and the reason a first-wins dedup at this layer was
	// reverted: the lines only the policy-bearing entry carries must survive.
	if n := count("neighbor 10.0.2.2 activate"); n != 1 {
		t.Errorf("#9192: %d `neighbor 10.0.2.2 activate` lines, want 1", n)
	}
	if n := count("neighbor 10.0.2.2 route-map PS in"); n != 1 {
		t.Errorf("#9192: %d `neighbor 10.0.2.2 route-map PS in` lines, want 1. A dedup that "+
			"keeps the FIRST entry drops the import policy — the config still commits and "+
			"the peer still comes up, with the operator's route filter silently absent", n)
	}
}
