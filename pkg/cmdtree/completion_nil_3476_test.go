package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3476: the `show security policies … policy <TAB>` ContextDynamicFn in
// OperationalTree derefs zpp.FromZone and p.Name without nil guards. The
// tolerant / HA-sync config path (#3474) can leave a nil zone-pair set or nil
// rule the runtime walker tolerates. This drives the real completer; reverting
// either guard makes it panic (RED on revert).
func TestShowPoliciesPolicyCompletionNilSlotsNoPanic(t *testing.T) {
	cfg := &config.Config{}
	// nil zpp FIRST (exercises the zpp guard before the matching set), then the
	// matching trust->untrust set whose rule slice leads with a nil rule.
	cfg.Security.Policies = []*config.ZonePairPolicies{
		nil,
		{
			FromZone: "trust",
			ToZone:   "untrust",
			Policies: []*config.Policy{nil, {Name: "p1"}},
		},
	}

	cands := CompleteFromTree(OperationalTree,
		[]string{"show", "security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"},
		"", cfg)

	// The nil rule must be skipped and the real policy name surfaced.
	if !contains(cands, "p1") {
		t.Fatalf("expected policy name p1 in completions, got %v", cands)
	}
	for _, c := range cands {
		if c == "" {
			t.Fatalf("nil rule produced an empty completion candidate: %v", cands)
		}
	}
}
