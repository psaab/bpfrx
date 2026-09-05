package config

import (
	"fmt"
	"strings"
	"testing"
)

// #8854: the host-inbound advisory pass called ResolveInterfaceHostInbound
// once PER ZONE. The call takes only cfg and depends on no loop variable, and
// the resolver sorts every zone name internally, so the tolerant compile was
// O(Z^2 log Z). Measured on CompileConfigLenient before the fix:
//
//	 500 zones   0.15 s        3000 zones   8.5 s
//	2000 zones   4.0 s         8000 zones    76 s
//
// at Z=3000 the resolver was 86.7% cumulative and slices.pdqsortOrdered 67.7%.
// The tolerant path is boot and HA peer-sync, so this is a node taking 76
// seconds to come up on a config that commits clean.
//
// WHY THIS CELL EXISTS AT ALL. Every correctness test stays GREEN if someone
// moves the call back inside the loop — the advisories are identical either
// way, only the cost changes. A perf fix with only correctness cells silently
// regresses, which is the shape of #6897 on this board: the property nobody
// asserted was the property that broke.
//
// WHY CALL COUNT AND NOT WALL CLOCK. A timing assertion has to pick a
// threshold, and a threshold on a shared machine is either flaky or so loose it
// stops failing. The call count is deterministic, has no timing component, and
// fails for exactly the right reason — it goes from 1 to Z the moment the call
// re-enters the loop.
func TestHostInboundResolverCalledOncePerValidate8854(t *testing.T) {
	orig := resolveInterfaceHostInboundFn
	defer func() { resolveInterfaceHostInboundFn = orig }()

	// Several zone counts, because "calls == 1" is trivially true for a
	// one-zone config: with the defect the count equals the ZONE COUNT, so a
	// single-zone fixture cannot tell the fixed code from the broken code.
	for _, zones := range []int{1, 2, 8, 32} {
		t.Run(fmt.Sprintf("zones=%d", zones), func(t *testing.T) {
			calls := 0
			resolveInterfaceHostInboundFn = func(c *Config) map[string]*HostInboundTraffic {
				calls++
				return orig(c)
			}
			tree, perrs := NewParser(hostInboundZonesFixture8854(zones)).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile must succeed: %v", err)
			}
			// The fixture must actually reach the advisory pass, or "calls == 1"
			// would be satisfied by never running it.
			if got := len(cfg.Security.Zones); got != zones {
				t.Fatalf("fixture compiled %d zones, want %d — the pass may not "+
					"have been exercised", got, zones)
			}
			if calls == 0 {
				t.Fatalf("the resolver was never called for %d zones, so this "+
					"cell measured nothing", zones)
			}
			if calls != 1 {
				t.Errorf("ResolveInterfaceHostInbound was called %d times for %d "+
					"zones, want exactly 1. The call is loop-invariant — it takes "+
					"only cfg — so a per-zone call makes the TOLERANT compile "+
					"quadratic (76s at 8000 zones), and the tolerant path is boot "+
					"and HA peer-sync (#8854).", calls, zones)
			}
		})
	}
}

// hostInboundZonesFixture8854 builds a config whose zones carry PER-INTERFACE
// host-inbound stanzas. That detail is load-bearing: ResolveInterfaceHostInbound
// iterates zone.InterfaceHostInbound and skips a zone with none, so a fixture
// carrying only the ZONE-level `host-inbound-traffic` stanza resolves to an
// EMPTY map and exercises none of the work this cell is about.
func hostInboundZonesFixture8854(zones int) string {
	var b strings.Builder
	b.WriteString("interfaces {\n")
	for i := 0; i < zones; i++ {
		b.WriteString(fmt.Sprintf("    ge-0/0/%d { unit 0 { family inet { address 10.%d.0.1/24; } } }\n", i, i%250))
	}
	b.WriteString("}\nsecurity {\n    zones {\n")
	for i := 0; i < zones; i++ {
		b.WriteString(fmt.Sprintf(
			"        security-zone z%d { interfaces { ge-0/0/%d.0 { host-inbound-traffic { system-services ping; } } } }\n", i, i))
	}
	b.WriteString("    }\n}\n")
	return b.String()
}
