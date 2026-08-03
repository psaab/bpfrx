package config

import (
	"fmt"
	"strings"
	"testing"
)

// Tests for #6812 (opus-review-001 R73): SourceNATAggregateOverBudgetPools —
// the deterministic FIRST-FIT admission that picks WHICH referenced pools do
// not fit the #5877 aggregate budgets, so the tolerant snapshot builder
// (pkg/dataplane/userspace/nat_source.go) can poison exactly those pools
// instead of shipping them to a dataplane that would eagerly build their
// per-address occupancy bitmaps (three full-range /16 pools = 12,683,575,296
// bitmap bits, ~1.48 GiB).
//
// The fixtures reuse the #5877 helpers (snat5877Tree / snat5877Pools /
// distinctSlash16 / distinctHostIP) and compile via the LENIENT path: the
// strict path rejects these configs outright, so the poison set only ever
// matters for tolerated configs.
//
// FAIL-ON-REVERT: any change that drops pools from the poison set (or stops
// charging a budget) turns the over-budget cases GREEN -> RED here; a change
// that over-rejects (poisons pools that fit) turns the at-budget / first-fit
// cases RED.

// poisonSet compiles the fixture leniently and returns the over-budget pool
// set, failing the test on compile error.
func poisonSet(t *testing.T, cmds ...string) map[string]bool {
	t.Helper()
	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return SourceNATAggregateOverBudgetPools(cfg)
}

func assertPoison(t *testing.T, got map[string]bool, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("poison set = %v, want exactly %v", got, want)
	}
	for _, name := range want {
		if !got[name] {
			t.Fatalf("poison set = %v, missing %q (want %v)", got, name, want)
		}
	}
}

// TestAggregateOverBudgetPoolsPortCapacity_6812 pins the port-capacity
// budget walk on the review's exact scenario: three full-range /16 pools
// (65,536 addresses x 64,512 default PAT slots ≈ 4.23e9 each). Two fit under
// 2^33; the third does not — and ONLY the third is poisoned.
func TestAggregateOverBudgetPoolsPortCapacity_6812(t *testing.T) {
	assertPoison(t,
		poisonSet(t, snat5877Pools(3, distinctSlash16, "")...),
		"p2")
	// Two full-range /16 pools sit just under the budget: nothing poisoned.
	assertPoison(t,
		poisonSet(t, snat5877Pools(2, distinctSlash16, "")...))
}

// TestAggregateOverBudgetPoolsAddresses_6812 pins the total-address budget:
// 17 x /16 = 1,114,112 hosts exceeds 1,048,576; only pool 16 is poisoned.
func TestAggregateOverBudgetPoolsAddresses_6812(t *testing.T) {
	assertPoison(t,
		poisonSet(t, snat5877Pools(17, distinctSlash16, "5000 to 5001")...),
		"p16")
	// Exactly at the budget: nothing poisoned.
	assertPoison(t,
		poisonSet(t, snat5877Pools(16, distinctSlash16, "5000 to 5001")...))
}

// TestAggregateOverBudgetPoolsCount_6812 pins the distinct-pool COUNT
// budget: pools 0..1023 fit, pool 1024 (the 1025th) is poisoned.
func TestAggregateOverBudgetPoolsCount_6812(t *testing.T) {
	assertPoison(t,
		poisonSet(t, snat5877Pools(MaxSourceNATPoolCount+1, distinctHostIP, "")...),
		fmt.Sprintf("p%d", MaxSourceNATPoolCount))
}

// TestAggregateOverBudgetPoolsFirstFit_6812 pins the first-fit-continue
// rule (parity with the Rust resolve_pool_allocators): a pool that is
// refused does NOT consume budget, so a later, smaller pool still installs.
// p1 alone (17 x /16 members = 1,114,112 addresses) exceeds the address
// budget by itself; p0 and p2 are tiny and must survive.
func TestAggregateOverBudgetPoolsFirstFit_6812(t *testing.T) {
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source pool p0 address 203.0.113.1/32",
		"set security nat source rule-set RS rule r0 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule r0 then source-nat pool p0",
	}
	// p1: 17 distinct /16 members in ONE pool — over the 1,048,576-address
	// aggregate budget on its own.
	for i := 0; i < 17; i++ {
		cmds = append(cmds, fmt.Sprintf("set security nat source pool p1 address 10.%d.0.0/16", i))
	}
	cmds = append(cmds,
		"set security nat source rule-set RS rule r1 match source-address 10.0.1.0/24",
		"set security nat source rule-set RS rule r1 then source-nat pool p1",
		"set security nat source pool p2 address 203.0.113.2/32",
		"set security nat source rule-set RS rule r2 match source-address 10.0.2.0/24",
		"set security nat source rule-set RS rule r2 then source-nat pool p2",
	)
	assertPoison(t, poisonSet(t, cmds...), "p1")
}

// TestAggregateOverBudgetPoolsUnreferenced_6812 pins the scoping parity with
// the strict gate: pools no pool-mode rule references never reach the
// allocator and are never poisoned, however large.
func TestAggregateOverBudgetPoolsUnreferenced_6812(t *testing.T) {
	cmds := []string{}
	for i := 0; i < 64; i++ {
		cmds = append(cmds, fmt.Sprintf("set security nat source pool orphan%d address 203.0.113.0/16", i))
	}
	assertPoison(t, poisonSet(t, cmds...))
}

// TestAggregateValidatorMatchesPoisonWalk_6812 pins validator/poison
// agreement: whenever the strict validator rejects, the poison set is
// non-empty (the tolerant path degrades the same config per-pool); whenever
// the validator accepts, the poison set is empty (no over-reject). This is
// the drift guard for the shared sourceNATAggregateReferencedCharges walk.
func TestAggregateValidatorMatchesPoisonWalk_6812(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"count-over", snat5877Pools(MaxSourceNATPoolCount+1, distinctHostIP, "")},
		{"count-at", snat5877Pools(MaxSourceNATPoolCount, distinctHostIP, "")},
		{"addrs-over", snat5877Pools(17, distinctSlash16, "5000 to 5001")},
		{"addrs-at", snat5877Pools(16, distinctSlash16, "5000 to 5001")},
		{"cap-over", snat5877Pools(3, distinctSlash16, "")},
		{"cap-at", snat5877Pools(2, distinctSlash16, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := snat5877Tree(t, tc.cmds...)
			_, strictErr := CompileConfig(tree)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			poison := SourceNATAggregateOverBudgetPools(cfg)
			over := strings.HasSuffix(tc.name, "-over")
			if strictErr == nil == over {
				t.Fatalf("strict reject = %v, want over-budget = %v (err %v)", !over, over, strictErr)
			}
			if over && len(poison) == 0 {
				t.Fatalf("over-budget config must poison at least one pool on the tolerant path")
			}
			if !over && len(poison) != 0 {
				t.Fatalf("at-budget config must poison nothing, got %v", poison)
			}
		})
	}
}
