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

// snat6812UnusablePools emits `n` referenced pools that the snapshot builder
// will independently mark UNUSABLE (poolCmds decides how), followed by ONE
// small healthy pool "good" referenced LAST. Every unusable pool carries a
// single distinct /32 so the ONLY aggregate axis these fixtures can cross is
// the distinct-pool COUNT — the address and port-capacity budgets stay orders
// of magnitude below their limits, so a poison verdict here cannot be
// attributed to another axis.
func snat6812UnusablePools(n int, poolCmds func(i int, name string) []string) []string {
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("bad%d", i)
		cmds = append(cmds, poolCmds(i, name)...)
		cmds = append(cmds,
			fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool %s", i, name),
		)
	}
	// The healthy pool is referenced LAST, so under the first-fit walk it is
	// the one an over-charge of the unusable pools would refuse.
	return append(cmds,
		"set security nat source pool good address 198.51.100.7/32",
		"set security nat source pool good port range 10000 to 10009",
		fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", n),
		fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool good", n),
	)
}

// TestAggregateBudgetExcludesUnusablePools_6812 is the #6812 F1 regression
// (Codex gate finding): a pool the snapshot builder ALREADY marks unusable
// builds NO allocator in the dataplane — the Rust parse loop gates
// `PendingPoolAllocator` on `pool_failure.is_none()`
// (userspace-dp/src/nat/source.rs), so a failed pool is never charged and
// never occupies a slot in `resolve_pool_allocators`' first-fit walk. Charging
// it Go-side therefore refuses a pool Rust would admit.
//
// The concrete damage is fail-closed OVER-rejection on the TOLERANT recovery
// path — a lenient load / peer-sync (#1960 no-brick) is precisely how an
// operator gets back to a working state, and this took a healthy pool down
// with the broken ones. MaxSourceNATPoolCount unusable pools exactly fill the
// count budget, so the healthy pool referenced after them was poisoned as
// number 1,025.
//
// The dataplane half of the parity claim is
// `production_entry_admits_a_healthy_pool_after_failed_pools_6812`
// (userspace-dp/src/nat/tests_aggregate_budget.rs), which drives the SAME
// scenario — MaxSourceNATPoolCount unusable pools then one healthy pool —
// through the Rust production entry and asserts the healthy pool installs a
// real allocator. The snapshot-shape half (that Go actually emits the
// `pool_unusable` markers that test consumes) is
// TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812
// (pkg/dataplane/userspace).
//
// RED-on-revert: restore the unconditional charge in
// sourceNATAggregateReferencedCharges and the poison set comes back
// {"good"} — the healthy pool disabled by pools that install nothing.
func TestAggregateBudgetExcludesUnusablePools_6812(t *testing.T) {
	cases := []struct {
		name string
		// wantReason is what SourceNATPoolUnusableReason must say about the
		// fixture's pools. "" is NOT an omission: it is the unparseable-member
		// case, where the pool DEFINITION is fine and the pool is skipped by the
		// zero-expanded-addresses rule instead.
		wantReason string
		cmds       func(i int, name string) []string
		about      string
	}{
		{
			name:       "invalid_port_range",
			wantReason: "invalid_port_range",
			about:      "a reversed `port range` leaves PortRangeInvalidSpec set (#5457); the builder marks the pool unusable",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address 10.%d.%d.1/32", name, i/256, i%256),
					fmt.Sprintf("set security nat source pool %s port range 20000 to 10000", name),
				}
			},
		},
		{
			name:       "zone_scoped_pool_address",
			wantReason: "zone_scoped_pool_address",
			about:      "a `%zone` member is not dataplane-representable (#5875); the builder marks the pool unusable",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address fe80::%d%%eth0", name, i+1),
				}
			},
		},
		{
			name:       "empty_pool",
			wantReason: "empty_pool",
			about:      "a referenced pool with no address member ships nothing; the builder marks the pool unusable",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s port range 10000 to 10009", name),
				}
			},
		},
		{
			// The pool definition itself is fine — members present, no zone
			// qualifier, valid port range — so SourceNATPoolUnusableReason says
			// nothing and the snapshot ships the raw strings. It is RUST that
			// refuses: expand_pool_address fails on every member, total_pool is
			// 0, the `allocator_key()` gate skips the rule, and it fails as
			// InvalidPool at the boundary having built nothing. This is the case
			// the zero-expanded-addresses skip exists for, and the ONLY one that
			// binds it.
			name:       "no_member_expands",
			wantReason: "",
			about:      "every member is unparseable, so Rust expands zero addresses and builds no allocator",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address 999.999.999.%d", name, i%256),
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := snat6812UnusablePools(MaxSourceNATPoolCount, tc.cmds)
			cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			// PRECONDITION: the fixture really did build MaxSourceNATPoolCount
			// unusable pools plus the healthy one. Without this a fixture that
			// silently dropped its pools would pass the assertion below while
			// exercising nothing.
			if got := len(cfg.Security.NAT.SourcePools); got != MaxSourceNATPoolCount+1 {
				t.Fatalf("fixture defined %d pools, want %d — the scenario never reached the budget",
					got, MaxSourceNATPoolCount+1)
			}
			if reason := SourceNATPoolUnusableReason(cfg.Security.NAT.SourcePools["bad0"]); reason != tc.wantReason {
				t.Fatalf("bad0 unusable reason = %q, want %q (%s); the fixture is not building the shape under test",
					reason, tc.wantReason, tc.about)
			}
			// For the unparseable-member case, also pin the premise the skip
			// rests on: Go expands zero addresses from these members, which is
			// what makes Rust's `total_pool > 0` gate skip the rule too.
			if tc.wantReason == "" {
				for _, m := range SourceNATPoolMembers(cfg.Security.NAT.SourcePools["bad0"]) {
					if n := sourceNATPoolMemberHostCount(m); n != 0 {
						t.Fatalf("member %q expands to %d addresses, want 0 — the fixture is not "+
							"the zero-expansion case and the skip under test is not being exercised", m, n)
					}
				}
			}
			if reason := SourceNATPoolUnusableReason(cfg.Security.NAT.SourcePools["good"]); reason != "" {
				t.Fatalf("the healthy pool is itself unusable (%q); the fixture proves nothing", reason)
			}
			// THE DISCRIMINATOR: pools that build no allocator must not consume
			// aggregate budget, so nothing is poisoned.
			poison := SourceNATAggregateOverBudgetPools(cfg)
			if poison["good"] {
				t.Fatalf("the healthy pool was poisoned %q by %d pools that build NO allocator "+
					"(%s) — fail-closed over-rejection on the tolerant recovery path, and a "+
					"divergence from the Rust walk, which skips failed pools entirely",
					"aggregate_over_budget", MaxSourceNATPoolCount, tc.name)
			}
			if len(poison) != 0 {
				t.Fatalf("poison set = %v, want empty — no pool in this fixture crosses a budget "+
					"once the unusable pools are excluded", poison)
			}
		})
	}
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
