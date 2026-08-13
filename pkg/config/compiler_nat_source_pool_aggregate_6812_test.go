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
		// fixture's pools. Every case now names a reason: since round 2 the
		// shared verdict is the ONLY exclusion, so a "" here would mean the pool
		// is charged and the case is not testing an exclusion at all.
		wantReason string
		// wantSum is the round-1 host-count sum for ONE of these pools — the
		// derived quantity the budget walk used to consult. It is asserted
		// exactly, because it is what separates the classes: a case with sum 0
		// was already excluded by the old zero-total rule, while a case with a
		// NON-ZERO sum was charged by round 1 and is only excluded now that the
		// walk asks the runtime's all-or-nothing question instead. Without this
		// the two round-2 cases would be indistinguishable from the round-1 ones
		// and could pass on the old code path.
		wantSum uint64
		cmds    func(i int, name string) []string
		about   string
	}{
		{
			name:       "invalid_port_range",
			wantReason: "invalid_port_range",
			wantSum:    1, // one /32 member
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
			wantSum:    1, // netip parses a zoned bare address
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
			wantSum:    0, // no members at all
			about:      "a referenced pool with no address member ships nothing; the builder marks the pool unusable",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s port range 10000 to 10009", name),
				}
			},
		},
		{
			// RE-CUT IN ROUND 2. This cell used to assert wantReason "": the
			// pool definition looked fine (members present, no zone qualifier,
			// valid port range), so the shared predicate said nothing and the
			// budget walk skipped the pool only because its members summed to
			// ZERO expanded addresses. It now binds through the shared verdict
			// instead — the membership grammar clause rejects the member, so the
			// pool is excluded for the same reason every other unusable pool is.
			// The cell is NOT green by construction: "invalid_pool" is a
			// distinct, asserted value that only the new clause produces, and
			// the discriminator below still fails if the pool is charged.
			name:       "no_member_expands",
			wantReason: "invalid_pool",
			wantSum:    0, // the round-1 zero-total path
			about:      "every member is unparseable, so Rust expands zero addresses and builds no allocator",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address 999.999.999.%d", name, i%256),
				}
			},
		},
		{
			// ROUND 2 ORDERING GUARD. A zone-scoped CIDR fails BOTH the
			// membership grammar (netip.ParsePrefix rejects a zone qualifier
			// outright) and the #5875 zone check. The grammar clause is placed
			// BELOW zone_scoped_pool_address precisely so this member keeps
			// reporting the specific reason it reported before round 2 — a
			// comment says so in SourceNATPoolUnusableReason, and this cell is
			// what makes that true rather than merely stated. Swap the two
			// clauses and this reds with "invalid_pool".
			//
			// The STRICT path is unaffected either way: the zone-scope gate
			// (runUniformGatesNAT:163) precedes the address-grammar gate
			// (:189), so the commit diagnostic still names zone/scope —
			// TestSourceNATPoolZoneScopedAddressRejected/scoped-cidr.
			name:       "zone_scoped_prefix",
			wantReason: "zone_scoped_pool_address",
			wantSum:    0, // ParsePrefix rejects the zone, so the member counts 0
			about:      "a zone-scoped CIDR fails the grammar too; the #5875 reason must still win",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address fe80::%d%%eth0/64", name, i+1),
				}
			},
		},
		{
			// ROUND 2, THE FIFTH CLASS (Codex re-gate at a00a03fc1). One
			// honorable member plus one malformed member. The runtime is
			// ALL-OR-NOTHING — expand_pool_address failing on ANY member sets
			// `invalid_pool_address` and fails the WHOLE pool as InvalidPool, so
			// the dataplane builds no allocator — but the round-1 budget walk
			// summed host counts (1 + 0 = 1), found the total non-zero, and
			// charged the pool. 1,024 of them consumed the entire pool-count
			// budget and poisoned the healthy pool referenced after them.
			//
			// Neither of the two round-1 skips caught it: the pool is not
			// unusable by the definition checks, and its expanded count is not
			// zero. That is why round 2 replaced the derived quantity with the
			// runtime's own verdict rather than adding a fifth condition.
			name:       "some_member_fails",
			wantReason: "invalid_pool",
			wantSum:    1, // 1 + 0: NON-zero, so round 1 charged it
			about:      "one malformed member among honorable ones fails the WHOLE pool in Rust",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address 198.51.100.%d", name, i%256),
					fmt.Sprintf("set security nat source pool %s address not-an-ip", name),
				}
			},
		},
		{
			// ROUND 2, the same class reached by CAPACITY rather than grammar.
			// `10.<i>.0.0/15` parses cleanly and expands to 131,072 hosts —
			// twice MaxSourceNATPoolPrefixHosts — so expand_pool_address refuses
			// it and the pool builds nothing. Round 1 charged it 131,072
			// addresses (and 8,455,716,864 port-capacity slots) against budgets
			// of 1,048,576 and 2^33: eight such pools exhausted the address
			// budget and one alone exhausted the port capacity, all on behalf of
			// allocators that never exist. It survived the zero-total skip
			// precisely because it expands to a large number, not to nothing.
			name:       "member_over_capacity",
			wantReason: "invalid_pool",
			wantSum:    131072, // 2x the 65,536 allocator cap
			about:      "an over-capacity /15 expands to 131,072 hosts, above the 65,536 allocator cap",
			cmds: func(i int, name string) []string {
				return []string{
					// Even /15 bases (i*2 % 256) keep each prefix canonical and
					// distinct, so the fixture is 1,024 genuinely separate pools.
					fmt.Sprintf("set security nat source pool %s address 10.%d.0.0/15", name, (i*2)%256),
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
			// Pin the DERIVED QUANTITY round 1 consulted, so each case is
			// provably the class it claims to be. A non-zero sum means round 1
			// charged this pool: those cases (some_member_fails,
			// member_over_capacity) are excluded only because the walk now asks
			// the runtime's all-or-nothing question. A zero sum means the old
			// zero-total rule already excluded it.
			var sum uint64
			for _, m := range SourceNATPoolMembers(cfg.Security.NAT.SourcePools["bad0"]) {
				sum = checkedAddU64(sum, sourceNATPoolMemberHostCount(m))
			}
			if sum != tc.wantSum {
				t.Fatalf("bad0 host-count sum = %d, want %d — the fixture is not the class under "+
					"test (%s), so the exclusion it exercises is not the one this case names",
					sum, tc.wantSum, tc.name)
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

// TestBudgetChargeImpliesHonorableMembers_6812 binds the invariant that
// replaced the zero-expanded-addresses skip in sourceNATAggregateReferencedCharges
// (#6812 F1 round 2).
//
// The skip was deleted rather than kept as a belt because it became
// UNREACHABLE: the shared verdict is all-or-nothing over
// sourceNATPoolAddressReason, so any pool with a member that fails to parse is
// already excluded, and a pool with no members reports empty_pool. A charged
// pool therefore has at least one member, every member parses, and a parsing
// member has a host count of at least 1.
//
// Deleting a branch leaves nothing to test, so this tests the two premises the
// deletion rests on, over the full grammar surface:
//
//  1. HONORABLE => COUNTABLE. Every member sourceNATPoolAddressReason accepts
//     has sourceNATPoolMemberHostCount >= 1. If this ever fails, a charged pool
//     could sum to zero and the deleted branch would be needed again.
//  2. The walk never emits a zero-address charge, driven through the real
//     compiler over the same member shapes.
//
// RED-on-revert: make sourceNATPoolAddressReason accept an unparseable member
// (e.g. return ("", true) unconditionally) and premise 1 reds on "not-an-ip"
// with hostCount 0 — the exact combination that made the fifth class possible.
func TestBudgetChargeImpliesHonorableMembers_6812(t *testing.T) {
	// The grammar surface: accepted and rejected shapes, v4 and v6, bare and
	// CIDR, at and over the prefix cap.
	members := []string{
		"198.51.100.1", "198.51.100.0/32", "203.0.113.0/28", "10.0.0.0/16",
		"2001:db8::1", "2001:db8::/128", "2001:db8::/112",
		"not-an-ip", "203.0.113.1/garbage", "999.999.999.1", "",
		"10.0.0.0/15", "10.0.0.0/8", "2001:db8::/111", "::/0",
		"fe80::1%eth0", "fe80::/112%eth0",
	}
	for _, m := range members {
		_, ok := sourceNATPoolAddressReason(m)
		n := sourceNATPoolMemberHostCount(m)
		if ok && n == 0 {
			t.Fatalf("member %q is honorable by the shared grammar but expands to 0 addresses: "+
				"a pool of such members would be CHARGED with a zero total, the shape the "+
				"deleted zero-expanded-addresses skip used to catch", m)
		}
	}

	// Premise 2, through the real compiler: no charge is ever zero-address,
	// whatever mix of honorable and rejected members a pool carries.
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i, m := range members {
		if m == "" {
			continue // not expressible as a `set` token
		}
		cmds = append(cmds,
			fmt.Sprintf("set security nat source pool q%d address 198.51.100.1", i),
			fmt.Sprintf("set security nat source pool q%d address %s", i, m),
			fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool q%d", i, i),
		)
	}
	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	charges := sourceNATAggregateReferencedCharges(cfg)
	if len(charges) == 0 {
		t.Fatal("no pool was charged at all — the fixture proves nothing about charged pools")
	}
	for _, c := range charges {
		if c.addrs == 0 {
			t.Fatalf("pool %s was charged with 0 expanded addresses; the invariant that let the "+
				"zero-total skip be deleted no longer holds", c.name)
		}
		// And the charged set is exactly the honorable one.
		if reason := SourceNATPoolUnusableReason(cfg.Security.NAT.SourcePools[c.name]); reason != "" {
			t.Fatalf("pool %s was charged despite being unusable (%q)", c.name, reason)
		}
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
