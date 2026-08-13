// #6812 (opus-review-001 R73): the #5877 aggregate cardinality gate is
// warning-only on the tolerant load / peer-sync path (#1960 no-brick), so a
// tolerated over-budget source-NAT config used to reach the snapshot builder
// intact — and the Rust apply boundary then EAGERLY built every pool's
// per-address occupancy bitmap (three full-range /16 pools = 12,683,575,296
// bitmap bits, ~1.48 GiB) before any reuse check. The builder now poisons
// exactly the pools that do not fit the budget
// (config.SourceNATAggregateOverBudgetPools, the same first-fit admission the
// Rust resolve_pool_allocators enforces at the boundary): the affected rules
// install nothing (fail-closed, "aggregate_over_budget"), the pools that fit
// are untouched, and the compile-time warning still tells the operator to
// shrink the config.
//
// RED-on-revert (poison block in nat_source.go removed): the p2 snapshot
// comes back PoolUnusable=false and ships its full /16 member to the
// dataplane — the eager-bitmap path re-opens.
package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// snatAggregateCfg_6812 compiles (lenient — the tolerant path this guard
// exists for) a config with n /16 pools at the DEFAULT 1024-65535 PAT range,
// each referenced by its own pool-mode rule: the review's R73 fixture.
// distinctSlash16_6812 returns a distinct, non-overlapping, PARSEABLE /16 per
// pool index for i in [0, 1280).
//
// #6812 F1 round 2 — fixture correction. This helper replaces an inline
// `10.<i>.0.0/16`, which is only a valid address for i < 256: at
// MaxSourceNATPoolCount+1 pools, indices 256..1024 emitted `10.256.0.0/16` and
// beyond, which netip cannot parse. Those 769 pools were NOT the "healthy pools
// past the budget" the over-reach control below claims to exercise — they
// expanded to zero addresses and were skipped by the (now removed) zero-total
// rule, so the control's poison set came from the 256 genuinely valid /16s
// alone. The bug was invisible while the budget walk inferred usability from a
// host-count sum; the shared all-or-nothing verdict names it ("invalid_pool"),
// which is how it surfaced.
func distinctSlash16_6812(i int) string {
	return fmt.Sprintf("%d.%d.0.0/16", 10+i/256, i%256)
}

func snatAggregateCfg_6812(t *testing.T, n int) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i := 0; i < n; i++ {
		cmds = append(cmds,
			fmt.Sprintf("set security nat source pool p%d address %s", i, distinctSlash16_6812(i)),
			fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool p%d", i, i),
		)
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	// PRECONDITION (#6812 F1 round 2): this fixture stands for HEALTHY pools —
	// every test built on it asserts something about pools the dataplane WOULD
	// install. A pool that is unusable from its definition is excluded from the
	// aggregate budget by design, so an accidentally-malformed address here
	// would silently shrink the charged set and make the over-reach control
	// below prove less than it claims (which is exactly what `10.<i>.0.0/16`
	// did past index 255). Fail by name instead.
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("p%d", i)
		if reason := config.SourceNATPoolUnusableReason(cfg.Security.NAT.SourcePools[name]); reason != "" {
			t.Fatalf("fixture pool %s (address %s) is unusable (%q) — this fixture must emit "+
				"only pools the dataplane would install, or the budget assertions built on it "+
				"are charging fewer pools than they claim",
				name, distinctSlash16_6812(i), reason)
		}
	}
	return cfg
}

func snapByPool_6812(t *testing.T, snaps []SourceNATRuleSnapshot, pool string) SourceNATRuleSnapshot {
	t.Helper()
	for _, s := range snaps {
		if s.PoolName == pool {
			return s
		}
	}
	t.Fatalf("no snapshot for pool %q (have %d snapshots)", pool, len(snaps))
	return SourceNATRuleSnapshot{}
}

// TestSourceNATSnapshotAggregateOverBudgetPoisoned_6812: of three
// full-range /16 pools (the review's 12.7 Gbit scenario), the two that fit
// the 2^33 port-capacity budget ship intact and the third is poisoned —
// fail-closed, with the precise reason — instead of forcing the eager
// bitmap.
func TestSourceNATSnapshotAggregateOverBudgetPoisoned_6812(t *testing.T) {
	cfg := snatAggregateCfg_6812(t, 3)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 3 {
		t.Fatalf("snapshots = %d, want 3", len(snaps))
	}
	for _, pool := range []string{"p0", "p1"} {
		s := snapByPool_6812(t, snaps, pool)
		if s.PoolUnusable {
			t.Fatalf("%s: PoolUnusable = true (reason %q), want false — pools within the budget must ship intact (no over-reject)", pool, s.PoolUnusableReason)
		}
		if len(s.PoolAddresses) != 1 {
			t.Fatalf("%s: PoolAddresses = %v, want the single /16 member", pool, s.PoolAddresses)
		}
	}
	s := snapByPool_6812(t, snaps, "p2")
	if !s.PoolUnusable {
		t.Fatalf("p2: PoolUnusable = false, want true — the pool crossing the aggregate budget must fail closed (on revert its /16 ships and the dataplane builds the 12.7 Gbit bitmap)")
	}
	if s.PoolUnusableReason != "aggregate_over_budget" {
		t.Fatalf("p2: PoolUnusableReason = %q, want %q", s.PoolUnusableReason, "aggregate_over_budget")
	}
}

// snatUnusablePlusHealthyCfg_6812 compiles (leniently — the tolerant recovery
// path this guard exists for) a config with `nBad` referenced pools whose
// `port range` is REVERSED, so #5457 leaves PortRangeInvalidSpec set and the
// builder marks each one unusable, followed by ONE healthy pool referenced
// LAST. Every pool is a single /32 so the only aggregate axis in play is the
// distinct-pool COUNT.
func snatUnusablePlusHealthyCfg_6812(t *testing.T, nBad int) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i := 0; i < nBad; i++ {
		cmds = append(cmds,
			fmt.Sprintf("set security nat source pool bad%d address 10.%d.%d.1/32", i, i/256, i%256),
			fmt.Sprintf("set security nat source pool bad%d port range 20000 to 10000", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool bad%d", i, i),
		)
	}
	cmds = append(cmds,
		"set security nat source pool good address 198.51.100.7/32",
		"set security nat source pool good port range 10000 to 10009",
		fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", nBad),
		fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool good", nBad),
	)
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812 is the Go half of
// the #6812 F1 parity regression (Codex gate finding). It drives the whole
// builder — poison walk included — on the tolerant recovery path and asserts
// the SNAPSHOT that reaches the dataplane.
//
// MaxSourceNATPoolCount pools with a reversed `port range` are already unusable
// and build NO allocator in Rust (the parse loop gates PendingPoolAllocator on
// `pool_failure.is_none()`), so they must not consume the aggregate pool-count
// budget. Before the fix they consumed all 1,024 slots and the healthy pool
// referenced after them shipped PoolUnusable=true / "aggregate_over_budget" —
// a pool the dataplane would have installed, disabled on the one path (lenient
// load / peer-sync, #1960 no-brick) an operator uses to recover.
//
// This test also PINS the snapshot shape that the Rust half consumes:
// `production_entry_admits_a_healthy_pool_after_failed_pools_6812`
// (userspace-dp/src/nat/tests_aggregate_budget.rs) builds its 1,024 refused
// pools with exactly the PoolUnusable / "invalid_port_range" markers asserted
// below, then drives the Rust production entry and asserts the healthy pool
// installs a real allocator. If this builder ever stops emitting that shape,
// this test reds and the Rust fixture stops standing for anything real.
//
// RED-on-revert (drop the SourceNATPoolUnusableReason skip in
// sourceNATAggregateReferencedCharges): the "good" snapshot comes back
// PoolUnusable=true with reason "aggregate_over_budget".
func TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812(t *testing.T) {
	nBad := config.MaxSourceNATPoolCount
	cfg := snatUnusablePlusHealthyCfg_6812(t, nBad)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != nBad+1 {
		t.Fatalf("snapshots = %d, want %d — the fixture never reached the pool-count budget",
			len(snaps), nBad+1)
	}

	// PRECONDITION + Rust-fixture contract: every bad pool ships unusable for
	// its OWN reason, not the aggregate one. A fixture whose "bad" pools were
	// actually healthy would fill the budget legitimately and prove nothing.
	for i := 0; i < nBad; i++ {
		s := snapByPool_6812(t, snaps, fmt.Sprintf("bad%d", i))
		if !s.PoolUnusable || s.PoolUnusableReason != "invalid_port_range" {
			t.Fatalf("bad%d: PoolUnusable=%v reason=%q, want true/%q — the fixture is not "+
				"building pools that fail before the aggregate walk, so the healthy-pool "+
				"assertion below would prove nothing",
				i, s.PoolUnusable, s.PoolUnusableReason, "invalid_port_range")
		}
	}

	// THE DISCRIMINATOR: the healthy pool survives, and ships intact.
	good := snapByPool_6812(t, snaps, "good")
	if good.PoolUnusable {
		t.Fatalf("good: PoolUnusable = true (reason %q), want false — %d pools that build NO "+
			"allocator consumed the whole pool-count budget and disabled a healthy pool. "+
			"The Rust walk (resolve_pool_allocators) skips failed pools entirely and would "+
			"have installed this one, so the two sides disagree about which pools live",
			good.PoolUnusableReason, nBad)
	}
	if len(good.PoolAddresses) != 1 || good.PoolAddresses[0] != "198.51.100.7/32" {
		t.Fatalf("good: PoolAddresses = %v, want [198.51.100.7/32]", good.PoolAddresses)
	}
	if good.PortLow != 10000 || good.PortHigh != 10009 {
		t.Fatalf("good: port range = %d-%d, want 10000-10009 (the shape the Rust half builds)",
			good.PortLow, good.PortHigh)
	}
}

// TestSourceNATSnapshotAggregateStillPoisonsPastBudget_6812 is the over-reach
// control for the test above, in its own body so it still runs when that one
// fails. The pool-count budget must keep firing for HEALTHY pools: excluding
// unusable pools from the charge must not be over-read as excluding everything.
//
// Stays GREEN under the F1 revert (which only ever charges MORE), which is what
// makes it a control rather than a restatement of the fix.
func TestSourceNATSnapshotAggregateStillPoisonsPastBudget_6812(t *testing.T) {
	cfg := snatAggregateCfg_6812(t, config.MaxSourceNATPoolCount+1)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != config.MaxSourceNATPoolCount+1 {
		t.Fatalf("snapshots = %d, want %d", len(snaps), config.MaxSourceNATPoolCount+1)
	}
	// snatAggregateCfg_6812 emits /16 pools, so the port-capacity budget binds
	// first: the poisoned set is every pool past the point where 2^33 slots are
	// consumed. What this control asserts is that the cap still fires at all.
	poisoned := 0
	for _, s := range snaps {
		if s.PoolUnusable {
			if s.PoolUnusableReason != "aggregate_over_budget" {
				t.Fatalf("%s: reason = %q, want %q", s.PoolName, s.PoolUnusableReason, "aggregate_over_budget")
			}
			poisoned++
		}
	}
	if poisoned == 0 {
		t.Fatalf("%d healthy referenced pools poisoned nothing: the aggregate cap stopped "+
			"firing for pools that DO build allocators", config.MaxSourceNATPoolCount+1)
	}
	if snaps[0].PoolUnusable {
		t.Fatalf("the first pool — far below every budget — was poisoned %q; the cap is "+
			"rejecting configs it must admit", snaps[0].PoolUnusableReason)
	}
}

// TestSourceNATSnapshotAggregateAtBudgetUnaffected_6812: two full-range /16
// pools sit just under the 2^33 port-capacity budget — the guard must not
// fire at all (no over-reject of a legal, if large, tolerated config).
func TestSourceNATSnapshotAggregateAtBudgetUnaffected_6812(t *testing.T) {
	cfg := snatAggregateCfg_6812(t, 2)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2", len(snaps))
	}
	for _, s := range snaps {
		if s.PoolUnusable {
			t.Fatalf("%s: PoolUnusable = true (reason %q), want false at budget", s.PoolName, s.PoolUnusableReason)
		}
	}
}

// snatMixedMemberPlusHealthyCfg_6812 emits nBad referenced pools that each mix
// ONE honorable member with one member the Rust expander refuses, followed by a
// small healthy pool "good" referenced LAST. `mkBad` supplies the refused
// member.
//
// This is the round-2 fifth-class fixture. Unlike snatUnusablePlusHealthyCfg_6812
// (whose pools fail on their DEFINITION — a reversed port range), every pool
// here looks well-formed to the definition checks: members present, no `%zone`
// qualifier, a valid default port range. It is the MEMBERSHIP that the dataplane
// refuses, and it refuses the whole pool for one bad member.
func snatMixedMemberPlusHealthyCfg_6812(t *testing.T, nBad int, mkBad func(i int) string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i := 0; i < nBad; i++ {
		cmds = append(cmds,
			fmt.Sprintf("set security nat source pool bad%d address 198.51.100.%d", i, i%256),
			fmt.Sprintf("set security nat source pool bad%d address %s", i, mkBad(i)),
			fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool bad%d", i, i),
		)
	}
	cmds = append(cmds,
		"set security nat source pool good address 198.51.100.7/32",
		"set security nat source pool good port range 10000 to 10009",
		fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", nBad),
		fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool good", nBad),
	)
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// TestSourceNATSnapshotMixedMemberPoolsDoNotPoisonHealthy_6812 is the round-2
// F1 regression at the SNAPSHOT boundary — the wire the operator's translation
// actually depends on.
//
// The dataplane's pool grammar is ALL-OR-NOTHING: `expand_pool_address` failing
// on ONE member sets `invalid_pool_address` and fails the WHOLE pool as
// InvalidPool (userspace-dp/src/nat/source.rs), so such a pool builds no
// allocator and occupies no budget slot there. Round 1's budget walk instead
// SUMMED per-member host counts and skipped only a zero total, so a pool of
// `[198.51.100.1, not-an-ip]` summed to 1, was charged, and 1,024 of them
// consumed the entire pool-count budget — shipping the healthy pool referenced
// after them as PoolUnusable / "aggregate_over_budget" on the one path (lenient
// load / peer-sync, #1960 no-brick) an operator uses to recover.
//
// The over-capacity spelling of the same class — a prefix that PARSES but
// expands past the allocator cap — is driven separately below, on the axis
// where it does damage.
//
// RED-on-revert (drop the membership-grammar clause from
// config.SourceNATPoolUnusableReason): the bad pools ship PoolUnusable=false,
// the walk charges all 1,024, and "good" comes back
// PoolUnusable=true / "aggregate_over_budget".
func TestSourceNATSnapshotMixedMemberPoolsDoNotPoisonHealthy_6812(t *testing.T) {
	// Only the MALFORMED spelling is driven here. The over-capacity spelling
	// cannot starve a pool on the COUNT axis — 1,024 over-capacity pools blow
	// the ADDRESS budget long before the count budget, so first-fit refuses them
	// and they consume nothing, leaving the healthy pool unharmed even under the
	// revert. Its damage lands on the port-capacity axis instead, and is driven
	// by TestSourceNATSnapshotOverCapacityPoolDoesNotStarveHealthy_6812 below —
	// where the discriminator genuinely fails on revert rather than passing for
	// an unrelated reason.
	cases := []struct {
		name  string
		mkBad func(i int) string
		about string
	}{
		{
			name:  "malformed_member",
			mkBad: func(int) string { return "not-an-ip" },
			about: "an unparseable member",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nBad := config.MaxSourceNATPoolCount
			cfg := snatMixedMemberPlusHealthyCfg_6812(t, nBad, tc.mkBad)
			snaps := buildSourceNATSnapshots(cfg, nil)
			if len(snaps) != nBad+1 {
				t.Fatalf("snapshots = %d, want %d — the fixture never reached the pool-count budget",
					len(snaps), nBad+1)
			}

			// PRECONDITION: every bad pool ships unusable for its OWN membership
			// reason, not the aggregate one. "invalid_pool" is what the Rust
			// decoder maps to SourceNatFailureReason::InvalidPool — the exact
			// disposition the parse loop reached on its own before Go decided it.
			for i := 0; i < nBad; i++ {
				s := snapByPool_6812(t, snaps, fmt.Sprintf("bad%d", i))
				if !s.PoolUnusable || s.PoolUnusableReason != "invalid_pool" {
					t.Fatalf("bad%d (%s): PoolUnusable=%v reason=%q, want true/%q — the builder is "+
						"shipping a pool the dataplane refuses as if it were installable, so the "+
						"budget below is charging allocators that never exist",
						i, tc.about, s.PoolUnusable, s.PoolUnusableReason, "invalid_pool")
				}
				// And the pool DEFINITION really is otherwise fine: this is the
				// fifth class, not one of the four round-1 classes wearing a new
				// name. A definition-unusable pool would have been excluded
				// before this round's change and would prove nothing.
				if s.PortLow != 1024 || s.PortHigh != 65535 {
					t.Fatalf("bad%d: port range %d-%d, want the 1024-65535 default — the fixture is "+
						"failing on its port range, which round 1 already excluded",
						i, s.PortLow, s.PortHigh)
				}
			}

			// THE DISCRIMINATOR: the healthy pool survives, and ships intact.
			good := snapByPool_6812(t, snaps, "good")
			if good.PoolUnusable {
				t.Fatalf("good: PoolUnusable = true (reason %q), want false — %d pools that build NO "+
					"allocator (%s) consumed the whole pool-count budget and disabled a healthy pool "+
					"on the tolerant recovery path",
					good.PoolUnusableReason, nBad, tc.about)
			}
			if len(good.PoolAddresses) != 1 || good.PoolAddresses[0] != "198.51.100.7/32" {
				t.Fatalf("good: PoolAddresses = %v, want [198.51.100.7/32]", good.PoolAddresses)
			}
			if good.PortLow != 10000 || good.PortHigh != 10009 {
				t.Fatalf("good: port range = %d-%d, want 10000-10009", good.PortLow, good.PortHigh)
			}
		})
	}
}

// TestSourceNATSnapshotOverCapacityPoolDoesNotStarveHealthy_6812 drives the
// SECOND spelling of the fifth class, on the axis where it bites: an
// over-capacity member.
//
// `10.0.0.0/15` parses cleanly and expands to 131,072 hosts — exactly twice
// MaxSourceNATPoolPrefixHosts — so `expand_pool_address` refuses it and the
// pool builds no allocator at all. Round 1's walk nevertheless charged it
// 131,072 addresses x the 64,512-slot default PAT range = 8,455,716,864 of the
// 8,589,934,592-slot port-capacity budget: 98.4% of the budget spent on an
// allocator that does not exist. A healthy full /16 pool referenced after it
// (4,227,858,432 slots — admissible on its own, and the exact shape the #5877
// budget is documented to admit two of) then pushed the running total to
// 12,683,575,296 and was poisoned "aggregate_over_budget".
//
// It survived round 1's zero-total skip precisely BECAUSE it expands to a large
// number. That is the clearest statement of why the sum was never the right
// question: the derived quantity was not merely incomplete, it pointed the
// wrong way — the more egregious the member, the larger its phantom charge.
//
// Two pools, no count-budget involvement: the ONLY axis in play is port
// capacity, so a poison verdict here cannot be attributed to anything else.
//
// RED-on-revert (drop the membership-grammar clause from
// config.SourceNATPoolUnusableReason): "good" comes back PoolUnusable=true /
// "aggregate_over_budget".
func TestSourceNATSnapshotOverCapacityPoolDoesNotStarveHealthy_6812(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		// Referenced FIRST, so under the first-fit walk its charge is the one
		// that would consume the budget ahead of the healthy pool.
		"set security nat source pool bad address 10.0.0.0/15",
		"set security nat source rule-set RS rule r0 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule r0 then source-nat pool bad",
		"set security nat source pool good address 172.16.0.0/16",
		"set security nat source rule-set RS rule r1 match source-address 10.0.1.0/24",
		"set security nat source rule-set RS rule r1 then source-nat pool good",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2", len(snaps))
	}

	// PRECONDITION: the over-capacity pool is refused for its MEMBERSHIP, and
	// the healthy pool is genuinely large enough that a phantom charge ahead of
	// it is what decides its fate.
	bad := snapByPool_6812(t, snaps, "bad")
	if !bad.PoolUnusable || bad.PoolUnusableReason != "invalid_pool" {
		t.Fatalf("bad: PoolUnusable=%v reason=%q, want true/%q — an over-capacity prefix must be "+
			"refused for its membership, not charged as if the dataplane would expand it",
			bad.PoolUnusable, bad.PoolUnusableReason, "invalid_pool")
	}
	if len(bad.PoolAddresses) != 1 || bad.PoolAddresses[0] != "10.0.0.0/15" {
		t.Fatalf("bad: PoolAddresses = %v, want [10.0.0.0/15]", bad.PoolAddresses)
	}

	// THE DISCRIMINATOR.
	good := snapByPool_6812(t, snaps, "good")
	if good.PoolUnusable {
		t.Fatalf("good: PoolUnusable = true (reason %q), want false — a healthy full /16 pool "+
			"(4,227,858,432 of 8,589,934,592 slots, admissible on its own) was disabled by ONE "+
			"over-capacity pool that builds no allocator at all",
			good.PoolUnusableReason)
	}
	if len(good.PoolAddresses) != 1 || good.PoolAddresses[0] != "172.16.0.0/16" {
		t.Fatalf("good: PoolAddresses = %v, want [172.16.0.0/16]", good.PoolAddresses)
	}
}

// TestSnapshotPoisonFollowsEmittedScopeOrder_6812 is the #6812 F3 round 3
// guard at the boundary that matters: the pool the Go budget walk admits must
// be the pool the DATAPLANE charges first.
//
// The Rust resolver (resolve_pool_allocators, userspace-dp/src/nat/source.rs)
// walks the emitted rule slice in order, and this builder STABLE-sorts that
// slice by #4161 scope tier. So the interface-scoped rule-set is charged
// first — and the Go walk, which decides the poison this builder stamps, must
// use the same order or the surviving pool is chosen by an unrelated rule.
//
// `aaa`/`big` is zone-scoped (tier 1) and consumes 98% of the port-slot
// budget; `zzz`/`small` is interface-scoped (tier 0, more specific). Each fits
// alone, neither fits alongside the other. Through round 2 the walk ordered by
// rule-set NAME, so `aaa` took the budget and the MORE-SPECIFIC rule-set's
// pool was the one poisoned.
//
// RED-on-revert: restore the name sort in
// config.sourceNATAggregateReferencedCharges and the emitted order flips —
// snapshot[0] (small) comes back PoolUnusable=true.
func TestSnapshotPoisonFollowsEmittedScopeOrder_6812(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source rule-set aaa from zone trust",
		"set security nat source rule-set aaa to zone untrust",
		"set security nat source rule-set aaa rule r0 match source-address 10.0.0.0/24",
		"set security nat source rule-set aaa rule r0 then source-nat pool big",
		"set security nat source pool big address 10.100.0.0/16",
		"set security nat source pool big address 10.101.0.0/16",
		"set security nat source rule-set zzz from interface ge-0/0/1.0",
		"set security nat source rule-set zzz rule r0 match source-address 10.0.0.0/24",
		"set security nat source rule-set zzz rule r0 then source-nat pool small",
		"set security nat source pool small address 10.200.0.0/16",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	out := buildSourceNATSnapshots(cfg, nil)
	if len(out) != 2 {
		t.Fatalf("emitted %d rules, want 2", len(out))
	}
	// The emitted order is the order the dataplane charges.
	if out[0].PoolName != "small" || out[1].PoolName != "big" {
		t.Fatalf("emitted order = [%s %s], want [small big] (interface tier first)",
			out[0].PoolName, out[1].PoolName)
	}
	if sourceNATScopeTier(out[0]) >= sourceNATScopeTier(out[1]) {
		t.Fatalf("emitted tiers = [%d %d]; the fixture no longer discriminates on tier",
			sourceNATScopeTier(out[0]), sourceNATScopeTier(out[1]))
	}
	// The FIRST-charged pool keeps its allocator; the later one is refused.
	if out[0].PoolUnusable {
		t.Fatalf("the first-charged pool %q was poisoned (%q) — the Go walk admitted a "+
			"DIFFERENT pool than the dataplane charges first",
			out[0].PoolName, out[0].PoolUnusableReason)
	}
	if !out[1].PoolUnusable || out[1].PoolUnusableReason != "aggregate_over_budget" {
		t.Fatalf("second pool %q unusable=%v reason=%q, want aggregate_over_budget",
			out[1].PoolName, out[1].PoolUnusable, out[1].PoolUnusableReason)
	}
}

// TestBuilderEmittedOrderIsStableWithinATier_6812 binds the BUILDER half of
// the #6812 F3 equality. Round 4 pinned the WALK
// (config.sourceNATAggregateReferencedCharges); this pins the emission side,
// which is the half with a dataplane consequence.
//
// F3's deliverable is an EQUALITY — a same-tier tie resolves in config order,
// which is what makes the walk's first-reference sequence equal the builder's
// emitted sequence. Only one half was pinned. Swapping THIS sort
// (nat_source.go, the #4161 tier sort) for an unstable one left the entire Go
// suite green.
//
// THREE invariants, asserted separately so a failure names which one broke.
// The comment above the production sort claims all three; only the first is
// implied by the walk-side test:
//
//  1. rule-sets appear in config order WITHIN a tier;
//  2. each rule-set's rules stay CONTIGUOUS — "rule-sets never interleave";
//  3. rules keep their within-rule-set config order.
//
// (2) is the one with teeth and it is NOT implied by (1). An unstable sort can
// keep every rule-set's FIRST rule in config order while lifting its second
// rule past another rule-set's — first-references still ascending, blocks
// split. Measured under sort.Slice: if03's two rules land at indices 10 and 13
// with if07 and if05 between them.
//
// Why that is misrouting rather than an ordering nit: the Rust matcher
// (match_source_nat_result_for_tuple, userspace-dp/src/nat/source.rs) is
// FIRST-MATCH on this slice precisely because the slice arrives pre-tiered —
// the production comment says so ("this is why the Rust first-match loop is
// deliberately left unchanged: it reads a pre-tiered Vec"). Split a rule-set
// and a flow matching if03/r1 takes if07/r0's translation instead.
//
// FAIL-ON-REVERT: sort.SliceStable -> sort.Slice in buildSourceNATSnapshots.
func TestBuilderEmittedOrderIsStableWithinATier_6812(t *testing.T) {
	const nPerTier, rulesPerSet = 10, 2
	tree := &config.ConfigTree{}
	var cmds []string
	// INTERLEAVED across two tiers so the input is neither single-keyed nor
	// already tier-sorted, and >= 13 rule-sets so sort.Slice actually permutes
	// (measured in round 4: pdqsort preserves order below that).
	for i := 0; i < nPerTier; i++ {
		iface := fmt.Sprintf("if%02d", i)
		zone := fmt.Sprintf("zn%02d", i)
		cmds = append(cmds,
			fmt.Sprintf("set security nat source rule-set %s from interface ge-0/0/%d.0", iface, i),
			fmt.Sprintf("set security nat source pool %s address 10.%d.0.1", iface, 100+i),
			fmt.Sprintf("set security nat source rule-set %s from zone trust%d", zone, i),
			fmt.Sprintf("set security nat source pool %s address 10.%d.0.1", zone, 200+i),
		)
		// TWO rules per rule-set: contiguity is vacuous with one.
		for r := 0; r < rulesPerSet; r++ {
			cmds = append(cmds,
				fmt.Sprintf("set security nat source rule-set %s rule r%d match source-address 10.0.%d.0/24", iface, r, r),
				fmt.Sprintf("set security nat source rule-set %s rule r%d then source-nat pool %s", iface, r, iface),
				fmt.Sprintf("set security nat source rule-set %s rule r%d match source-address 10.0.%d.0/24", zone, r, r),
				fmt.Sprintf("set security nat source rule-set %s rule r%d then source-nat pool %s", zone, r, zone),
			)
		}
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}

	// Precondition: the DECLARED order alternates tiers, so an unstable sort
	// has something to permute. Without this the fixture silently decays into
	// the all-equal-key shape that makes the mutation a no-op.
	var declared []int
	for _, rs := range cfg.Security.NAT.Source {
		declared = append(declared, config.SourceNATScopeTier(
			rs.FromInterface, rs.FromZone, rs.FromRoutingInstance,
			rs.ToInterface, rs.ToZone, rs.ToRoutingInstance))
	}
	if len(declared) != 2*nPerTier {
		t.Fatalf("compiled %d rule-sets, want %d", len(declared), 2*nPerTier)
	}
	alreadySorted := true
	for i := 1; i < len(declared); i++ {
		if declared[i] < declared[i-1] {
			alreadySorted = false
		}
	}
	if alreadySorted {
		t.Fatal("declared order is already tier-sorted; an unstable sort would have " +
			"nothing to permute and this fixture would not bind stability")
	}

	out := buildSourceNATSnapshots(cfg, nil)
	if len(out) != 2*nPerTier*rulesPerSet {
		t.Fatalf("emitted %d rules, want %d", len(out), 2*nPerTier*rulesPerSet)
	}

	// (1) Rule-set FIRST references, in emitted order, per tier.
	var firstRefs []string
	seen := map[string]bool{}
	for _, s := range out {
		if !seen[s.PoolName] {
			seen[s.PoolName] = true
			firstRefs = append(firstRefs, s.PoolName)
		}
	}
	var wantRefs []string
	for i := 0; i < nPerTier; i++ {
		wantRefs = append(wantRefs, fmt.Sprintf("if%02d", i))
	}
	for i := 0; i < nPerTier; i++ {
		wantRefs = append(wantRefs, fmt.Sprintf("zn%02d", i))
	}
	for i := range wantRefs {
		if firstRefs[i] != wantRefs[i] {
			// Errorf, not Fatalf: the contiguity check below is a SEPARATE
			// invariant and a mutation that breaks both should report both.
			t.Errorf("emitted rule-set order[%d] = %s, want %s — a same-tier tie was not "+
				"resolved in CONFIG order, so the emitted sequence no longer equals the "+
				"budget walk's.\n got: %v\nwant: %v", i, firstRefs[i], wantRefs[i],
				firstRefs, wantRefs)
			break
		}
	}

	// (2) CONTIGUITY — independent of (1), and the invariant the Rust
	// first-match matcher relies on.
	firstIdx := map[string]int{}
	lastIdx := map[string]int{}
	for i, s := range out {
		if _, ok := firstIdx[s.PoolName]; !ok {
			firstIdx[s.PoolName] = i
		}
		lastIdx[s.PoolName] = i
	}
	for name, lo := range firstIdx {
		hi := lastIdx[name]
		if hi-lo+1 != rulesPerSet {
			var between []string
			for i := lo; i <= hi; i++ {
				if out[i].PoolName != name {
					between = append(between, fmt.Sprintf("%s/%s@%d", out[i].PoolName, out[i].Name, i))
				}
			}
			t.Errorf("rule-set %s SPLIT: its %d rules span indices %d..%d with %v between "+
				"them. The Rust matcher is first-match on this slice, so a flow matching a "+
				"later rule of %s takes the interposed rule-set's translation instead",
				name, rulesPerSet, lo, hi, between, name)
		}
	}

	// (3) Within-rule-set rule order (Junos within-set order).
	for name, lo := range firstIdx {
		for r := 0; r < rulesPerSet; r++ {
			if got := out[lo+r].Name; got != fmt.Sprintf("r%d", r) {
				t.Errorf("rule-set %s rule[%d] = %s, want r%d — within-rule-set config "+
					"order was not preserved", name, r, got, r)
			}
		}
	}
}
