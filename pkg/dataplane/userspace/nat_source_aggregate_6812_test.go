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
func snatAggregateCfg_6812(t *testing.T, n int) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i := 0; i < n; i++ {
		cmds = append(cmds,
			fmt.Sprintf("set security nat source pool p%d address 10.%d.0.0/16", i, i),
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
