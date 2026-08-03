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
