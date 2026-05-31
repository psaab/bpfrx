package routing

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeRuleOps is an in-memory ip-rule table implementing ruleOps. It
// records every RuleAdd/RuleDel so tests can assert exactly which
// policy-routing rules a domain manager programs — WITHOUT netlink.
// This is the seam the #1698 split introduced; before it, the rule
// reconcilers could not be exercised without a live kernel (see the
// "can't test actual ip rule creation without netlink" note in
// TestRibGroupNeedsLeak).
type fakeRuleOps struct {
	// rules holds the current rule set keyed by family, mirroring the
	// kernel's per-family rule list that RuleList returns.
	rules map[int][]netlink.Rule

	adds int
	dels int
}

func newFakeRuleOps() *fakeRuleOps {
	return &fakeRuleOps{rules: map[int][]netlink.Rule{
		unix.AF_INET:  {},
		unix.AF_INET6: {},
	}}
}

func (f *fakeRuleOps) RuleAdd(r *netlink.Rule) error {
	f.adds++
	f.rules[r.Family] = append(f.rules[r.Family], *r)
	return nil
}

func (f *fakeRuleOps) RuleDel(r *netlink.Rule) error {
	f.dels++
	list := f.rules[r.Family]
	out := list[:0:0]
	for _, e := range list {
		if e.Priority == r.Priority {
			continue
		}
		out = append(out, e)
	}
	f.rules[r.Family] = out
	return nil
}

func (f *fakeRuleOps) RuleList(family int) ([]netlink.Rule, error) {
	return f.rules[family], nil
}

// count returns the number of rules currently present for a family.
func (f *fakeRuleOps) count(family int) int { return len(f.rules[family]) }

// hasTable reports whether any rule in the family targets the table.
func (f *fakeRuleOps) hasTable(family, table int) bool {
	for _, r := range f.rules[family] {
		if r.Table == table {
			return true
		}
	}
	return false
}

// TestRibGroupRulesApply_Fake exercises ribGroupManager over a fake
// ruleOps, asserting the leak rules are programmed for the source table
// — the exact ip-rule-creation path the old test suite could not reach
// without netlink. Constructs the domain manager directly, NOT the whole
// routing.Manager.
func TestRibGroupRulesApply_Fake(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {
			Name:       "dmz-leak",
			ImportRibs: []string{"dmz-vr.inet.0", "inet.0"},
		},
		"self-only": {
			Name:       "self-only",
			ImportRibs: []string{"tunnel-vr.inet.0"},
		},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "tunnel-vr", TableID: 100, InterfaceRoutesRibGroup: "self-only"},
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
	}

	if err := rg.Apply(ribGroups, instances); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// dmz-vr (table 101) leaks → one IPv4 + one IPv6 rule for table 101.
	if !ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("expected IPv4 leak rule for table 101, rules=%v", ops.rules[unix.AF_INET])
	}
	if !ops.hasTable(unix.AF_INET6, 101) {
		t.Errorf("expected IPv6 leak rule for table 101, rules=%v", ops.rules[unix.AF_INET6])
	}
	// tunnel-vr (self-only) must NOT produce a leak rule for table 100.
	if ops.hasTable(unix.AF_INET, 100) {
		t.Errorf("self-only should not leak table 100, rules=%v", ops.rules[unix.AF_INET])
	}
	if got := ops.count(unix.AF_INET); got != 1 {
		t.Errorf("expected exactly 1 IPv4 rule, got %d", got)
	}

	// Re-applying must clear the prior rules first (clear-then-add), so
	// the rule count stays stable rather than doubling.
	prevAdds := ops.adds
	if err := rg.Apply(ribGroups, instances); err != nil {
		t.Fatalf("Apply (second): %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 1 {
		t.Errorf("after re-apply expected 1 IPv4 rule, got %d", got)
	}
	if ops.dels == 0 {
		t.Error("expected re-apply to delete the prior rules (clear-then-add)")
	}
	if ops.adds <= prevAdds {
		t.Error("expected re-apply to re-add rules")
	}
}

// TestNextTableRulesApply_Fake exercises nextTableManager over a fake,
// asserting a next-table directive becomes an ip rule pointing at the
// target instance's table.
func TestNextTableRulesApply_Fake(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}

	routes := []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
		{Destination: "2001:db8::/32", NextTable: "dmz-vr"},
		{Destination: "10.99.0.0/16", NextTable: "unknown-vr"}, // skipped
		{Destination: "10.0.0.0/8"},                            // no next-table, skipped
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101},
	}

	if err := nt.Apply(routes, instances); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("expected IPv4 next-table rule for table 101, rules=%v", ops.rules[unix.AF_INET])
	}
	if !ops.hasTable(unix.AF_INET6, 101) {
		t.Errorf("expected IPv6 next-table rule for table 101, rules=%v", ops.rules[unix.AF_INET6])
	}
	if got := ops.count(unix.AF_INET); got != 1 {
		t.Errorf("expected 1 IPv4 rule (unknown-vr skipped), got %d", got)
	}
	if got := ops.count(unix.AF_INET6); got != 1 {
		t.Errorf("expected 1 IPv6 rule, got %d", got)
	}
}

// TestNextTableRulesPriorityCap exercises the #1706 hard cap: programming
// more next-table routes than the clear() window (100 priorities) must
// stop at the boundary so every programmed rule stays inside the range
// clear() scans — otherwise rules at prio >= 200 leak permanently. The
// boundary case (exactly 100 routes) programs the full set; one over
// triggers the cap.
func TestNextTableRulesPriorityCap(t *testing.T) {
	mkRoutes := func(n int) []*config.StaticRoute {
		routes := make([]*config.StaticRoute, n)
		for i := 0; i < n; i++ {
			// Distinct /24 destinations, all pointing at the same table.
			routes[i] = &config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "dmz-vr",
			}
		}
		return routes
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	// Exactly at the window size: all 100 admitted, none beyond range.
	t.Run("at-limit", func(t *testing.T) {
		ops := newFakeRuleOps()
		nt := &nextTableManager{ops: ops}
		if err := nt.Apply(mkRoutes(100), instances); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != 100 {
			t.Fatalf("expected all 100 routes programmed at the limit, got %d", total)
		}
		assertAllRulesInRange(t, ops, nextTableRulePriority, nextTableRulePriority+100)
	})

	// One over the window: cap fires, only 100 admitted, none out of range.
	t.Run("over-limit", func(t *testing.T) {
		ops := newFakeRuleOps()
		nt := &nextTableManager{ops: ops}
		if err := nt.Apply(mkRoutes(150), instances); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != 100 {
			t.Fatalf("expected cap to hold at 100 programmed rules, got %d", total)
		}
		assertAllRulesInRange(t, ops, nextTableRulePriority, nextTableRulePriority+100)

		// Re-apply must leave no residue: every programmed rule is inside
		// clear()'s window, so clear-then-add keeps the count stable. A
		// leaked rule at prio >= 200 would survive clear() and grow the set.
		if err := nt.Apply(mkRoutes(150), instances); err != nil {
			t.Fatalf("Apply (second): %v", err)
		}
		total = ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != 100 {
			t.Fatalf("re-apply leaked rules: expected 100, got %d", total)
		}
	})
}

// TestRibGroupRulesPriorityCap exercises the #1706 hard cap for rib-group
// rules. Each leaking table consumes TWO priorities (v4+v6), so the
// window of 100 priorities fits 50 tables. The 50th table must program at
// slots 33098/33099 (the last in-range pair); the 51st must be rejected.
func TestRibGroupRulesPriorityCap(t *testing.T) {
	mkConfig := func(n int) (map[string]*config.RibGroup, []*config.RoutingInstanceConfig) {
		ribGroups := map[string]*config.RibGroup{}
		instances := make([]*config.RoutingInstanceConfig, n)
		for i := 0; i < n; i++ {
			rgName := fmt.Sprintf("leak-%d", i)
			// Import a different table than the source so needsLeak is true.
			ribGroups[rgName] = &config.RibGroup{
				Name:       rgName,
				ImportRibs: []string{"inet.0"}, // main table 254 != source
			}
			instances[i] = &config.RoutingInstanceConfig{
				Name:                    fmt.Sprintf("vr-%d", i),
				TableID:                 1000 + i, // distinct source tables
				InterfaceRoutesRibGroup: rgName,
			}
		}
		return ribGroups, instances
	}

	t.Run("at-limit", func(t *testing.T) {
		ops := newFakeRuleOps()
		rg := &ribGroupManager{ops: ops}
		ribGroups, instances := mkConfig(50)
		if err := rg.Apply(ribGroups, instances); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != 100 {
			t.Fatalf("expected 50 tables * 2 = 100 rules at the limit, got %d", total)
		}
		assertAllRulesInRange(t, ops, ribGroupRulePriority, ribGroupRulePriority+100)
		// The 50th (last admitted) table must occupy the final in-range
		// pair: IPv4 at 33098, IPv6 at 33099.
		if !hasPriority(ops, unix.AF_INET, ribGroupRulePriority+98) {
			t.Errorf("expected IPv4 rule at the last in-range slot %d", ribGroupRulePriority+98)
		}
		if !hasPriority(ops, unix.AF_INET6, ribGroupRulePriority+99) {
			t.Errorf("expected IPv6 rule at the last in-range slot %d", ribGroupRulePriority+99)
		}
	})

	t.Run("over-limit", func(t *testing.T) {
		ops := newFakeRuleOps()
		rg := &ribGroupManager{ops: ops}
		ribGroups, instances := mkConfig(60)
		if err := rg.Apply(ribGroups, instances); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != 100 {
			t.Fatalf("expected cap to hold at 100 rules (50 tables), got %d", total)
		}
		assertAllRulesInRange(t, ops, ribGroupRulePriority, ribGroupRulePriority+100)
		// The 51st table (would-be slots 33100/33101) must be absent.
		if hasPriority(ops, unix.AF_INET, ribGroupRulePriority+100) ||
			hasPriority(ops, unix.AF_INET6, ribGroupRulePriority+101) {
			t.Errorf("51st table leaked beyond the cleared window (slot %d/%d present)",
				ribGroupRulePriority+100, ribGroupRulePriority+101)
		}

		// Re-apply must not leak: all programmed rules are inside the
		// cleared window.
		if err := rg.Apply(ribGroups, instances); err != nil {
			t.Fatalf("Apply (second): %v", err)
		}
		total = ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != 100 {
			t.Fatalf("re-apply leaked rib-group rules: expected 100, got %d", total)
		}
	})
}

// hasPriority reports whether any rule in the family was programmed at
// the exact priority.
func hasPriority(ops *fakeRuleOps, family, prio int) bool {
	for _, r := range ops.rules[family] {
		if r.Priority == prio {
			return true
		}
	}
	return false
}

// assertAllRulesInRange fails the test if any programmed rule in either
// family has a priority outside [lo, hi) — i.e. a rule clear() would not
// remove. This is the invariant the #1706 priority caps guarantee.
func assertAllRulesInRange(t *testing.T, ops *fakeRuleOps, lo, hi int) {
	t.Helper()
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, r := range ops.rules[family] {
			if r.Priority < lo || r.Priority >= hi {
				t.Errorf("rule priority %d outside cleared window [%d,%d) — would leak",
					r.Priority, lo, hi)
			}
		}
	}
}

// TestPBRRulesApply_Fake exercises pbrManager over a fake, asserting a
// PBRRule with a TOS match becomes an ip rule targeting the right table,
// and that clear-then-add keeps the rule set stable on re-apply.
func TestPBRRulesApply_Fake(t *testing.T) {
	ops := newFakeRuleOps()
	p := &pbrManager{ops: ops}

	rules := []PBRRule{
		{Family: unix.AF_INET, TOS: 46 << 2, TableID: 100, Instance: "vr-a"},
		{Family: unix.AF_INET6, Src: "2001:db8::/32", TableID: 100, Instance: "vr-a"},
		{Family: unix.AF_INET, Dst: "10.5.0.0/16", TableID: 101, Instance: "vr-b"},
	}

	if err := p.Apply(rules); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !ops.hasTable(unix.AF_INET, 100) || !ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("expected IPv4 PBR rules for tables 100 and 101, rules=%v", ops.rules[unix.AF_INET])
	}
	if !ops.hasTable(unix.AF_INET6, 100) {
		t.Errorf("expected IPv6 PBR rule for table 100, rules=%v", ops.rules[unix.AF_INET6])
	}
	if got := ops.count(unix.AF_INET); got != 2 {
		t.Errorf("expected 2 IPv4 PBR rules, got %d", got)
	}

	// Empty rule set clears everything.
	if err := p.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if ops.count(unix.AF_INET) != 0 || ops.count(unix.AF_INET6) != 0 {
		t.Errorf("expected all PBR rules cleared, v4=%d v6=%d",
			ops.count(unix.AF_INET), ops.count(unix.AF_INET6))
	}
}
