package routing

import (
	"errors"
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

	// listErr injects a per-family RuleList dump failure, simulating a
	// transient netlink error on one address family while the other
	// succeeds — the failure mode #2273 fixes. RuleList(family) returns
	// listErr[family] (and a nil slice) when present.
	listErr map[int]error

	// addErr, when non-nil, makes RuleAdd fail without recording the rule —
	// used to exercise the #3430 H3 add-failure aggregation in pbrManager.Apply.
	addErr error

	// addErrFamily injects a per-family RuleAdd failure, simulating a
	// transient netlink error on one address family while the other
	// succeeds. RuleAdd fails (without recording the rule) when
	// addErrFamily[r.Family] is non-nil. Used to exercise the #3731
	// next-table / rib-group add-failure aggregation with family isolation
	// (a v4 add can fail while the sibling v6 add still installs).
	addErrFamily map[int]error

	// delErr, when non-nil, makes RuleDel fail without removing the rule —
	// used to exercise the #3430 H3 clear-failure aggregation (a stale rule
	// that cannot be deleted must surface as a non-nil Apply error).
	delErr error

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
	if f.addErr != nil {
		return f.addErr
	}
	if f.addErrFamily != nil {
		if err := f.addErrFamily[r.Family]; err != nil {
			return err
		}
	}
	f.adds++
	f.rules[r.Family] = append(f.rules[r.Family], *r)
	return nil
}

func (f *fakeRuleOps) RuleDel(r *netlink.Rule) error {
	if f.delErr != nil {
		return f.delErr
	}
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
	if f.listErr != nil {
		if err := f.listErr[family]; err != nil {
			return nil, err
		}
	}
	return f.rules[family], nil
}

// failList arms RuleList(family) to return err. Used to recreate the
// transient per-family netlink dump failure from #2273.
func (f *fakeRuleOps) failList(family int, err error) {
	if f.listErr == nil {
		f.listErr = map[int]error{}
	}
	f.listErr[family] = err
}

// failAdd arms RuleAdd(rule) to return err for rules in the given family
// (without recording them). Used to recreate a transient per-family netlink
// add failure so the #3731 aggregation can be exercised with one family
// failing while the sibling family still installs.
func (f *fakeRuleOps) failAdd(family int, err error) {
	if f.addErrFamily == nil {
		f.addErrFamily = map[int]error{}
	}
	f.addErrFamily[family] = err
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

// TestRibGroupRulesApply_UnknownRibNoLeak is the #2226 fail-on-revert
// guard. A rib-group whose ONLY import-rib names a rib that resolves to
// no real routing table (a typo / non-existent instance) must NOT install
// any leak rule for the source table. Before the fix, resolveRibTable
// returned a bare 0 for the unknown name; 0 != sourceTable(101) set
// needsLeak, and the applier installed `ip rule from all lookup 101` —
// a silent mis-leak of the source table into the main lookup. With the
// fix the unknown rib is skipped (ok=false) and no rule is programmed.
//
// Reverting either the resolveRibTable (int,bool) split or the
// needsLeak-loop ok guard makes this test fail (a phantom rule for
// table 101 appears).
func TestRibGroupRulesApply_UnknownRibNoLeak(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"typo-leak": {
			Name: "typo-leak",
			// Both names are undefined: a non-existent instance and pure
			// garbage. Neither resolves to a real table.
			ImportRibs: []string{"does-not-exist.inet.0", "garbage"},
		},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "typo-leak"},
	}

	if err := rg.Apply(ribGroups, instances); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("unknown import-rib must NOT install an IPv4 leak rule for table 101 (#2226), rules=%v", ops.rules[unix.AF_INET])
	}
	if ops.hasTable(unix.AF_INET6, 101) {
		t.Errorf("unknown import-rib must NOT install an IPv6 leak rule for table 101 (#2226), rules=%v", ops.rules[unix.AF_INET6])
	}
	// And specifically never a rule into table 0 (the old fallback target).
	if ops.hasTable(unix.AF_INET, 0) || ops.hasTable(unix.AF_INET6, 0) {
		t.Errorf("must never install a rule into table 0 from an unresolved rib (#2226)")
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 0 {
		t.Errorf("expected zero rules for an all-unknown rib-group, got %d (%v / %v)",
			got, ops.rules[unix.AF_INET], ops.rules[unix.AF_INET6])
	}
}

// TestRibGroupRulesApply_DefinedRibStillLeaks is the companion no-false-
// reject guard for #2226: a rib-group importing a DEFINED rib (another
// real instance's table, plus the main table) still leaks the source
// table correctly. This pins that the (int,bool) split did not break the
// happy path — only the unresolvable case changed.
func TestRibGroupRulesApply_DefinedRibStillLeaks(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {
			Name: "dmz-leak",
			// dmz-vr.inet.0 (self, table 101), tunnel-vr.inet.0 (defined,
			// table 100), inet.0 (main, 254). The defined non-self ribs
			// must drive the leak.
			ImportRibs: []string{"dmz-vr.inet.0", "tunnel-vr.inet.0", "inet.0"},
		},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "tunnel-vr", TableID: 100},
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
	}

	if err := rg.Apply(ribGroups, instances); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("defined import-rib must still leak table 101 (IPv4), rules=%v", ops.rules[unix.AF_INET])
	}
	if !ops.hasTable(unix.AF_INET6, 101) {
		t.Errorf("defined import-rib must still leak table 101 (IPv6), rules=%v", ops.rules[unix.AF_INET6])
	}
}

// TestRibGroupApplyAggregatesAddErrors is the #3731 fail-on-revert guard for
// the rib-group reconciler. Each leaked table programs a v4 THEN a v6 ip rule;
// a RuleAdd failure on either (or both) must be aggregated and returned rather
// than logged-and-swallowed with Apply reporting nil (the pre-fix clearErr-only
// return). The subtests pin v4-only, v6-only, and both-family failures — the
// sibling family that DID install stays installed (forward progress) while
// Apply still surfaces the error.
//
// Reverting ribGroupManager.Apply to the log-only branches + `return clearErr`
// makes every subtest go RED (Apply returns nil).
func TestRibGroupApplyAggregatesAddErrors(t *testing.T) {
	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {Name: "dmz-leak", ImportRibs: []string{"inet.0"}}, // main 254 != source
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
	}

	t.Run("v4-only", func(t *testing.T) {
		ops := newFakeRuleOps()
		ops.failAdd(unix.AF_INET, errors.New("netlink EPERM on v4"))
		rg := &ribGroupManager{ops: ops}
		if err := rg.Apply(ribGroups, instances); err == nil {
			t.Fatal("Apply must return non-nil when the v4 leak rule fails (#3731)")
		}
		if ops.hasTable(unix.AF_INET, 101) {
			t.Errorf("failed v4 leak rule must not be recorded, rules=%v", ops.rules[unix.AF_INET])
		}
		if !ops.hasTable(unix.AF_INET6, 101) {
			t.Errorf("sibling v6 leak rule must still install (forward progress), rules=%v", ops.rules[unix.AF_INET6])
		}
	})

	t.Run("v6-only", func(t *testing.T) {
		ops := newFakeRuleOps()
		ops.failAdd(unix.AF_INET6, errors.New("netlink EPERM on v6"))
		rg := &ribGroupManager{ops: ops}
		if err := rg.Apply(ribGroups, instances); err == nil {
			t.Fatal("Apply must return non-nil when the v6 leak rule fails (#3731)")
		}
		if !ops.hasTable(unix.AF_INET, 101) {
			t.Errorf("sibling v4 leak rule must still install (forward progress), rules=%v", ops.rules[unix.AF_INET])
		}
		if ops.hasTable(unix.AF_INET6, 101) {
			t.Errorf("failed v6 leak rule must not be recorded, rules=%v", ops.rules[unix.AF_INET6])
		}
	})

	t.Run("both-family", func(t *testing.T) {
		ops := newFakeRuleOps()
		ops.addErr = errors.New("netlink ENOBUFS")
		rg := &ribGroupManager{ops: ops}
		if err := rg.Apply(ribGroups, instances); err == nil {
			t.Fatal("Apply must return non-nil when both leak rules fail (#3731)")
		}
		if ops.count(unix.AF_INET) != 0 || ops.count(unix.AF_INET6) != 0 {
			t.Errorf("no leak rule should be recorded, v4=%d v6=%d",
				ops.count(unix.AF_INET), ops.count(unix.AF_INET6))
		}
	})
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

// TestNextTableApplyAggregatesAddErrors is the #3731 fail-on-revert guard for
// the next-table reconciler. A per-rule RuleAdd failure after the up-front
// clear() must be aggregated and returned — not logged-and-swallowed with Apply
// still reporting nil (the pre-fix clearErr-only return). Before the fix a
// transient netlink add error left the inter-VRF leak DOWN while Apply told the
// daemon apply loop "success".
//
// Reverting nextTableManager.Apply to `continue` + `return clearErr` makes this
// test go RED (Apply returns nil).
func TestNextTableApplyAggregatesAddErrors(t *testing.T) {
	routes := []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
		{Destination: "2001:db8::/32", NextTable: "dmz-vr"},
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	// Both-family failure: every RuleAdd fails, no rule recorded, Apply
	// surfaces the aggregated error.
	ops := newFakeRuleOps()
	ops.addErr = errors.New("netlink ENOBUFS")
	nt := &nextTableManager{ops: ops}
	if err := nt.Apply(routes, instances); err == nil {
		t.Fatal("Apply must return a non-nil error when RuleAdd fails (#3731)")
	}
	if ops.count(unix.AF_INET) != 0 || ops.count(unix.AF_INET6) != 0 {
		t.Errorf("no rule should have been recorded, v4=%d v6=%d",
			ops.count(unix.AF_INET), ops.count(unix.AF_INET6))
	}

	// Single-family failure: forward progress preserved — the v4 add fails
	// (error aggregated) while the sibling v6 rule still installs, and Apply
	// still returns the aggregated error rather than swallowing it.
	ops2 := newFakeRuleOps()
	ops2.failAdd(unix.AF_INET, errors.New("netlink EPERM on v4"))
	nt2 := &nextTableManager{ops: ops2}
	if err := nt2.Apply(routes, instances); err == nil {
		t.Fatal("Apply must return non-nil when the v4 add fails (#3731)")
	}
	if ops2.count(unix.AF_INET) != 0 {
		t.Errorf("failed v4 rule must not be recorded, got %d", ops2.count(unix.AF_INET))
	}
	if ops2.count(unix.AF_INET6) != 1 {
		t.Errorf("sibling v6 rule must still install (forward progress), got %d", ops2.count(unix.AF_INET6))
	}
}

// TestNextTableApplyIdempotentReapply pins that the #3731 aggregation does not
// regress the clean path: a first apply returns nil, and re-applying the same
// config (clear-then-add) still returns nil with a stable rule set. The
// re-apply cannot EEXIST because clear() removes the prior in-window rules
// before they are re-added — an already-present rule is handled as success, not
// an error (matching the #3430 PBR path, which likewise clears then re-adds).
func TestNextTableApplyIdempotentReapply(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	routes := []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
		{Destination: "2001:db8::/32", NextTable: "dmz-vr"},
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	if err := nt.Apply(routes, instances); err != nil {
		t.Fatalf("clean Apply must return nil, got %v", err)
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 2 {
		t.Fatalf("expected 2 rules after clean apply, got %d", got)
	}
	if err := nt.Apply(routes, instances); err != nil {
		t.Fatalf("idempotent re-apply must return nil, got %v", err)
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 2 {
		t.Fatalf("re-apply must keep a stable rule set, got %d", got)
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
		{Family: unix.AF_INET, TOS: 46 << 2, TOSSet: true, TableID: 100, Instance: "vr-a"},
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

// TestPBRApplyAggregatesAddErrors verifies that pbrManager.Apply surfaces a
// RuleAdd failure (#3430 H3) instead of swallowing it and reporting success
// after the up-front clear already removed the previously-working steering.
func TestPBRApplyAggregatesAddErrors(t *testing.T) {
	ops := newFakeRuleOps()
	ops.addErr = errors.New("netlink EPERM")
	p := &pbrManager{ops: ops}

	rules := []PBRRule{
		{Family: unix.AF_INET, TOS: 46 << 2, TOSSet: true, TableID: 100, Instance: "vr-a"},
	}
	err := p.Apply(rules)
	if err == nil {
		t.Fatal("Apply must return a non-nil error when RuleAdd fails (#3430 H3)")
	}
	if ops.count(unix.AF_INET) != 0 {
		t.Errorf("no rule should have been recorded, got %d", ops.count(unix.AF_INET))
	}
}

// TestPBRApplyCapBoundary pins the apply-side priority-window cap: exactly
// maxPBRRules rules install cleanly, and one more triggers the overflow error
// after installing the first maxPBRRules (#3430 M3, apply leg).
func TestPBRApplyCapBoundary(t *testing.T) {
	mk := func(n int) []PBRRule {
		out := make([]PBRRule, n)
		for i := range out {
			out[i] = PBRRule{Family: unix.AF_INET, Src: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), TableID: 100, Instance: "vr"}
		}
		return out
	}

	t.Run("exactly at cap", func(t *testing.T) {
		ops := newFakeRuleOps()
		p := &pbrManager{ops: ops}
		if err := p.Apply(mk(maxPBRRules)); err != nil {
			t.Fatalf("exactly %d rules must apply without error, got %v", maxPBRRules, err)
		}
		if ops.count(unix.AF_INET) != maxPBRRules {
			t.Errorf("expected %d rules installed, got %d", maxPBRRules, ops.count(unix.AF_INET))
		}
	})

	t.Run("one over cap", func(t *testing.T) {
		ops := newFakeRuleOps()
		p := &pbrManager{ops: ops}
		err := p.Apply(mk(maxPBRRules + 1))
		if err == nil {
			t.Fatal("exceeding the cap must return a non-nil error")
		}
		if ops.count(unix.AF_INET) != maxPBRRules {
			t.Errorf("expected %d rules installed at the cap, got %d", maxPBRRules, ops.count(unix.AF_INET))
		}
	})
}

// TestPBRApplyClearDelFailureSurfaced verifies that a RuleDel failure during
// the up-front clear is surfaced (#3430 H3 second leg): a stale PBR rule that
// cannot be removed leaves the kernel in a divergent state, so Apply must
// return non-nil rather than reporting success because the new adds worked.
func TestPBRApplyClearDelFailureSurfaced(t *testing.T) {
	ops := newFakeRuleOps()
	// Seed a stale rule inside the PBR window so clear() tries to delete it.
	seedRule(ops, unix.AF_INET, pbrRulePriority+5, 100)
	ops.delErr = errors.New("netlink EBUSY")
	p := &pbrManager{ops: ops}

	// New desired rule set; its adds succeed, but the stale rule cannot be
	// cleared. Pre-fix the clear() RuleDel failure was debug-logged only and
	// Apply returned nil.
	rules := []PBRRule{
		{Family: unix.AF_INET, Src: "10.7.0.0/16", TableID: 101, Instance: "vr-b"},
	}
	if err := p.Apply(rules); err == nil {
		t.Fatal("Apply must return non-nil when a stale rule cannot be cleared (#3430 H3)")
	}
}

// seedRule inserts a rule at the given family/priority/table directly into
// the fake's backing store (bypassing RuleAdd accounting) so a clear() can
// be exercised against pre-existing kernel rules.
func seedRule(ops *fakeRuleOps, family, prio, table int) {
	ops.rules[family] = append(ops.rules[family], netlink.Rule{
		Family:   family,
		Priority: prio,
		Table:    table,
	})
}

// TestRulesClearListErrorSurfaced is the #2273 fail-on-revert guard. When
// RuleList(AF_INET) fails transiently while RuleList(AF_INET6) succeeds,
// clear() (via Apply) must:
//
//  1. return a non-nil error naming the failing family (so the daemon
//     apply loop observes it instead of a silent self-healing-orphan
//     window), and
//  2. still best-effort delete the rules it COULD list — the AF_INET6
//     rule in the managed window is removed.
//
// The AF_INET rule in the window is left in place because its family's
// dump failed (the orphan this PR makes observable). Reverting clear() to
// `continue` + `return nil` makes assertion (1) fail for all three
// managers, and reverting the Apply wiring (returning bare nil) also fails
// (1) — this is the regression pin.
func TestRulesClearListErrorSurfaced(t *testing.T) {
	injErr := errors.New("netlink: transient EBUSY on AF_INET dump")

	type tc struct {
		name string
		// run pre-seeds rules, arms the AF_INET list failure, runs Apply
		// with a desired config that produces ZERO new rules (so the only
		// activity is the clear), and returns the Apply error.
		run func(ops *fakeRuleOps) error
		// inetPrio / inet6Prio are managed-window priorities for each
		// domain so the seeded rules fall inside clear()'s scan range.
		inetPrio  int
		inet6Prio int
	}

	cases := []tc{
		{
			name:      "next-table",
			inetPrio:  nextTableRulePriority + 1,
			inet6Prio: nextTableRulePriority + 2,
			run: func(ops *fakeRuleOps) error {
				nt := &nextTableManager{ops: ops}
				// No routes carry a next-table directive → no re-adds; the
				// only work clear() does is delete-in-window.
				return nt.Apply(nil, nil)
			},
		},
		{
			name:      "rib-group",
			inetPrio:  ribGroupRulePriority + 1,
			inet6Prio: ribGroupRulePriority + 2,
			run: func(ops *fakeRuleOps) error {
				rg := &ribGroupManager{ops: ops}
				// Empty rib-groups → early return after clear; no re-adds.
				return rg.Apply(nil, nil)
			},
		},
		{
			name:      "pbr",
			inetPrio:  pbrRulePriority + 1,
			inet6Prio: pbrRulePriority + 2,
			run: func(ops *fakeRuleOps) error {
				p := &pbrManager{ops: ops}
				// Empty PBR set → early return after clear; no re-adds.
				return p.Apply(nil)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := newFakeRuleOps()
			// One managed-window rule per family.
			seedRule(ops, unix.AF_INET, c.inetPrio, 100)
			seedRule(ops, unix.AF_INET6, c.inet6Prio, 101)
			// AF_INET dump fails transiently; AF_INET6 succeeds.
			ops.failList(unix.AF_INET, injErr)

			err := c.run(ops)
			if err == nil {
				t.Fatalf("%s: Apply must return an error when RuleList(AF_INET) fails (#2273) — got nil", c.name)
			}
			if !errors.Is(err, injErr) {
				t.Errorf("%s: returned error must wrap the injected list failure, got %v", c.name, err)
			}

			// Best-effort delete preserved: the family that DID list is
			// cleaned. The AF_INET6 window rule must be gone.
			if got := ops.count(unix.AF_INET6); got != 0 {
				t.Errorf("%s: AF_INET6 window rule must still be deleted despite the AF_INET list failure, count=%d rules=%v",
					c.name, got, ops.rules[unix.AF_INET6])
			}
			// The AF_INET window rule could not be listed, so it survives
			// (the orphan this PR makes observable, not silent).
			if got := ops.count(unix.AF_INET); got != 1 {
				t.Errorf("%s: AF_INET window rule should remain (its dump failed), count=%d", c.name, got)
			}
		})
	}
}
