package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #6467 cross-family cap binding.
//
// The kernel programs global next-table leaks as ip rules from a SINGLE shared
// priority counter: pkg/routing nextTableManager.Apply iterates v4 then v6 and
// advances one `prio` across both families, so the 100-entry window is shared,
// not per-family. buildRouteSnapshots mirrors that by declaring
// `nextTableLeakCount` OUTSIDE the addRoutes closure (routes.go), so the two
// global calls — inet then inet6 — draw down the same budget.
//
// Every pre-existing #6467 fixture is v4-ONLY, so that shared-ness was never
// bound: moving `nextTableLeakCount := 0` into the addRoutes closure (making
// the window per-call) leaves the ENTIRE package green while a 60 v4 + 60 v6
// config publishes 120 FIB leaks against the kernel's 100 — the #6467
// kernel/dataplane verdict split silently restored in its cross-family form.
//
// This test is that missing binding. Note it asserts the per-family SPLIT
// (60 inet + 40 inet6), not merely a total of 100: a total-only assertion is
// also satisfied by a 50/50 split, which the kernel would never produce because
// it fills v4 first.
func TestBuildRouteSnapshotsNextTableCapIsSharedAcrossFamilies_6467(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	// Isolate the config-static next-table path: no kernel ip-rules to ingest.
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	// 60 + 60 straddles the 100-entry window: v4 fits entirely, v6 is truncated
	// to the remainder. Both counts are below the window on their own, so a
	// per-family counter would publish all 120 and cap neither.
	const v4Count = 60
	const v6Count = 60
	const wantV4 = v4Count                              // 60 — fits, filled first
	const wantV6 = config.NextTableRuleWindow - v4Count // 40 — the remainder

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < v4Count; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "blue",
			})
	}
	for i := 0; i < v6Count; i++ {
		cfg.RoutingOptions.Inet6StaticRoutes = append(cfg.RoutingOptions.Inet6StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("2001:db8:%x::/48", i),
				NextTable:   "blue",
			})
	}

	routes, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	var gotV4, gotV6 int
	for _, r := range routes {
		if r.NextTable != "blue" {
			continue
		}
		switch r.Family {
		case "inet":
			gotV4++
		case "inet6":
			gotV6++
		default:
			t.Fatalf("unexpected family %q on a next-table leak", r.Family)
		}
	}

	if total := gotV4 + gotV6; total != config.NextTableRuleWindow {
		t.Fatalf("the next-table window is SHARED across families: %d v4 + %d v6 routes must "+
			"publish exactly %d FIB leaks, got %d (%d inet + %d inet6). A per-family counter "+
			"publishes all %d and re-opens the #6467 kernel/dataplane verdict split — leak "+
			"#%d+ resolves into the target VRF on the AF_XDP fast path while a slow-path "+
			"packet resolves in the main table",
			v4Count, v6Count, config.NextTableRuleWindow, total, gotV4, gotV6,
			v4Count+v6Count, config.NextTableRuleWindow+1)
	}
	// The SPLIT, not just the total. The kernel fills v4 first and then spends
	// what remains on v6, so a 50/50 split would also total 100 while diverging
	// from what the kernel actually installs.
	if gotV4 != wantV4 || gotV6 != wantV6 {
		t.Fatalf("shared window must be drawn down v4-first like the kernel applier "+
			"(pkg/routing nextTableManager.Apply iterates v4 then v6 on one prio counter): "+
			"want %d inet + %d inet6, got %d inet + %d inet6",
			wantV4, wantV6, gotV4, gotV6)
	}
}

// TestBuildRouteSnapshotsV6OnlyNextTableCapped_6467 covers the mirror case the
// v4-only fixtures also leave unbound: a v6-only over-window config must be
// capped too. Without it, a regression that caps only the first addRoutes call
// would still pass the cross-family test above (v4 fills the window there).
func TestBuildRouteSnapshotsV6OnlyNextTableCapped_6467(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	const n = config.NextTableRuleWindow + 50

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < n; i++ {
		cfg.RoutingOptions.Inet6StaticRoutes = append(cfg.RoutingOptions.Inet6StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("2001:db8:%x::/48", i),
				NextTable:   "blue",
			})
	}

	routes, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	leaks := 0
	for _, r := range routes {
		if r.NextTable == "blue" {
			leaks++
		}
	}
	if leaks != config.NextTableRuleWindow {
		t.Fatalf("a v6-only over-window next-table config must cap at exactly %d leaks like "+
			"its v4 twin, got %d", config.NextTableRuleWindow, leaks)
	}
}
