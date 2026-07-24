package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestBuildRouteSnapshotsCapsConfigStaticNextTableLeaks is the #6467 FIB-side
// fail-on-revert guard. The userspace FIB derives next-table leaks from BOTH the
// kernel ip-rule dump (naturally capped at config.NextTableRuleWindow because
// the applier installs at most that many) AND the config static routes. Before
// #6467 the config-static path was UNCAPPED, so a config with >100 global
// next-table routes published leak #101+ into the userspace FIB even though the
// kernel dropped it — a slow-path packet matching leak #101+ then resolved into
// the target VRF on the AF_XDP fast path but the main table in the kernel.
//
// This test isolates the config-static path (ruleListFn returns no kernel rules)
// and asserts the FIB never publishes more next-table leaks than the kernel cap.
//
// RED-on-revert: removing the config.NextTableRuleWindow cap in the
// buildRouteSnapshots config-static path publishes all 150 leaks, so the
// `leaks > config.NextTableRuleWindow` assertion fails.
func TestBuildRouteSnapshotsCapsConfigStaticNextTableLeaks(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	// Isolate the config-static next-table path: no kernel ip-rules to ingest.
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	const over = 50
	const n = config.NextTableRuleWindow + over // 150 global next-table routes

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < n; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
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
	if leaks > config.NextTableRuleWindow {
		t.Fatalf("userspace FIB published %d config-static next-table leaks, exceeding "+
			"the kernel cap of %d — leak #%d+ resolves into the target VRF on the fast "+
			"path but the main table in the kernel (#6467)",
			leaks, config.NextTableRuleWindow, config.NextTableRuleWindow+1)
	}
	// The cap must truncate at exactly the window, not drop everything.
	if leaks != config.NextTableRuleWindow {
		t.Fatalf("expected exactly %d next-table leaks at the cap, got %d",
			config.NextTableRuleWindow, leaks)
	}
}

// TestBuildRouteSnapshotsUncappedBelowWindow is the companion no-regression
// guard: a config with FEWER than the window's worth of global next-table routes
// publishes every one (the #6467 cap only truncates genuine over-subscription).
func TestBuildRouteSnapshotsUncappedBelowWindow(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	const n = 10 // well under config.NextTableRuleWindow
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < n; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.0.0/16", i),
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
	if leaks != n {
		t.Fatalf("expected all %d next-table leaks published below the cap, got %d", n, leaks)
	}
}
