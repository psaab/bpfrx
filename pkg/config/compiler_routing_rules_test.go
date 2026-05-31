package config

import (
	"strings"
	"testing"
)

// TestValidateRoutingRuleWindowWarnings covers the #1706 commit-time
// warnings that pair with the applier's fixed next-table / rib-group
// ip-rule priority windows. The warning fires only when the config
// exceeds the window the applier can program; at or below the limit it
// stays silent.
func TestValidateRoutingRuleWindowWarnings(t *testing.T) {
	mkNextTableRoutes := func(n int) []*StaticRoute {
		routes := make([]*StaticRoute, n)
		for i := range routes {
			routes[i] = &StaticRoute{Destination: "10.0.0.0/8", NextTable: "vr"}
		}
		return routes
	}
	mkRibGroupInstances := func(n int) []*RoutingInstanceConfig {
		insts := make([]*RoutingInstanceConfig, n)
		for i := range insts {
			insts[i] = &RoutingInstanceConfig{InterfaceRoutesRibGroup: "leak"}
		}
		return insts
	}

	t.Run("next-table at limit is silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.RoutingOptions.StaticRoutes = mkNextTableRoutes(100)
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) != 0 {
			t.Fatalf("expected no warning at 100 next-table routes, got %v", got)
		}
	})

	t.Run("next-table over limit warns", func(t *testing.T) {
		cfg := &Config{}
		// Split across inet + inet6 to prove both lists are counted.
		cfg.RoutingOptions.StaticRoutes = mkNextTableRoutes(60)
		cfg.RoutingOptions.Inet6StaticRoutes = mkNextTableRoutes(41)
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) == 0 || !strings.Contains(got[0], "next-table") {
			t.Fatalf("expected a next-table over-limit warning, got %v", got)
		}
		if !strings.Contains(got[0], "101") {
			t.Errorf("warning should report the combined count 101, got %q", got[0])
		}
	})

	t.Run("rib-group at limit is silent", func(t *testing.T) {
		cfg := &Config{RoutingInstances: mkRibGroupInstances(50)}
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) != 0 {
			t.Fatalf("expected no warning at 50 rib-group instances, got %v", got)
		}
	})

	t.Run("rib-group over limit warns", func(t *testing.T) {
		cfg := &Config{RoutingInstances: mkRibGroupInstances(51)}
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) != 1 || !strings.Contains(got[0], "rib-group") {
			t.Fatalf("expected a rib-group over-limit warning, got %v", got)
		}
		if !strings.Contains(got[0], "51") {
			t.Errorf("warning should report the count 51, got %q", got[0])
		}
	})

	t.Run("instances with no rib-group reference are not counted", func(t *testing.T) {
		insts := make([]*RoutingInstanceConfig, 60)
		for i := range insts {
			insts[i] = &RoutingInstanceConfig{} // no rib-group reference
		}
		cfg := &Config{RoutingInstances: insts}
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) != 0 {
			t.Fatalf("instances without a rib-group reference must not warn, got %v", got)
		}
	})

	t.Run("v6-only rib-group reference is counted", func(t *testing.T) {
		insts := make([]*RoutingInstanceConfig, 51)
		for i := range insts {
			insts[i] = &RoutingInstanceConfig{InterfaceRoutesRibGroupV6: "leak6"}
		}
		cfg := &Config{RoutingInstances: insts}
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) != 1 || !strings.Contains(got[0], "rib-group") {
			t.Fatalf("expected a rib-group over-limit warning for v6-only refs, got %v", got)
		}
	})
}

// TestValidateConfigSurfacesRoutingRuleWindowWarnings asserts the
// over-limit warnings actually flow out of the commit-time entry point
// ValidateConfig, not just the standalone helper. If the wiring in
// ValidateConfig were dropped, the operator would lose the warning even
// though the helper-level tests above still pass.
func TestValidateConfigSurfacesRoutingRuleWindowWarnings(t *testing.T) {
	cfg := &Config{}
	for i := 0; i < 101; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&StaticRoute{Destination: "10.0.0.0/8", NextTable: "vr"})
	}
	for i := 0; i < 51; i++ {
		cfg.RoutingInstances = append(cfg.RoutingInstances,
			&RoutingInstanceConfig{InterfaceRoutesRibGroup: "leak"})
	}

	warnings := ValidateConfig(cfg)
	var sawNextTable, sawRibGroup bool
	for _, w := range warnings {
		if strings.Contains(w, "next-table") && strings.Contains(w, "ignored at") {
			sawNextTable = true
		}
		if strings.Contains(w, "rib-group") && strings.Contains(w, "ignored at") {
			sawRibGroup = true
		}
	}
	if !sawNextTable {
		t.Errorf("ValidateConfig did not surface the next-table over-limit warning; got %v", warnings)
	}
	if !sawRibGroup {
		t.Errorf("ValidateConfig did not surface the rib-group over-limit warning; got %v", warnings)
	}
}
