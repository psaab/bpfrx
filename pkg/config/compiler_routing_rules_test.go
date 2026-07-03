package config

import (
	"fmt"
	"strings"
	"testing"
)

// mkLeakingInstance builds a config with ONE routing-instance that imports
// the main table via an interface-routes rib-group and carries n static
// connected prefixes on its member interface unit. family selects v4 ("inet")
// or v6 ("inet6") addresses (and the corresponding rib-group field), so the
// #3876 per-prefix window warn can be exercised on either family.
func mkLeakingInstance(n int, family string) *Config {
	cfg := &Config{}
	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if family == "inet6" {
			addrs = append(addrs, fmt.Sprintf("2001:db8:%x::1/64", i))
		} else {
			addrs = append(addrs, fmt.Sprintf("10.%d.%d.1/24", i/256, i%256))
		}
	}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: addrs},
		}},
	}
	cfg.RoutingOptions.RibGroups = map[string]*RibGroup{
		"leak": {Name: "leak", ImportRibs: []string{"inet.0", "inet6.0"}},
	}
	ri := &RoutingInstanceConfig{
		Name:       "dmz-vr",
		TableID:    101,
		Interfaces: []string{"ge-0/0/1.0"},
	}
	if family == "inet6" {
		ri.InterfaceRoutesRibGroupV6 = "leak"
	} else {
		ri.InterfaceRoutesRibGroup = "leak"
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{ri}
	return cfg
}

// TestValidateRoutingRuleWindowWarnings covers the commit-time warnings that
// pair with the applier's fixed next-table / rib-group ip-rule priority
// windows. The warning fires only when the config exceeds the window the
// applier can program; at or below the limit it stays silent. The rib-group
// window is now PER CONNECTED PREFIX (#3876, 1000-rule window).
func TestValidateRoutingRuleWindowWarnings(t *testing.T) {
	mkNextTableRoutes := func(n int) []*StaticRoute {
		routes := make([]*StaticRoute, n)
		for i := range routes {
			routes[i] = &StaticRoute{Destination: "10.0.0.0/8", NextTable: "vr"}
		}
		return routes
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
		cfg := mkLeakingInstance(1000, "inet")
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) != 0 {
			t.Fatalf("expected no warning at 1000 leaked prefixes, got %v", got)
		}
	})

	t.Run("rib-group over limit warns", func(t *testing.T) {
		cfg := mkLeakingInstance(1001, "inet")
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) != 1 || !strings.Contains(got[0], "rib-group") {
			t.Fatalf("expected a rib-group over-limit warning, got %v", got)
		}
		if !strings.Contains(got[0], "1001") {
			t.Errorf("warning should report the prefix count 1001, got %q", got[0])
		}
	})

	t.Run("instances with no rib-group reference are not counted", func(t *testing.T) {
		// An addressed instance with NO rib-group reference contributes no
		// leaked prefixes and must not warn.
		cfg := mkLeakingInstance(1001, "inet")
		cfg.RoutingInstances[0].InterfaceRoutesRibGroup = ""
		got := validateRoutingRuleWindowWarnings(cfg)
		if len(got) != 0 {
			t.Fatalf("instances without a rib-group reference must not warn, got %v", got)
		}
	})

	t.Run("v6-only rib-group reference is counted", func(t *testing.T) {
		cfg := mkLeakingInstance(1001, "inet6")
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
	cfg := mkLeakingInstance(1001, "inet")
	for i := 0; i < 101; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&StaticRoute{Destination: "10.0.0.0/8", NextTable: "vr"})
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
