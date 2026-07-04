package config

import "testing"

// TestRoutingInstanceInterfaceMultiValue_3904 is the F-163 RED-on-revert guard:
// a routing-instance `interface [ ge-0/0/1 ge-0/0/2 ]` bracket list must place
// EVERY listed port in the routing-instance, not just the first. Before #3904
// the compiler read `nodeVal(prop)` (Keys[1]) and dropped the rest, stranding
// the remaining ports in the default table — a VRF isolation break (the routing
// arm of the #2419 bracket-list-truncation class).
func TestRoutingInstanceInterfaceMultiValue_3904(t *testing.T) {
	tree := buildTree3904(t, []string{
		"set routing-instances VR instance-type virtual-router",
		"set routing-instances VR interface [ ge-0/0/1 ge-0/0/2 ]",
	})
	// The routing-instance config must also be commit-valid.
	var scfg Config
	if err := SchemaValidate(tree, &scfg); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}

	var cfg Config
	if err := compileRoutingInstances(tree.FindChild("routing-instances"), &cfg); err != nil {
		t.Fatalf("compileRoutingInstances: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("routing-instances = %d, want 1", len(cfg.RoutingInstances))
	}
	ri := cfg.RoutingInstances[0]
	if !equalStrs3904(ri.Interfaces, []string{"ge-0/0/1", "ge-0/0/2"}) {
		t.Errorf("routing-instance %q interfaces = %v, want [ge-0/0/1 ge-0/0/2] (bracket list truncated → VRF isolation break)", ri.Name, ri.Interfaces)
	}
}

// TestRoutingInstanceInterfaceSeparateLines_3904 confirms the repeated-line
// form (one `interface` set per port) still accumulates every port, and a
// single-value form keeps working.
func TestRoutingInstanceInterfaceSeparateLines_3904(t *testing.T) {
	tree := buildTree3904(t, []string{
		"set routing-instances VR interface ge-0/0/1",
		"set routing-instances VR interface ge-0/0/2",
	})
	var cfg Config
	if err := compileRoutingInstances(tree.FindChild("routing-instances"), &cfg); err != nil {
		t.Fatalf("compileRoutingInstances: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("routing-instances = %d, want 1", len(cfg.RoutingInstances))
	}
	if !equalStrs3904(cfg.RoutingInstances[0].Interfaces, []string{"ge-0/0/1", "ge-0/0/2"}) {
		t.Errorf("repeated-line interfaces = %v, want [ge-0/0/1 ge-0/0/2]", cfg.RoutingInstances[0].Interfaces)
	}
}
