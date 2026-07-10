package config

import "testing"

// A Junos `route <prefix> reject` must compile to a StaticRoute carrying the
// Reject disposition (an unreachable route: drop + ICMP unreachable), distinct
// from `discard` (a silent blackhole). Before #5298 the compiler's static-route
// action switch handled only `discard`/`preference`, so a committed `reject`
// (accepted by the schema) was silently dropped: no disposition, no next-hop —
// and the FRR renderer then emitted nothing, letting matching traffic fall
// through to a less-specific route (a fail-wide). RED-on-revert: Reject stays
// false (the reject intent is erased end to end).
func TestStaticRouteRejectCompiles_5298(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 10.9.0.0/16 reject",
		"set routing-options static route 2001:db8:dead::/48 reject",
	})

	v4 := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.9.0.0/16")
	if !v4.Reject {
		t.Errorf("v4 route 10.9.0.0/16: Reject=false, want true (reject erased #5298)")
	}
	if v4.Discard {
		t.Errorf("v4 reject route must NOT set Discard (reject != silent blackhole)")
	}
	if len(v4.NextHops) != 0 {
		t.Errorf("reject route must have no next-hops, got %+v", v4.NextHops)
	}

	v6 := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "2001:db8:dead::/48")
	if !v6.Reject {
		t.Errorf("v6 route 2001:db8:dead::/48: Reject=false, want true (reject erased #5298)")
	}
}

// The hierarchical brace form must compile identically to the flat-set form.
func TestStaticRouteRejectHierarchical_5298(t *testing.T) {
	tree, errs := NewParser(`
routing-options {
    static {
        route 172.16.0.0/12 {
            reject;
        }
    }
}
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "172.16.0.0/12")
	if !r.Reject {
		t.Errorf("hierarchical reject route: Reject=false, want true")
	}
	if r.Discard {
		t.Errorf("hierarchical reject route must NOT set Discard")
	}
}

// `discard` must still compile to Discard (and never Reject), guarding the
// symmetric #5298 disposition split.
func TestStaticRouteDiscardStillDiscard_5298(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 10.8.0.0/16 discard",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.8.0.0/16")
	if !r.Discard {
		t.Errorf("discard route: Discard=false, want true")
	}
	if r.Reject {
		t.Errorf("discard route must NOT set Reject (discard = silent blackhole)")
	}
}
