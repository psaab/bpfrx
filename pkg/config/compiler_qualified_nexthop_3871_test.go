package config

import "testing"

func findStaticRoute3871(t *testing.T, routes []*StaticRoute, dest string) *StaticRoute {
	t.Helper()
	for _, r := range routes {
		if r.Destination == dest {
			return r
		}
	}
	t.Fatalf("static route %s not found", dest)
	return nil
}

// A floating static: a primary next-hop plus a `qualified-next-hop <gw>
// { preference N; metric M; }` backup. The qualified next-hop MUST carry its
// own per-next-hop preference/metric, not fold into the route-level
// Preference. RED-on-revert: the qualified preference/metric are dropped
// (both next-hops equal-cost) (#3871).
func TestQualifiedNextHopCarriesPerNHPreference_3871(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 10.5.0.0/16 next-hop 10.0.0.1",
		"set routing-options static route 10.5.0.0/16 qualified-next-hop 10.0.0.2 preference 250",
		"set routing-options static route 10.5.0.0/16 qualified-next-hop 10.0.0.2 metric 7",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.5.0.0/16")
	if len(r.NextHops) != 2 {
		t.Fatalf("NextHops = %d, want 2 (primary + qualified backup): %+v", len(r.NextHops), r.NextHops)
	}
	var primary, qualified *NextHopEntry
	for i := range r.NextHops {
		switch r.NextHops[i].Address {
		case "10.0.0.1":
			primary = &r.NextHops[i]
		case "10.0.0.2":
			qualified = &r.NextHops[i]
		}
	}
	if primary == nil || qualified == nil {
		t.Fatalf("expected next-hops 10.0.0.1 (primary) + 10.0.0.2 (qualified): %+v", r.NextHops)
	}
	if primary.HasPreference {
		t.Errorf("primary next-hop should have no per-NH preference (uses route-level), got %d", primary.Preference)
	}
	if !qualified.HasPreference || qualified.Preference != 250 {
		t.Errorf("qualified next-hop Preference = %d (has=%v), want 250 (has=true)", qualified.Preference, qualified.HasPreference)
	}
	if !qualified.HasMetric || qualified.Metric != 7 {
		t.Errorf("qualified next-hop Metric = %d (has=%v), want 7 (has=true)", qualified.Metric, qualified.HasMetric)
	}
}

// A plain multi next-hop list must NOT acquire any per-next-hop preference —
// it is equal-cost ECMP, kept distinct from the floating qualified backup.
func TestPlainNextHopHasNoPerNHPreference_3871(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 10.6.0.0/16 next-hop 10.0.0.1",
		"set routing-options static route 10.6.0.0/16 next-hop 10.0.0.2",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.6.0.0/16")
	for _, nh := range r.NextHops {
		if nh.HasPreference || nh.HasMetric {
			t.Errorf("plain next-hop %s must have no per-NH preference/metric: %+v", nh.Address, nh)
		}
	}
}
