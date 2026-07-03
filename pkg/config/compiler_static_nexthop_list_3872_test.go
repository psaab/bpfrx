package config

import "testing"

func nhAddrs3872(nhs []NextHopEntry) []string {
	out := make([]string, 0, len(nhs))
	for _, nh := range nhs {
		out = append(out, nh.Address)
	}
	return out
}

// A canonical Junos ECMP list `next-hop [ gw1 gw2 ]` must install EVERY
// gateway as an equal-cost next-hop. RED-on-revert: only the first gateway is
// compiled (multipath silently lost) (#3872).
func TestStaticNextHopBracketListECMP_3872(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 10.1.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 ]",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.1.0.0/16")
	got := nhAddrs3872(r.NextHops)
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("next-hops = %v, want [10.0.0.1 10.0.0.2] (equal-cost ECMP)", got)
	}
	for _, nh := range r.NextHops {
		if nh.HasPreference {
			t.Errorf("plain ECMP next-hop %s must not carry a per-NH preference", nh.Address)
		}
	}
}

// A three-gateway list also keeps every gateway.
func TestStaticNextHopBracketListThree_3872(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 10.2.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 10.0.0.3 ]",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.2.0.0/16")
	got := nhAddrs3872(r.NextHops)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if len(got) != len(want) {
		t.Fatalf("next-hops = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("next-hops = %v, want %v", got, want)
		}
	}
}

// A single next-hop still compiles to exactly one entry (no regression).
func TestStaticSingleNextHopUnchanged_3872(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "0.0.0.0/0")
	if got := nhAddrs3872(r.NextHops); len(got) != 1 || got[0] != "10.0.0.254" {
		t.Fatalf("next-hops = %v, want [10.0.0.254]", got)
	}
}

// The IPv6 link-local `next-hop <gw> interface <if>` modifier still walks as a
// child — multi + valueList must NOT swallow the interface as a bogus gateway.
func TestStaticNextHopInterfaceModifierPreserved_3872(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 2001:db8::/32 next-hop fe80::1 interface reth0.50",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "2001:db8::/32")
	if len(r.NextHops) != 1 {
		t.Fatalf("NextHops = %d, want 1: %+v", len(r.NextHops), r.NextHops)
	}
	nh := r.NextHops[0]
	if nh.Address != "fe80::1" || nh.Interface != "reth0.50" {
		t.Fatalf("next-hop = {Address:%q Interface:%q}, want {fe80::1 reth0.50}", nh.Address, nh.Interface)
	}
}

// #3872 composes with #3871: a plain next-hop list AND a qualified-next-hop
// backup on the same route stay distinct — the list is equal-cost (no per-NH
// preference), the qualified entry is the floating backup (preference 250).
func TestStaticNextHopListComposesWithQualified_3872(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 10.3.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 ]",
		"set routing-options static route 10.3.0.0/16 qualified-next-hop 10.0.0.9 preference 250",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.3.0.0/16")
	var backup *NextHopEntry
	equalCost := 0
	for i := range r.NextHops {
		switch r.NextHops[i].Address {
		case "10.0.0.1", "10.0.0.2":
			if r.NextHops[i].HasPreference {
				t.Errorf("plain ECMP next-hop %s must not carry a per-NH preference", r.NextHops[i].Address)
			}
			equalCost++
		case "10.0.0.9":
			backup = &r.NextHops[i]
		}
	}
	if equalCost != 2 {
		t.Fatalf("want 2 equal-cost next-hops, got %d: %+v", equalCost, r.NextHops)
	}
	if backup == nil || !backup.HasPreference || backup.Preference != 250 {
		t.Fatalf("qualified backup 10.0.0.9 preference = want 250 floating, got %+v", backup)
	}
}
