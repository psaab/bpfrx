package config

import "testing"

// #8690 family 4: interfaces. 15 sites, all drop shape "empty".

// A GRE tunnel's destination decides where the tunnel goes. Brace-elided it
// compiled to nothing, so the interface came up with no tunnel endpoint on a
// commit that reported success.
func TestElidedTunnelDestinationReachesTheInterface8690(t *testing.T) {
	const braced = `interfaces { gr-0/0/0 { tunnel { source 10.0.0.1; destination 10.0.0.2; } } }`
	const elided = `interfaces { gr-0/0/0 { tunnel source 10.0.0.1; } }`
	b := compileText(t, braced)
	if b == nil {
		t.Fatal("the braced fixture must compile")
	}
	get := func(c *Config) (string, string) {
		i, ok := c.Interfaces.Interfaces["gr-0/0/0"]
		if !ok || i.Tunnel == nil {
			return "", ""
		}
		return i.Tunnel.Source, i.Tunnel.Destination
	}
	bs, bd := get(b)
	// POSITIVE HALF: the braced spelling must carry both, or the elided
	// comparison below is between two empty strings.
	if bs == "" || bd == "" {
		t.Fatalf("the braced spelling carried source=%q destination=%q; the fixture no longer "+
			"demonstrates the tunnel being read", bs, bd)
	}
	e := compileText(t, elided)
	if e == nil {
		t.Fatal("the elided fixture must compile")
	}
	es, _ := get(e)
	if es != "10.0.0.1" {
		t.Errorf("the brace-elided `tunnel source` compiled to %q, not %q — the tunnel is "+
			"configured differently from what the operator wrote (#8690)", es, "10.0.0.1")
	}
}

// THE DISCRIMINATION, again with the same head on both sides of the rule.
// `destination` is admitted under `tunnel` (empty) and must NOT be admitted
// under `routing-instance` (partial).
func TestTunnelAndRoutingInstanceDestinationDiffer8690(t *testing.T) {
	if !compactNormalizeInScope("tunnel", "destination") {
		t.Error("`tunnel destination` is drop shape empty and must be normalized")
	}
	if compactNormalizeInScope("routing-instance", "destination") {
		t.Error("`tunnel routing-instance destination` is drop shape PARTIAL — something " +
			"consumes part of that tail. The head is identical to `tunnel destination`, which " +
			"IS admitted; only the container distinguishes them (#8690)")
	}
}

// The ten partial sites in this family fold at the INSTANCE level, where
// production passes the instance name as the container keyword. No static pair
// can match them — they are safe by construction rather than by being listed.
//
// This cell states that so it is not mistaken for coverage: it asserts the
// property the safety depends on, so if the pass ever starts passing a schema
// keyword there instead, this reds and the ten need explicit protection.
func TestInterfaceInstancePartialsAreUnreachableByAPairRule8690(t *testing.T) {
	// A pair rule keyed on the schema token would be ("interfaces","mtu");
	// production passes the instance name. Neither is admitted today, and the
	// first must never become admissible by accident.
	if compactNormalizeInScope("interfaces", "mtu") {
		t.Error("a pair keyed on the schema token now admits `interfaces <if> mtu`, which is " +
			"drop shape PARTIAL (#8690)")
	}
	if compactNormalizeInScope("ge-0-0-0", "mtu") {
		t.Error("a pair keyed on an INSTANCE NAME is admitted — the scope has become " +
			"instance-sensitive, which no static rule should be (#8690)")
	}
}
