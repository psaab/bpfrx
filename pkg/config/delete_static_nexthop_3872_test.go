package config

import "testing"

// applySetsDeletes3872 applies `set ...` then `delete ...` commands (prefix
// each command with its verb) via ParseSetCommand + SetPath/DeletePath, then
// compiles.
func applySetsDeletes3872(t *testing.T, sets []string, deletes []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range sets {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	for _, cmd := range deletes {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(delete %q): %v", cmd, err)
		}
		if err := tree.DeletePath(path); err != nil {
			t.Fatalf("DeletePath(%q): %v", cmd, err)
		}
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

// Deleting ONE gateway of a `next-hop [ a b ]` ECMP list must remove only that
// gateway and keep the healthy other path — NOT delete the whole leaf and
// leave the route with 0 next-hops (which renders Null0 blackhole). RED-on-
// revert: the whole next-hop leaf is deleted, route blackholed (#3872 delete
// side, the #3846 class).
func TestDeleteStaticNextHopFirstMember_3872(t *testing.T) {
	c := applySetsDeletes3872(t,
		[]string{"set routing-options static route 10.1.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 ]"},
		[]string{"routing-options static route 10.1.0.0/16 next-hop 10.0.0.1"},
	)
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.1.0.0/16")
	got := nhAddrs3872(r.NextHops)
	if len(got) != 1 || got[0] != "10.0.0.2" {
		t.Fatalf("after delete 10.0.0.1: next-hops = %v, want [10.0.0.2] (healthy path must survive; whole route was blackholed before the fix)", got)
	}
}

// Deleting a NON-FIRST gateway also works (was "path not found" before).
func TestDeleteStaticNextHopNonFirstMember_3872(t *testing.T) {
	c := applySetsDeletes3872(t,
		[]string{"set routing-options static route 10.1.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 ]"},
		[]string{"routing-options static route 10.1.0.0/16 next-hop 10.0.0.2"},
	)
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.1.0.0/16")
	got := nhAddrs3872(r.NextHops)
	if len(got) != 1 || got[0] != "10.0.0.1" {
		t.Fatalf("after delete 10.0.0.2: next-hops = %v, want [10.0.0.1]", got)
	}
}

// Deleting an interface-qualified gateway drops the WHOLE entry (gateway + its
// interface modifier), not a gateway-less next-hop container.
func TestDeleteStaticNextHopInterfaceQualified_3872(t *testing.T) {
	c := applySetsDeletes3872(t,
		[]string{
			"set routing-options static route 2001:db8::/32 next-hop fe80::1 interface reth0.50",
			"set routing-options static route 2001:db8::/32 next-hop fe80::2 interface reth0.51",
		},
		[]string{"routing-options static route 2001:db8::/32 next-hop fe80::1"},
	)
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "2001:db8::/32")
	if len(r.NextHops) != 1 {
		t.Fatalf("after delete fe80::1: NextHops = %d, want 1 (whole entry dropped): %+v", len(r.NextHops), r.NextHops)
	}
	nh := r.NextHops[0]
	if nh.Address != "fe80::2" || nh.Interface != "reth0.51" {
		t.Fatalf("surviving next-hop = {Address:%q Interface:%q}, want {fe80::2 reth0.51}", nh.Address, nh.Interface)
	}
}

// Deleting the LAST gateway leaves the route with 0 next-hops — which must NOT
// render a Null0 blackhole. RED-on-revert: the route renders Null0 (fail-wide).
func TestDeleteStaticNextHopLastMember_3872(t *testing.T) {
	c := applySetsDeletes3872(t,
		[]string{"set routing-options static route 10.1.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 ]"},
		[]string{
			"routing-options static route 10.1.0.0/16 next-hop 10.0.0.1",
			"routing-options static route 10.1.0.0/16 next-hop 10.0.0.2",
		},
	)
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.1.0.0/16")
	if len(r.NextHops) != 0 {
		t.Fatalf("after deleting both gateways: NextHops = %v, want none", nhAddrs3872(r.NextHops))
	}
}

// Deleting a member that is not present is reported (not silently succeeding).
func TestDeleteStaticNextHopAbsentMemberErrors_3872(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set routing-options static route 10.1.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 ]"} {
		path, _ := ParseSetCommand(cmd)
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	path, _ := ParseSetCommand("routing-options static route 10.1.0.0/16 next-hop 10.9.9.9")
	if err := tree.DeletePath(path); err == nil {
		t.Fatal("deleting an absent next-hop member should error (not-found contract)")
	}
}
