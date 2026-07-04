package config

import "testing"

// compileHier3881 parses a hierarchical (brace / inline-keys) config source and
// compiles it, so tests can exercise the NON-flat-set AST shapes.
func compileHier3881(t *testing.T, src string) *Config {
	t.Helper()
	p := NewParser(src)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", src, perrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return c
}

// The hierarchical INLINE-keys route form collapses the whole route onto one
// leaf node's Keys with NO children:
//
//	route 2001:db8::/32 next-hop fe80::1 interface reth0.50;   (one line, no braces)
//
// The trailing `interface <if>` is the egress modifier of the preceding
// gateway. For an IPv6 LINK-LOCAL next-hop (fe80::/10) the egress interface is
// REQUIRED — the gateway is ambiguous/unresolvable without it. Before #3881 the
// inline-keys switch had no logic to consume `interface <if>` after the gateway
// run, so the interface was silently DROPPED and the route misinstalled.
//
// RED-on-revert: nh.Interface is "" (interface dropped) on revert.
func TestStaticRouteInlineKeysInterfaceModifier_3881(t *testing.T) {
	c := compileHier3881(t,
		`routing-options { static { route 2001:db8::/32 next-hop fe80::1 interface reth0.50; } }`)
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "2001:db8::/32")
	if len(r.NextHops) != 1 {
		t.Fatalf("NextHops = %d, want 1: %+v", len(r.NextHops), r.NextHops)
	}
	nh := r.NextHops[0]
	if nh.Address != "fe80::1" || nh.Interface != "reth0.50" {
		t.Fatalf("inline-keys next-hop = {Address:%q Interface:%q}, want {fe80::1 reth0.50}",
			nh.Address, nh.Interface)
	}
}

// The hierarchical BRACE form (route node WITH children) already carried the
// interface modifier — this pins it so the #3881 fix does not regress the shape
// that worked.
func TestStaticRouteBraceInterfaceModifier_3881(t *testing.T) {
	c := compileHier3881(t,
		`routing-options { static { route 2001:db8::/32 { next-hop fe80::1 interface reth0.50; } } }`)
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "2001:db8::/32")
	if len(r.NextHops) != 1 {
		t.Fatalf("NextHops = %d, want 1: %+v", len(r.NextHops), r.NextHops)
	}
	nh := r.NextHops[0]
	if nh.Address != "fe80::1" || nh.Interface != "reth0.50" {
		t.Fatalf("brace next-hop = {Address:%q Interface:%q}, want {fe80::1 reth0.50}",
			nh.Address, nh.Interface)
	}
}

// The flat-set form (ParseSetCommand + SetPath) already carried the interface
// modifier (#3872) — pin it alongside the two hierarchical shapes so all three
// entry paths agree.
func TestStaticRouteFlatSetInterfaceModifier_3881(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 2001:db8::/32 next-hop fe80::1 interface reth0.50",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "2001:db8::/32")
	if len(r.NextHops) != 1 {
		t.Fatalf("NextHops = %d, want 1: %+v", len(r.NextHops), r.NextHops)
	}
	nh := r.NextHops[0]
	if nh.Address != "fe80::1" || nh.Interface != "reth0.50" {
		t.Fatalf("flat-set next-hop = {Address:%q Interface:%q}, want {fe80::1 reth0.50}",
			nh.Address, nh.Interface)
	}
}

// An inline-keys ECMP list keeps every gateway AND applies a trailing interface
// modifier to the gateways (single-egress link-local ECMP). Guards that the
// #3881 interface consume did not break the #3872 multi-gateway absorb.
func TestStaticRouteInlineKeysECMPStillWorks_3881(t *testing.T) {
	c := compileHier3881(t,
		`routing-options { static { route 10.1.0.0/16 next-hop 10.0.0.1 10.0.0.2; } }`)
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.1.0.0/16")
	got := nhAddrs3872(r.NextHops)
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("inline ECMP next-hops = %v, want [10.0.0.1 10.0.0.2]", got)
	}
}

// Defect 2 (negligible edge): a next-hop value literally named "interface" as
// the FIRST token must be treated as a gateway, not the modifier keyword. The
// interface-modifier detection fires only after ≥1 gateway is parsed.
func TestStaticRouteNextHopLiteralInterfaceFirstValue_3881(t *testing.T) {
	c := compileHier3881(t,
		`routing-options { static { route 10.9.0.0/16 { next-hop interface; } } }`)
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.9.0.0/16")
	if len(r.NextHops) != 1 {
		t.Fatalf("NextHops = %d, want 1: %+v", len(r.NextHops), r.NextHops)
	}
	nh := r.NextHops[0]
	if nh.Address != "interface" || nh.Interface != "" {
		t.Fatalf("bare-first literal next-hop = {Address:%q Interface:%q}, want gateway {interface \"\"}",
			nh.Address, nh.Interface)
	}
}
