package config

import "testing"

// #8939 on `protocols router-advertisement interface`, and this one RE-CREATES
// A FIXED DEFECT BY A DIFFERENT ROUTE.
//
//	set protocols router-advertisement interface ge-0/0/0 \
//	    managed-configuration default-lifetime 0
//	  -> ManagedConfig=true  DefaultLifetime=0  DefaultLifetimeSet=FALSE
//
// `DefaultLifetimeSet` is the whole point of #4119. RFC 4861 §6.2.1 gives
// Router Lifetime 0 the meaning "this router is NOT a default router", so an
// EXPLICIT 0 must be distinguishable from an absent value. pkg/ra/sender.go
// keys on exactly that flag:
//
//	lifetime := defaultRouterLifetime          // 1800
//	if s.cfg.DefaultLifetimeSet { lifetime = s.cfg.DefaultLifetime }
//
// With the flag false, an operator's explicit 0 is advertised as 1800 — and
// #4119's own comment says what that costs: "xpf could never advertise `not a
// default router' and HIJACKED HOST DEFAULT-ROUTE SELECTION on multi-router
// LANs." #4119 fixed the `lifetime <= 0` coercion in the sender; the flat
// spelling reaches the identical outcome by never setting the flag.
//
// OPERATOR-REACHABLE, and only in the ordering an operator would naturally
// type. Measured through the strict pair:
//
//	default-lifetime 600 link-mtu 1400 managed-configuration   SCHEMA-REJECT
//	link-mtu 1400 default-lifetime 600 managed-configuration   SCHEMA-REJECT
//	managed-configuration default-lifetime 600 link-mtu 1400   ACCEPTED
//
// Flag first is admitted because `managed-configuration` is args:0 and
// untyped, and the container is open-world — the #9148 conjunction. My first
// probe tested ONLY the alphabetical ordering and concluded `SCHEMA-REJECT`;
// the census's union-over-orderings had it right and my narrower instrument
// was wrong.
func TestRAInterfaceFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *RAInterfaceConfig {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		for _, i := range cfg.Protocols.RouterAdvertisement {
			if i != nil && i.Interface == "ge-0/0/0" {
				return i
			}
		}
		t.Fatal("the command produced no RA interface (#8939)")
		return nil
	}

	b := "set protocols router-advertisement interface ge-0/0/0 "

	// THE SHARP CASE, and it is its own subtest because the consequence is
	// categorically different from a lost setting: an explicit 0 that survives
	// as "unset" is advertised as 1800.
	t.Run("explicit zero lifetime", func(t *testing.T) {
		ref := build(t, b+"managed-configuration", b+"default-lifetime 0")
		if !ref.DefaultLifetimeSet || ref.DefaultLifetime != 0 {
			t.Fatalf("the split reference arm did not record an EXPLICIT zero "+
				"(%+v); the comparison below would be meaningless (#8939, #4119)", ref)
		}
		got := build(t, b+"managed-configuration default-lifetime 0")
		if !got.DefaultLifetimeSet {
			t.Errorf("DefaultLifetimeSet = false after an explicit `default-lifetime "+
				"0`. pkg/ra/sender.go then advertises %d instead of 0, so the router "+
				"announces itself as a default router when the operator said it is "+
				"NOT one — #4119's defect, reached by a different route (#8939)",
				1800)
		}
		if got.DefaultLifetime != ref.DefaultLifetime {
			t.Errorf("default-lifetime = %d, want %d (#8939)",
				got.DefaultLifetime, ref.DefaultLifetime)
		}
	})

	t.Run("three leaves", func(t *testing.T) {
		// Flag first: the ordering that is ADMITTED at commit.
		ref := build(t, b+"managed-configuration", b+"default-lifetime 600",
			b+"link-mtu 1400")
		if !ref.ManagedConfig || !ref.DefaultLifetimeSet || ref.LinkMTU == 0 {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		for _, tc := range []struct{ name, cmd string }{
			{"two leaves", b + "managed-configuration default-lifetime 600"},
			{"three leaves", b + "managed-configuration default-lifetime 600 link-mtu 1400"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := build(t, tc.cmd)
				if got.DefaultLifetime != ref.DefaultLifetime ||
					got.DefaultLifetimeSet != ref.DefaultLifetimeSet {
					t.Errorf("default-lifetime = %d/set=%v, want %d/set=%v (#8939)",
						got.DefaultLifetime, got.DefaultLifetimeSet,
						ref.DefaultLifetime, ref.DefaultLifetimeSet)
				}
				if tc.name == "three leaves" && got.LinkMTU != ref.LinkMTU {
					t.Errorf("link-mtu = %d, want %d -- the leaf a recursive descent "+
						"drops; without it the RA carries no MTU option and hosts fall "+
						"back to the interface MTU (#8939)", got.LinkMTU, ref.LinkMTU)
				}
			})
		}
	})
}
