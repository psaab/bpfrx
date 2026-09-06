package config

import "testing"

// #8939: `security ike gateway` and `security ipsec gateway` dropped every leaf
// after the first of a flat `set` command.
//
//	set security ike gateway gw1 address A external-interface E
//	  -> address="A"  external-interface=""
//
// A gateway with no external-interface binds to nothing: the VPN does not come
// up, and `show configuration` renders exactly what the operator typed.
//
// THIS CELL ASSERTS THREE LEAVES, DELIBERATELY, AND THE RATCHET CANNOT.
// flat_set_chain_walk_8939_test.go synthesizes the two alphabetically-first
// eligible leaves per container, and at TWO leaves the chain is
// indistinguishable from ordinary nesting:
//
//	two    [address A]
//	         [external-interface E]                  <- looks like nesting
//	three  [address A]
//	         [external-interface E local-address L]  <- ONE node, a FLAT RUN
//
// So a recursive DESCENT — the obvious fix — reads `external-interface`, drops
// `local-address`, and still clears every row of that fixture. The ratchet's
// green is necessary and not sufficient for this class of fix, which is why
// this assertion lives here rather than being left to it.
func TestGatewayFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *IPsecGateway {
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
		return cfg.Security.IPsec.Gateways["gw1"]
	}

	// BOTH containers. They share the IPsecGateway struct and DUPLICATE the
	// reader -- compileIKE and compileIPsec each carry their own
	// `for … range inst.node.Children` loop -- so a fix applied to one leaves
	// the other silently broken. Measured, not assumed.
	for _, base := range []string{
		"set security ike gateway gw1 ",
		"set security ipsec gateway gw1 ",
	} {
		t.Run(base, func(t *testing.T) {
			// REFERENCE ARM: separate commands, the spelling that always worked.
			ref := build(t, base+"address 192.0.2.1",
				base+"external-interface ge-0/0/0",
				base+"local-address 10.0.0.1")
			if ref == nil || ref.Address == "" || ref.ExternalIface == "" || ref.LocalAddress == "" {
				t.Fatalf("the split reference arm is incomplete (%+v) -- every "+
					"comparison below would pass against a gateway that carries "+
					"nothing (#8939)", ref)
			}

			for _, tc := range []struct{ name, cmd string }{
				{"two leaves", base + "address 192.0.2.1 external-interface ge-0/0/0"},
				// THE CASE A RECURSIVE DESCENT FAILS. At three leaves the
				// remainder packs onto ONE node's Keys, so only a
				// keyword-delimited scan reaches the third.
				{"three leaves", base + "address 192.0.2.1 external-interface ge-0/0/0 local-address 10.0.0.1"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got := build(t, tc.cmd)
					if got == nil {
						t.Fatalf("the packed command produced no gateway (#8939)")
					}
					if got.Address != ref.Address {
						t.Errorf("address = %q, want %q (#8939)", got.Address, ref.Address)
					}
					if got.ExternalIface != ref.ExternalIface {
						t.Errorf("external-interface = %q, want %q — a gateway bound "+
							"to nothing does not bring the VPN up, and `show "+
							"configuration` renders what the operator typed (#8939)",
							got.ExternalIface, ref.ExternalIface)
					}
					if tc.name == "three leaves" && got.LocalAddress != ref.LocalAddress {
						t.Errorf("local-address = %q, want %q — the THIRD leaf of the "+
							"run. A recursive descent reads the second and drops "+
							"this one, and the #8939 ratchet (two leaves per "+
							"container) would still record the container as fixed "+
							"(#8939)", got.LocalAddress, ref.LocalAddress)
					}
				})
			}
		})
	}
}

// A leaf that OWNS A BODY must keep its subtree: expandFlatRun must not hoist a
// nested block into sibling statements of the container.
func TestGatewayFlatRunLeavesBodiesAlone8939(t *testing.T) {
	tree := &ConfigTree{}
	for _, c := range []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 dead-peer-detection interval 10",
	} {
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
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil || gw.Address != "192.0.2.1" {
		t.Fatalf("the gateway lost its address while a body-owning sibling was "+
			"present: %+v (#8939)", gw)
	}
}
