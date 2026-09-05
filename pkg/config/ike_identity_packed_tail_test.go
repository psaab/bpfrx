package config

import "testing"

// An IKE gateway body written as a PACKED TAIL must compile the same identity
// the braced spelling does.
//
// THE ASSERTION IS THE ENFORCED OUTCOME — the compiled gateway carries
// LocalIDType/LocalIDValue — never that two spellings agree. An empty identity
// is not a weaker identity: strongSwan falls back to the local address, so the
// tunnel negotiates as a DIFFERENT peer identity than the operator configured
// and either fails to authenticate or authenticates as the wrong party. Two
// spellings that both drop it agree perfectly while every tunnel is wrong.
//
// WHY THE FIX IS THREE PARTS, each shown load-bearing by mutation rather than
// argued (`make test` in pkg/config; each mutant confirmed to APPLY and BUILD
// before its verdict was read):
//
//	scope admission of the pair       controls WHETHER the tail folds at all
//	packedStatements on the container controls HOW the folded tail splits
//	args:2 on the identity leaves     lets the split find the statement boundary
//
// The ordering matters and is the whole trap: `args:2` alone is INERT — measured
// byte-identical output — because nothing folds without the scope admission, and
// a harness that forces the flag would have reported it as a correct fix that
// changes nothing in the shipped product.
func TestIKEGatewayPackedTailCarriesIdentity(t *testing.T) {
	const head = `security { ike {
  proposal prop1 { authentication-method pre-shared-keys; dh-group group14; authentication-algorithm sha-256; encryption-algorithm aes-256-cbc; }
  policy pol1 { proposals prop1; pre-shared-key ascii-text "secret"; }
  `
	const tail = ` } }`
	gw := func(t *testing.T, body string) *IPsecGateway {
		t.Helper()
		tree, perrs := NewParser(head + body + tail).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			t.Fatalf("must COMMIT: %v", err)
		}
		for _, g := range cfg.Security.IPsec.Gateways {
			return g
		}
		t.Fatal("no gateway compiled")
		return nil
	}

	// REFERENCE: the braced spelling, which has always worked.
	ref := gw(t, `gateway gw1 { ike-policy pol1; address 192.0.2.1; external-interface ge-0/0/0; local-identity hostname foo; }`)
	if ref.LocalIDType != "hostname" || ref.LocalIDValue != "foo" {
		t.Fatalf("reference braced spelling lost the identity: type=%q value=%q — without a "+
			"working reference the packed cases below compare against nothing",
			ref.LocalIDType, ref.LocalIDValue)
	}

	for _, c := range []struct{ name, body, wantType, wantVal string }{
		{"identity is the ONLY statement in the tail",
			`gateway gw1 local-identity hostname foo;`, "hostname", "foo"},
		{"identity FIRST, sibling after",
			`gateway gw1 local-identity hostname foo external-interface ge-0/0/0;`, "hostname", "foo"},
		{"sibling first, identity AFTER",
			`gateway gw1 external-interface ge-0/0/0 local-identity hostname foo;`, "hostname", "foo"},
	} {
		g := gw(t, c.body)
		if g.LocalIDType != c.wantType || g.LocalIDValue != c.wantVal {
			t.Errorf("%s: LocalID=%q/%q, want %q/%q. An IKE gateway with no local identity "+
				"negotiates under a fallback identity, so the tunnel authenticates as the "+
				"wrong party or not at all",
				c.name, g.LocalIDType, g.LocalIDValue, c.wantType, c.wantVal)
		}
	}

	// remote-identity is the same shape and was the same defect; asserting only
	// one of the pair would leave the other free to regress.
	g := gw(t, `gateway gw1 external-interface ge-0/0/0 remote-identity hostname bar;`)
	if g.RemoteIDType != "hostname" || g.RemoteIDValue != "bar" {
		t.Errorf("packed remote-identity: RemoteID=%q/%q, want hostname/bar", g.RemoteIDType, g.RemoteIDValue)
	}

	// CONTROL: two args-declared siblings in one tail. This is what proves the
	// container opt-in works at all — before it, the tail built a CHAIN and
	// everything after the FIRST statement was lost regardless of arity, which
	// is the measurement that refuted the arity-only hypothesis.
	c := gw(t, `gateway gw1 external-interface ge-0/0/0 ike-policy pol1;`)
	if c.ExternalIface != "ge-0/0/0" || c.IKEPolicy != "pol1" {
		t.Errorf("control: two args-declared statements in one packed tail gave ext=%q pol=%q, "+
			"want both set. If only the first survives, the container is building a chain "+
			"rather than siblings and every multi-statement tail loses its remainder",
			c.ExternalIface, c.IKEPolicy)
	}
}
