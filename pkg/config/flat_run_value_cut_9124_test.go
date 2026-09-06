package config

import "testing"

// #9124: expandFlatRun cut a leaf's VALUE when the value happened to spell
// another leaf of the same container.
//
//	security ike gateway gw1 { ike-policy address; address 198.51.100.1; }
//
// with an IKE policy legitimately NAMED `address` was cut into `ike-policy` +
// `address`, so the gateway compiled with IKEPolicy="" and committed CLEAN at
// configstore.CheckText with zero warnings. swanctl then generated a gateway
// with no IKE policy.
//
// The scan tested every index from 1 and never consulted `leaf.args`, so index
// 1 of an `args: 1` leaf -- its value slot -- was a cut candidate. The schema
// already carried the arity; the scan simply never asked.
//
// The trigger is a naming COINCIDENCE rather than an ordinary spelling, which
// is why it survived: the operator's own object name has to equal a sibling
// keyword. That also bounds the severity -- there is no attacker input and no
// enforcement bypass -- but an explicit operator statement being silently
// dropped is an operator-contract failure whatever its blast radius.
func TestFlatRunDoesNotCutALeafValue9124(t *testing.T) {
	ike := func(pol string) string {
		return `security { ike {
			proposal pr1 {
				authentication-method pre-shared-keys;
				dh-group group14;
				authentication-algorithm sha1;
				encryption-algorithm aes-256-cbc;
			}
			policy ` + pol + ` {
				proposals pr1;
				pre-shared-key ascii-text "s3cret";
			}
			gateway gw1 {
				ike-policy ` + pol + `;
				address 198.51.100.1;
				external-interface ge-0/0/0;
			}
		} }`
	}
	for _, tc := range []struct{ name, policy string }{
		// THE DEFECT: the policy name collides with the `address` sibling.
		{"policy named after a sibling keyword", "address"},
		// The same collision one keyword over, so the fix cannot be specific
		// to `address`.
		{"policy named after another sibling", "external-interface"},
		// CONTROL: an ordinary name always worked. Without it, a fix that
		// stopped cutting entirely would pass the rows above and silently
		// break every legitimate packed chain.
		{"ordinary policy name", "pol1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, perrs := NewParser(ike(tc.policy)).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			c, err := CompileConfig(&ConfigTree{Children: root.Children})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			g := c.Security.IPsec.Gateways["gw1"]
			if g == nil {
				t.Fatal("gateway gw1 did not compile")
			}
			if g.IKEPolicy != tc.policy {
				t.Errorf("IKEPolicy = %q, want %q — the policy name was cut off as if it "+
					"were a sibling KEYWORD rather than this leaf's VALUE (#9124)",
					g.IKEPolicy, tc.policy)
			}
			// The sibling whose keyword the name collides with must still be
			// read. A fix that stopped the cut by swallowing the rest of the
			// line would satisfy the check above and lose this.
			if g.Address != "198.51.100.1" {
				t.Errorf("Address = %q, want 198.51.100.1 — the sibling statement after the "+
					"colliding value was lost", g.Address)
			}
		})
	}
}

// TestFlatRunStillExpandsPackedChains9124 is the control for the whole change.
// expandFlatRun EXISTS to split a packed chain; a fix that made it stop cutting
// would clear every row above and break the supported spelling this scan was
// written for.
func TestFlatRunStillExpandsPackedChains9124(t *testing.T) {
	for _, tc := range []struct {
		name  string
		line  string
		check func(*testing.T, *Config)
	}{
		{
			name: "applications packed chain",
			line: "set applications application a1 protocol tcp destination-port 80",
			check: func(t *testing.T, c *Config) {
				a := c.Applications.Applications["a1"]
				if a == nil {
					t.Fatal("application a1 did not compile")
				}
				if a.Protocol != "tcp" || a.DestinationPort != "80" {
					t.Errorf("protocol=%q destination-port=%q, want tcp/80 — the packed chain "+
						"stopped expanding", a.Protocol, a.DestinationPort)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &ConfigTree{}
			p, err := ParseSetCommand(tc.line)
			if err != nil {
				t.Fatalf("ParseSetCommand: %v", err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
			c, err := CompileConfig(tr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			tc.check(t, c)
		})
	}
}
