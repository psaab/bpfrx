package config

import "testing"

// issue 8939, first row by consequence: a single `set` command naming two
// cluster leaves silently dropped the second.
//
//	set chassis cluster authentication-key A additional-authentication-key B
//	  -> ControlLinkAuthKey="A"  ControlLinkAuthKeyAlt=""
//	  strictErr=false  warnings=0
//
// The dropped value is the ALTERNATE control-link PSK. An operator rotating
// cluster keys writes both, sees the command accepted, and gets one -- so the
// rollover they staged does not exist and the peer that presents the new key is
// refused. A silently absent second key is worse than a rejected command,
// because the rollover looks staged.
//
// WHY SetPath AND NOT THE PACKED TAIL. The hierarchical spelling of the same
// thing ALREADY WORKED: there both statements land on one node's Keys and
// splitClusterKeys separates them. The flat-set command instead builds a CHAIN
//
//	[authentication-key A]
//	  [additional-authentication-key B]
//
// so nothing is packed onto Keys, `clusterBodyNeedsSplit` said no, and the
// whole normalization was skipped for that shape. Both halves are fixed:
// the gate now recognises the chain, and the splitter hoists it.
//
// THE REMEDY FOLLOWS #6524 rather than rejecting the spelling. The chain is a
// SUPPORTED form -- `set applications application a1 protocol tcp
// destination-port 80` is tested behaviour -- and #6524 recorded why a schema
// reject is wrong: it would leave the LENIENT path (boot load, HA SyncApply)
// untouched, which is exactly where already-stored configs are.
func TestChainedClusterSetKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *ClusterConfig {
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
		return cfg.Chassis.Cluster
	}

	// REFERENCE ARM: two separate commands, the spelling that always worked.
	ref := build(t,
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaa",
		"set chassis cluster additional-authentication-key bbbbbbbbbbbbbbbb")
	if ref == nil || ref.ControlLinkAuthKeyAlt.Reveal() == "" {
		t.Fatal("the two-command reference arm carries no alternate key, so every " +
			"comparison below would pass against a config that has none (#8939)")
	}

	got := build(t, "set chassis cluster authentication-key aaaaaaaaaaaaaaaa "+
		"additional-authentication-key bbbbbbbbbbbbbbbb")
	if got == nil {
		t.Fatal("the packed command produced no cluster config (#8939)")
	}
	if got.ControlLinkAuthKey.Reveal() != ref.ControlLinkAuthKey.Reveal() {
		t.Errorf("packed command lost the primary control-link key: got %d bytes, "+
			"want %d (#8939)",
			len(got.ControlLinkAuthKey.Reveal()), len(ref.ControlLinkAuthKey.Reveal()))
	}
	if got.ControlLinkAuthKeyAlt.Reveal() != ref.ControlLinkAuthKeyAlt.Reveal() {
		t.Errorf("packed command lost the ALTERNATE control-link key: got %d bytes, "+
			"want %d.\n"+
			"  `set chassis cluster authentication-key A additional-authentication-key B` "+
			"is accepted with no error and no warning, and stores only A. A key "+
			"rollover staged this way does not exist, and the peer presenting the "+
			"new key is refused (#8939).",
			len(got.ControlLinkAuthKeyAlt.Reveal()), len(ref.ControlLinkAuthKeyAlt.Reveal()))
	}
}

// The two spellings that already worked, asserted so the chain fix cannot be
// bought at their expense -- and because the hierarchical arm is what proves
// the defect was SetPath's chain rather than the packed tail.
func TestClusterHierarchicalSpellingsUnaffected8939(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"braced", `chassis { cluster { authentication-key aaaaaaaaaaaaaaaa; additional-authentication-key bbbbbbbbbbbbbbbb; } }`},
		{"packed-tail", `chassis { cluster { authentication-key aaaaaaaaaaaaaaaa additional-authentication-key bbbbbbbbbbbbbbbb; } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileText(t, tc.text)
			if cfg == nil || cfg.Chassis.Cluster == nil {
				t.Fatal("fixture did not compile (#8939)")
			}
			cl := cfg.Chassis.Cluster
			if cl.ControlLinkAuthKey.Reveal() == "" || cl.ControlLinkAuthKeyAlt.Reveal() == "" {
				t.Errorf("the %s spelling lost a control-link key (primary=%d bytes, "+
					"alternate=%d bytes) -- it worked before the chain fix and must "+
					"still (#8939)",
					tc.name, len(cl.ControlLinkAuthKey.Reveal()), len(cl.ControlLinkAuthKeyAlt.Reveal()))
			}
		})
	}
}

// A container that legitimately declares children must NOT be hoisted. The
// promotion is gated on the schema for exactly this reason: `redundancy-group`
// owns its body, and flattening it would break the shape clusterBodyStatements
// depends on.
func TestClusterContainerBodyIsNotHoisted8939(t *testing.T) {
	cfg := compileText(t, `chassis { cluster { redundancy-group 1 { node 0 priority 100; node 1 priority 1; } } }`)
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("fixture did not compile (#8939)")
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 {
		t.Fatalf("redundancy-group count = %d, want 1 -- a container body was "+
			"hoisted into cluster-level siblings by the chain promotion (#8939)", len(rgs))
	}
	if len(rgs[0].NodePriorities) != 2 {
		t.Errorf("redundancy-group 1 has %d node-priority entries, want 2 -- its body was "+
			"flattened (#8939)", len(rgs[0].NodePriorities))
	}
}
