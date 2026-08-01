package config

import (
	"reflect"
	"testing"
)

// Tests for #6659 (fail-open half): compiler arms that read only ONE side of a
// dual-shape multi-value leaf, so a bracketed list or a packed statement
// silently compiled to one value — or to none.
//
// CLAUDE.md states the rule: "A compiler reading a multi-value leaf MUST read
// child.Keys[1:] AND child.Children and accumulate." These five arms did not.
// They are grouped here because each one is a FAIL-OPEN — the dropped value
// either widens what a rule matches, or escapes the commit gate that exists to
// reject it — as opposed to the pure value-drops tracked separately on #6659.
//
// THE ONE-SIDEDNESS RUNS IN BOTH DIRECTIONS. This is the property that makes the
// class recur, and it defeats the obvious fix strategy:
//
//   - some arms read Children and NEVER Keys[1:] — `attributes-match` and
//     `then change-configuration commands` here, which is why their PACKED-LEAF
//     spellings compiled to nothing while the block spellings worked;
//   - other arms read Keys[1:] and NEVER Children — the CoS `code-points`
//     collector (not in this PR) reads Keys plus the inline tail, so its
//     hierarchical BLOCK spelling loses the entire classifier.
//
// Anyone fixing this class by pattern-matching "looks like a nodeVal call" finds
// only the first direction and leaves the mirror image untouched. The check that
// actually works is per-shape: compile BOTH the bracketed/packed spelling AND the
// hierarchical block spelling and compare, which is what every test below does.
//
// Two distinct fail-open shapes appear below, do NOT conflate them:
//
//   - MATCH-WIDENING (attributes-match). Dropping the values makes the rule
//     match MORE than the operator wrote: an event policy with no
//     attributes-match fires on every occurrence of the event.
//   - GATE-ESCAPE (flow flag, static-NAT destination-address,
//     forwarding-table export). A commit-time validator walked the same one
//     side the compiler did, so an INVALID value in any slot but the first
//     committed CLEAN. Each of these has a paired "bogus value in slot 2"
//     assertion — that half is the actual security bug, and a fix that only
//     restores the value without extending the gate would leave it open.
//
// Per CLAUDE.md, every flat-set case is built with ParseSetCommand +
// tree.SetPath, never NewParser (which merges all set lines into one node).

func setTree6659(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func hierTree6659(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func mustCompile6659(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// --- FAIL-OPEN 1: event-options attributes-match (MATCH-WIDENING) -----------

// TestEventAttributesMatch6659PackedLeaf pins the fail-open the issue calls out:
// a PACKED-LEAF `attributes-match <event>.<attr> matches <value>;` carries the
// whole expression on the node's own Keys with NO children, and the arm read
// only Children — so the policy compiled with ZERO match constraints and fired
// on every occurrence of the event rather than the narrower set authored.
//
// The block and flat-set spellings already worked; they are asserted alongside
// as GREEN CONTROLS so a regression in the packed path is distinguishable from
// a regression in the reader as a whole.
func TestEventAttributesMatch6659PackedLeaf(t *testing.T) {
	cfg := mustCompile6659(t, hierTree6659(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        attributes-match ping_test_failed.test-owner matches Comcast;
    }
}`))
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("expected 1 event policy, got %d", len(cfg.EventOptions))
	}
	want := []string{"ping_test_failed.test-owner matches Comcast"}
	if got := cfg.EventOptions[0].AttributesMatch; !reflect.DeepEqual(got, want) {
		t.Fatalf("packed-leaf attributes-match = %q, want %q "+
			"(empty means the policy matches EVERY occurrence of the event — fail-open)", got, want)
	}
}

func TestEventAttributesMatch6659BlockAndFlatSetControls(t *testing.T) {
	want := []string{
		"ping_test_failed.test-owner matches Comcast",
		"ping_test_failed.test-name matches wan",
	}
	block := mustCompile6659(t, hierTree6659(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        attributes-match {
            ping_test_failed.test-owner matches Comcast;
            ping_test_failed.test-name matches wan;
        }
    }
}`))
	if got := block.EventOptions[0].AttributesMatch; !reflect.DeepEqual(got, want) {
		t.Fatalf("block attributes-match = %q, want %q", got, want)
	}
	flat := mustCompile6659(t, setTree6659(t,
		"set event-options policy p1 events ping_test_failed",
		"set event-options policy p1 attributes-match ping_test_failed.test-owner matches Comcast",
		"set event-options policy p1 attributes-match ping_test_failed.test-name matches wan",
	))
	if got := flat.EventOptions[0].AttributesMatch; !reflect.DeepEqual(got, want) {
		t.Fatalf("flat-set attributes-match = %q, want %q", got, want)
	}
}

// TestEventAttributesMatch6659PackedLeafReachesValidator is the GATE-ESCAPE half
// of the same arm. Because the packed leaf compiled to zero constraints,
// validateEventAttributesMatch had nothing to walk, so an expression naming an
// UNKNOWN attribute field committed CLEAN. Restoring the value must also restore
// the gate's reach.
func TestEventAttributesMatch6659PackedLeafReachesValidator(t *testing.T) {
	_, err := CompileConfig(hierTree6659(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        attributes-match ping_test_failed.NOSUCHFIELD matches Comcast;
    }
}`))
	if err == nil {
		t.Fatal("packed-leaf attributes-match with an unknown attribute field committed CLEAN; " +
			"the compiler dropped the expression so the validator never saw it (gate escape)")
	}
}

// --- FAIL-OPEN 2: event-options then change-configuration commands ----------

// TestEventChangeConfigCommands6659 covers both broken command spellings.
// The packed form compiled ZERO remediation commands. The unquoted BLOCK form
// truncated a command to its first word (`set`) because the arm read
// child.Name() — Keys[0] — instead of joining the child's Keys; that shape is
// not in the issue's table and was found by dumping the parsed AST.
func TestEventChangeConfigCommands6659(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  string
		want []string
	}{
		{
			"packed single quoted",
			`event-options { policy p1 { events e; then { change-configuration {
                commands "set system host-name foo";
            } } } }`,
			[]string{"set system host-name foo"},
		},
		{
			"packed bracket list",
			`event-options { policy p1 { events e; then { change-configuration {
                commands [ "set system host-name foo" "delete interfaces ge-0/0/0" ];
            } } } }`,
			[]string{"set system host-name foo", "delete interfaces ge-0/0/0"},
		},
		{
			"block unquoted (truncated to `set` pre-fix)",
			`event-options { policy p1 { events e; then { change-configuration { commands {
                set system host-name foo;
            } } } } }`,
			[]string{"set system host-name foo"},
		},
		{
			"block quoted (GREEN CONTROL — worked pre-fix)",
			`event-options { policy p1 { events e; then { change-configuration { commands {
                "set system host-name foo";
                "delete interfaces ge-0/0/0";
            } } } } }`,
			[]string{"set system host-name foo", "delete interfaces ge-0/0/0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, hierTree6659(t, tc.cfg))
			if got := cfg.EventOptions[0].ThenCommands; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ThenCommands = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- FAIL-OPEN 3: security flow traceoptions flag (GATE-ESCAPE) -------------

func TestFlowTraceFlags6659BothShapes(t *testing.T) {
	want := []string{"basic-datapath", "session"}
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"flat-set bracket", setTree6659(t,
			"set security flow traceoptions flag [ basic-datapath session ]")},
		{"hier block", hierTree6659(t, `
security { flow { traceoptions { flag { basic-datapath; session; } } } }`)},
		{"hier one-per-line (GREEN CONTROL)", hierTree6659(t, `
security { flow { traceoptions { flag basic-datapath; flag session; } } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			if cfg.Security.Flow.Traceoptions == nil {
				t.Fatal("no traceoptions compiled")
			}
			if got := cfg.Security.Flow.Traceoptions.Flags; !reflect.DeepEqual(got, want) {
				t.Fatalf("Flags = %q, want %q", got, want)
			}
		})
	}
}

// TestFlowTraceFlags6659UnknownFlagInAnySlotRejected is the GATE-ESCAPE half.
// validateFlowTraceFlagsStrict read the same nodeVal the compiler did, so an
// unknown flag anywhere but the FIRST slot committed clean. Both orderings must
// now be rejected; the first-slot case is the control that already worked.
func TestFlowTraceFlags6659UnknownFlagInAnySlotRejected(t *testing.T) {
	for _, tc := range []struct{ name, cmd string }{
		{"bogus in SECOND slot (the escape)",
			"set security flow traceoptions flag [ basic-datapath totally-bogus-flag ]"},
		{"bogus in THIRD slot",
			"set security flow traceoptions flag [ basic-datapath session totally-bogus-flag ]"},
		{"bogus in FIRST slot (control — already rejected)",
			"set security flow traceoptions flag [ totally-bogus-flag basic-datapath ]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(setTree6659(t, tc.cmd)); err == nil {
				t.Fatal("unknown flow trace flag committed CLEAN (gate escape)")
			}
		})
	}
}

// --- FAIL-OPEN 4: static NAT match destination-address (GATE-ESCAPE) --------

// TestStaticNATMatchAddresses6659MultiRejected pins that a multi-valued
// `match destination-address` is REJECTED rather than silently collapsing to the
// first prefix. Pre-#6659 nodeVal kept only the first, so the remaining prefixes
// were neither translated nor validated — a malformed prefix in slot 2 committed
// clean.
func TestStaticNATMatchAddresses6659MultiRejected(t *testing.T) {
	for _, tc := range []struct{ name, addrs string }{
		{"two well-formed prefixes", "[ 192.0.2.1/32 192.0.2.2/32 ]"},
		{"malformed prefix in SECOND slot (the escape)", "[ 192.0.2.1/32 not-an-address ]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(setTree6659(t,
				"set security nat static rule-set rs1 from zone untrust",
				"set security nat static rule-set rs1 rule r1 match destination-address "+tc.addrs,
				"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			))
			if err == nil {
				t.Fatal("multi-valued static-NAT match destination-address committed CLEAN; " +
					"only the first prefix would translate and the rest are silently ignored")
			}
		})
	}
}

// TestStaticNATMatchAddresses6659SingleUnchanged is the GREEN CONTROL: the
// ordinary single-prefix rule must compile exactly as before, with Match still
// carrying the prefix the dataplane snapshot lowers to.
func TestStaticNATMatchAddresses6659SingleUnchanged(t *testing.T) {
	cfg := mustCompile6659(t, setTree6659(t,
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
	))
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Match != "192.0.2.1/32" {
		t.Fatalf("Match = %q, want %q", rule.Match, "192.0.2.1/32")
	}
	if want := []string{"192.0.2.1/32"}; !reflect.DeepEqual(rule.MatchAddresses, want) {
		t.Fatalf("MatchAddresses = %q, want %q", rule.MatchAddresses, want)
	}
}

// --- FAIL-OPEN 5: routing-options forwarding-table export (GATE-ESCAPE) -----

// TestForwardingTableExport6659DanglingRefInAnySlot is the GATE-ESCAPE half and
// the sharpest case in this file: the reference gate exists precisely to stop a
// dangling export policy from silently disabling ECMP, and it read the same
// nodeVal the compiler did — so an undefined policy in slot 2 committed clean on
// exactly the scenario the gate's own error message describes.
func TestForwardingTableExport6659DanglingRefInAnySlot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		defined string
	}{
		{"p2 UNDEFINED (the escape)", "p1"},
		{"p1 UNDEFINED (control — already rejected)", "p2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(setTree6659(t,
				"set policy-options policy-statement "+tc.defined+" then accept",
				"set routing-options forwarding-table export [ p1 p2 ]",
			))
			if err == nil {
				t.Fatal("dangling forwarding-table export policy committed CLEAN (gate escape)")
			}
		})
	}
}

// TestForwardingTableExport6659MultiRejected pins that a multi-policy chain is
// rejected rather than silently collapsing: the FRR renderer honours exactly one
// export policy (resolveECMP), so the rest had no effect and nothing said so.
func TestForwardingTableExport6659MultiRejected(t *testing.T) {
	_, err := CompileConfig(setTree6659(t,
		"set policy-options policy-statement p1 then accept",
		"set policy-options policy-statement p2 then accept",
		"set routing-options forwarding-table export [ p1 p2 ]",
	))
	if err == nil {
		t.Fatal("multi-policy forwarding-table export committed CLEAN; only the first " +
			"policy renders, so the rest are silently ignored")
	}
}

// TestForwardingTableExport6659SingleUnchanged is the GREEN CONTROL: a single
// export policy still compiles and still lands in the scalar the FRR renderer
// reads, so ECMP rendering is untouched by this change.
func TestForwardingTableExport6659SingleUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"flat-set", setTree6659(t,
			"set policy-options policy-statement p1 then accept",
			"set routing-options forwarding-table export p1")},
		{"hier block", hierTree6659(t, `
policy-options { policy-statement p1 { then accept; } }
routing-options { forwarding-table { export p1; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			if got := cfg.RoutingOptions.ForwardingTableExport; got != "p1" {
				t.Fatalf("ForwardingTableExport = %q, want %q", got, "p1")
			}
			if want := []string{"p1"}; !reflect.DeepEqual(cfg.RoutingOptions.ForwardingTableExports, want) {
				t.Fatalf("ForwardingTableExports = %q, want %q", cfg.RoutingOptions.ForwardingTableExports, want)
			}
		})
	}
}

// --- proxy-ARP address list (value-drop, NOT a gate escape) -----------------

// TestProxyARPAddresses6659BothShapes pins the proxy-ARP list. This one is
// included here because the issue groups it with the high-severity sites, but it
// is a PURE VALUE-DROP, not a gate escape: proxy-ARP addresses carry no
// commit-time validator at all, so a malformed address in the FIRST slot commits
// clean too (asserted below so the distinction is recorded rather than assumed).
// The drop still matters — the firewall answered ARP for one address of the
// authored set and stayed silent for the rest.
func TestProxyARPAddresses6659BothShapes(t *testing.T) {
	want := []string{"192.0.2.1/32", "192.0.2.2/32"}
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"flat-set bracket", setTree6659(t,
			"set security nat proxy-arp interface ge-0/0/0 address [ 192.0.2.1 192.0.2.2 ]")},
		{"hier block", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address { 192.0.2.1; 192.0.2.2; } } } } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			if len(cfg.Security.NAT.ProxyARP) != 1 {
				t.Fatalf("expected 1 proxy-arp entry, got %d", len(cfg.Security.NAT.ProxyARP))
			}
			if got := cfg.Security.NAT.ProxyARP[0].Addresses; !reflect.DeepEqual(got, want) {
				t.Fatalf("Addresses = %q, want %q", got, want)
			}
		})
	}
}

// --- aliasing audit (carried forward from #6391) ----------------------------

// TestMultiValueLeaf6659NoSharedBackingStore is the #6391 aliasing hazard applied
// to every arm this PR touches.
//
// On #6391 a fan that stored ONE parsed *HostInboundTraffic under N map keys
// aliased a single value across all of them, because mergeHostInbound returns
// src unchanged when dst is nil — so a later in-place merge on one key surfaced
// on the others. That hazard needs two ingredients: a shared STRUCT POINTER, and
// a mutator that writes through it.
//
// None of the six accumulation targets here has either. Each is a []string
// (EventPolicy.AttributesMatch / ThenCommands, TraceOptions.Flags,
// ProxyARPEntry.Addresses, StaticNATRule.MatchAddresses,
// RoutingOptionsConfig.ForwardingTableExports) filled by spread-appending a
// FRESHLY RETURNED slice, so `append` copies the elements and the strings are
// immutable; and the two scalars (Match, ForwardingTableExport) are string copies
// of index 0, not slice aliases. That is a structural argument, so this test
// pins the observable consequence instead of restating it: sibling instances that
// each author their own values stay independent, with no value bleeding across.
func TestMultiValueLeaf6659NoSharedBackingStore(t *testing.T) {
	t.Run("two event policies stay independent", func(t *testing.T) {
		cfg := mustCompile6659(t, hierTree6659(t, `
event-options {
    policy pA { events e1; attributes-match e1.test-owner matches Comcast; }
    policy pB { events e2; attributes-match e2.test-name matches wan; }
}`))
		if len(cfg.EventOptions) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(cfg.EventOptions))
		}
		byName := map[string][]string{}
		for _, p := range cfg.EventOptions {
			byName[p.Name] = p.AttributesMatch
		}
		if want := []string{"e1.test-owner matches Comcast"}; !reflect.DeepEqual(byName["pA"], want) {
			t.Fatalf("pA AttributesMatch = %q, want %q", byName["pA"], want)
		}
		if want := []string{"e2.test-name matches wan"}; !reflect.DeepEqual(byName["pB"], want) {
			t.Fatalf("pB AttributesMatch = %q, want %q", byName["pB"], want)
		}
	})

	t.Run("two proxy-arp interfaces stay independent", func(t *testing.T) {
		cfg := mustCompile6659(t, setTree6659(t,
			"set security nat proxy-arp interface ge-0/0/0 address [ 192.0.2.1 192.0.2.2 ]",
			"set security nat proxy-arp interface ge-0/0/1 address [ 198.51.100.1 198.51.100.2 ]",
		))
		got := map[string][]string{}
		for _, p := range cfg.Security.NAT.ProxyARP {
			got[p.Interface] = p.Addresses
		}
		if want := []string{"192.0.2.1/32", "192.0.2.2/32"}; !reflect.DeepEqual(got["ge-0/0/0"], want) {
			t.Fatalf("ge-0/0/0 = %q, want %q", got["ge-0/0/0"], want)
		}
		if want := []string{"198.51.100.1/32", "198.51.100.2/32"}; !reflect.DeepEqual(got["ge-0/0/1"], want) {
			t.Fatalf("ge-0/0/1 = %q, want %q", got["ge-0/0/1"], want)
		}
		// Pointer independence of the backing arrays, the assertion that would
		// have caught the #6391 shape on day one (value equality would not).
		a, b := cfg.Security.NAT.ProxyARP[0].Addresses, cfg.Security.NAT.ProxyARP[1].Addresses
		if len(a) > 0 && len(b) > 0 && &a[0] == &b[0] {
			t.Fatal("two proxy-arp entries share the SAME Addresses backing array")
		}
	})

	t.Run("two static NAT rules stay independent", func(t *testing.T) {
		cfg := mustCompile6659(t, setTree6659(t,
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
			"set security nat static rule-set rs1 rule r2 match destination-address 192.0.2.9/32",
			"set security nat static rule-set rs1 rule r2 then static-nat prefix 10.0.0.9/32",
		))
		rules := cfg.Security.NAT.Static[0].Rules
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(rules))
		}
		for _, tc := range []struct{ name, addr string }{{"r1", "192.0.2.1/32"}, {"r2", "192.0.2.9/32"}} {
			for _, r := range rules {
				if r.Name != tc.name {
					continue
				}
				if r.Match != tc.addr || !reflect.DeepEqual(r.MatchAddresses, []string{tc.addr}) {
					t.Fatalf("%s: Match=%q MatchAddresses=%q, want %q",
						tc.name, r.Match, r.MatchAddresses, tc.addr)
				}
			}
		}
		if a, b := rules[0].MatchAddresses, rules[1].MatchAddresses; len(a) > 0 && len(b) > 0 && &a[0] == &b[0] {
			t.Fatal("two static NAT rules share the SAME MatchAddresses backing array")
		}
	})
}

// TestProxyARPAddresses6659RangeStillExpands is the GREEN CONTROL that the list
// reader did not break the `address <low> to <high>` range spellings, which are
// handled by earlier branches and must keep expanding.
func TestProxyARPAddresses6659RangeStillExpands(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"flat-set range", setTree6659(t,
			"set security nat proxy-arp interface ge-0/0/0 address 192.0.2.1 to 192.0.2.3")},
		{"hier range", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address 192.0.2.1 to 192.0.2.3; } } } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustCompile6659(t, tc.tree)
			got := cfg.Security.NAT.ProxyARP[0].Addresses
			want := []string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("range expansion = %q, want %q "+
					"(a bare list reader would emit the literal token \"to\" as an address)", got, want)
			}
		})
	}
}
