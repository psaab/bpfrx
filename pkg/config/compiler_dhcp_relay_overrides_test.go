package config

import (
	"strings"
	"testing"
)

// #2076: `forwarding-options dhcp-relay group <g> overrides always-broadcast`
// must compile to DHCPRelayGroup.AlwaysBroadcast in BOTH AST shapes and must
// NOT be swallowed into the interface list by the inline flat-set consumer.
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

func relayGroup(t *testing.T, cfg *Config, name string) *DHCPRelayGroup {
	t.Helper()
	if cfg.ForwardingOptions.DHCPRelay == nil {
		t.Fatalf("DHCPRelay config nil")
	}
	g := cfg.ForwardingOptions.DHCPRelay.Groups[name]
	if g == nil {
		t.Fatalf("relay group %q not found", name)
	}
	return g
}

// TestDHCPRelayOverrides_FlatSet_NotSwallowed is the BLOCKER regression
// (Codex#2): the flat-set inline interface consumer must stop at `overrides`,
// not eat it (and `always-broadcast`) into the interface list.
func TestDHCPRelayOverrides_FlatSet_NotSwallowed(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
		"set forwarding-options dhcp-relay group lan overrides always-broadcast",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	g := relayGroup(t, cfg, "lan")

	if !g.AlwaysBroadcast {
		t.Errorf("AlwaysBroadcast = false, want true (flat-set overrides)")
	}
	// The interface list must be EXACTLY [ge-0/0/0.0] — no overrides/
	// always-broadcast swallowed in.
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("Interfaces = %v, want [ge-0/0/0.0] (swallow regression)", g.Interfaces)
	}
	for _, name := range g.Interfaces {
		if name == "overrides" || name == "always-broadcast" {
			t.Errorf("override token %q swallowed into Interfaces: %v", name, g.Interfaces)
		}
	}
}

// TestDHCPRelayOverrides_FlatSet_OverridesBeforeInterface guards the reverse
// token order: `overrides always-broadcast` appearing before `interface` must
// still set the flag and the boundary must keep interface parsing correct.
func TestDHCPRelayOverrides_FlatSet_OverridesBeforeInterface(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan overrides always-broadcast",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/1.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	g := relayGroup(t, cfg, "lan")
	if !g.AlwaysBroadcast {
		t.Errorf("AlwaysBroadcast = false, want true")
	}
	if len(g.Interfaces) != 2 {
		t.Errorf("Interfaces = %v, want 2 entries", g.Interfaces)
	}
	for _, name := range g.Interfaces {
		if name == "overrides" || name == "always-broadcast" {
			t.Errorf("override token %q swallowed into Interfaces: %v", name, g.Interfaces)
		}
	}
}

// TestDHCPRelayOverrides_Absent proves the flag defaults to false with no
// overrides stanza (the additive default).
func TestDHCPRelayOverrides_Absent(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	g := relayGroup(t, cfg, "lan")
	if g.AlwaysBroadcast {
		t.Errorf("AlwaysBroadcast = true, want false (absent override)")
	}
}

// TestDHCPRelayOverrides_MergedKeys_NotSwallowed is the #2115-item-2
// non-tautological guard for the #2076 boundary fix. The committed
// flat-set test above passes even with the boundary fix reverted,
// because ParseSetCommand+SetPath split the four `set` lines into
// per-property sub-nodes (so the inline-Keys[2:] consumer in
// compileDHCPRelay never sees `interface` and `overrides` packed in one
// node). The shape that actually triggers the swallow is the
// MERGED-Keys group node the parser produces when it flattens a
// single statement into one node:
//
//	Keys = [group <g> interface <if> overrides always-broadcast]
//
// Compiled by the inline Keys[2:] loop (compiler_services.go ~1106),
// the `interface` case (~1108) must STOP at the `overrides` boundary
// (~1117-1119) — otherwise it consumes `overrides` and
// `always-broadcast` into g.Interfaces and AlwaysBroadcast stays
// false. We build the merged-Keys node directly and drive
// compileDHCPRelay so the boundary keyword cannot silently regress.
//
// Non-tautology proof: with the `keys[i+1] != "overrides"` boundary
// removed from compiler_services.go (the #2076 fix), this test FAILS —
// AlwaysBroadcast is false and Interfaces becomes
// [ge-0/0/0.0 overrides always-broadcast]. Verified by reverting that
// boundary locally.
func TestDHCPRelayOverrides_MergedKeys_NotSwallowed(t *testing.T) {
	// Construct the `forwarding-options dhcp-relay` node directly with a
	// single merged-Keys `group` child. This is the packed shape the
	// parser emits when a whole statement collapses into one node; it is
	// NOT reproducible via ParseSetCommand+SetPath (which splits into
	// sub-nodes), which is exactly why the flat-set test above is
	// tautological for the boundary fix.
	relayNode := &Node{
		Keys: []string{"dhcp-relay"},
		Children: []*Node{
			{
				Keys:   []string{"server-group", "sg", "10.1.1.1"},
				IsLeaf: true,
			},
			{
				// The merged-Keys group node: interface value followed
				// immediately by the overrides boundary keyword and its
				// always-broadcast sub-keyword, all packed into Keys.
				Keys: []string{
					"group", "lan",
					"interface", "ge-0/0/0.0",
					"overrides", "always-broadcast",
				},
				IsLeaf: true,
			},
		},
	}

	fo := &ForwardingOptionsConfig{}
	if err := compileDHCPRelay(relayNode, fo); err != nil {
		t.Fatalf("compileDHCPRelay: %v", err)
	}
	if fo.DHCPRelay == nil {
		t.Fatalf("DHCPRelay config nil")
	}
	g := fo.DHCPRelay.Groups["lan"]
	if g == nil {
		t.Fatalf("relay group %q not found", "lan")
	}

	if !g.AlwaysBroadcast {
		t.Errorf("AlwaysBroadcast = false, want true (merged-Keys overrides swallowed)")
	}
	// The interface list must be EXACTLY [ge-0/0/0.0]. If the boundary
	// fix is reverted, the interface consumer eats overrides and
	// always-broadcast into this list.
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("Interfaces = %v, want [ge-0/0/0.0] (merged-Keys swallow regression)", g.Interfaces)
	}
	for _, name := range g.Interfaces {
		if name == "overrides" || name == "always-broadcast" {
			t.Errorf("override token %q swallowed into Interfaces: %v", name, g.Interfaces)
		}
	}
}

// TestDHCPRelayOverrides_MergedKeys_OverridesBeforeInterface guards the
// reverse merged-Keys token order: `overrides always-broadcast` packed
// before `interface` in one group node. The `overrides` case (~1128)
// must consume only its own sub-keyword and stop at the `interface`
// boundary, leaving a clean single-entry interface list.
func TestDHCPRelayOverrides_MergedKeys_OverridesBeforeInterface(t *testing.T) {
	relayNode := &Node{
		Keys: []string{"dhcp-relay"},
		Children: []*Node{
			{
				Keys:   []string{"server-group", "sg", "10.1.1.1"},
				IsLeaf: true,
			},
			{
				Keys: []string{
					"group", "lan",
					"overrides", "always-broadcast",
					"interface", "ge-0/0/0.0",
				},
				IsLeaf: true,
			},
		},
	}

	fo := &ForwardingOptionsConfig{}
	if err := compileDHCPRelay(relayNode, fo); err != nil {
		t.Fatalf("compileDHCPRelay: %v", err)
	}
	g := fo.DHCPRelay.Groups["lan"]
	if g == nil {
		t.Fatalf("relay group %q not found", "lan")
	}
	if !g.AlwaysBroadcast {
		t.Errorf("AlwaysBroadcast = false, want true (merged-Keys overrides-first)")
	}
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("Interfaces = %v, want [ge-0/0/0.0]", g.Interfaces)
	}
	for _, name := range g.Interfaces {
		if name == "overrides" || name == "always-broadcast" {
			t.Errorf("override token %q swallowed into Interfaces: %v", name, g.Interfaces)
		}
	}
}

// TestDHCPRelayOverrides_SchemaCompletion proves the structural completion
// offers `always-broadcast` under `overrides`.
func TestDHCPRelayOverrides_SchemaCompletion(t *testing.T) {
	comps := CompleteSetPath([]string{
		"forwarding-options", "dhcp-relay", "group", "lan", "overrides", "",
	})
	found := false
	for _, c := range comps {
		if c == "always-broadcast" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("overrides completion missing always-broadcast; got %v", comps)
	}
}

// #4309 (fable-review-167 I-4): the additional relay overrides
// (maximum-hop-count / forward-only / relay-agent-option) must compile from
// the flat-set path. RED-on-revert: without the compiler cases each field
// reads back its zero value (silent drop).
func TestDHCPRelayOverrides_4309_FlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
		"set forwarding-options dhcp-relay group lan overrides maximum-hop-count 4",
		"set forwarding-options dhcp-relay group lan overrides forward-only",
		"set forwarding-options dhcp-relay group lan overrides relay-agent-option",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	g := relayGroup(t, cfg, "lan")
	if g.MaximumHopCount != 4 {
		t.Errorf("MaximumHopCount = %d, want 4", g.MaximumHopCount)
	}
	if !g.ForwardOnly {
		t.Error("ForwardOnly = false, want true")
	}
	if !g.RelayAgentOption {
		t.Error("RelayAgentOption = false, want true")
	}
	// The interface list must stay clean — the new override keywords/value
	// must not be swallowed into it.
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("Interfaces = %v, want [ge-0/0/0.0]", g.Interfaces)
	}
}

// Merged-Keys shape: `maximum-hop-count 4` packed inline with a value token in
// one group node exercises the inline-Keys override loop's value consumption
// (the loop must advance past the value, not treat "4" as an override keyword).
func TestDHCPRelayOverrides_4309_MergedKeysHopCountValue(t *testing.T) {
	relayNode := &Node{
		Keys: []string{"dhcp-relay"},
		Children: []*Node{
			{Keys: []string{"server-group", "sg", "10.1.1.1"}, IsLeaf: true},
			{
				Keys: []string{
					"group", "lan",
					"overrides", "maximum-hop-count", "4",
					"interface", "ge-0/0/0.0",
				},
				IsLeaf: true,
			},
		},
	}
	fo := &ForwardingOptionsConfig{}
	if err := compileDHCPRelay(relayNode, fo); err != nil {
		t.Fatalf("compileDHCPRelay: %v", err)
	}
	g := fo.DHCPRelay.Groups["lan"]
	if g == nil {
		t.Fatal("relay group lan not found")
	}
	if g.MaximumHopCount != 4 {
		t.Errorf("MaximumHopCount = %d, want 4 (merged-Keys value)", g.MaximumHopCount)
	}
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("Interfaces = %v, want [ge-0/0/0.0] (hop-count value swallowed?)", g.Interfaces)
	}
}

// Block form: `overrides { maximum-hop-count 4; forward-only; }` as child
// nodes exercises the children-based override loop.
func TestDHCPRelayOverrides_4309_BlockForm(t *testing.T) {
	relayNode := &Node{
		Keys: []string{"dhcp-relay"},
		Children: []*Node{
			{Keys: []string{"server-group", "sg", "10.1.1.1"}, IsLeaf: true},
			{
				Keys: []string{"group", "lan"},
				Children: []*Node{
					{Keys: []string{"interface", "ge-0/0/0.0"}, IsLeaf: true},
					{Keys: []string{"overrides"}, Children: []*Node{
						{Keys: []string{"maximum-hop-count", "4"}, IsLeaf: true},
						{Keys: []string{"forward-only"}, IsLeaf: true},
						{Keys: []string{"relay-agent-option"}, IsLeaf: true},
					}},
				},
			},
		},
	}
	fo := &ForwardingOptionsConfig{}
	if err := compileDHCPRelay(relayNode, fo); err != nil {
		t.Fatalf("compileDHCPRelay: %v", err)
	}
	g := fo.DHCPRelay.Groups["lan"]
	if g == nil {
		t.Fatal("relay group lan not found")
	}
	if g.MaximumHopCount != 4 {
		t.Errorf("MaximumHopCount = %d, want 4 (block form)", g.MaximumHopCount)
	}
	if !g.ForwardOnly {
		t.Error("ForwardOnly = false, want true (block form)")
	}
	if !g.RelayAgentOption {
		t.Error("RelayAgentOption = false, want true (block form)")
	}
}

// forward-only / relay-agent-option must surface an accepted-only advisory;
// maximum-hop-count is enforced and must NOT (it is a real behavior, not a
// no-op).
func TestDHCPRelayOverrides_4309_Advisory(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
		"set forwarding-options dhcp-relay group lan overrides forward-only",
		"set forwarding-options dhcp-relay group lan overrides relay-agent-option",
		"set forwarding-options dhcp-relay group lan overrides maximum-hop-count 4",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var warn string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#4309") && strings.Contains(w, "lan") {
			warn = w
		}
	}
	if warn == "" {
		t.Fatalf("expected a #4309 accepted-only advisory for group lan, got: %v", ValidateConfig(cfg))
	}
	if !strings.Contains(warn, "forward-only") || !strings.Contains(warn, "relay-agent-option") {
		t.Errorf("advisory missing an accepted-only knob: %s", warn)
	}
	// maximum-hop-count is enforced — it must not appear in the accepted-only
	// advisory.
	if strings.Contains(warn, "maximum-hop-count") {
		t.Errorf("maximum-hop-count is enforced and must not be in the accepted-only advisory: %s", warn)
	}
}

// #5414 (RFC 3046 §2.1 anti-spoofing): `overrides trust-option-82` marks the
// group's interfaces as trusted relay uplinks and must compile to
// DHCPRelayGroup.TrustOption82 from the flat-set path. RED-on-revert: without
// the compiler case the field reads back false (silent drop) and the relay
// keeps trusting a client-forged giaddr.
func TestDHCPRelayOverrides_5414_TrustOption82_FlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
		"set forwarding-options dhcp-relay group lan overrides trust-option-82",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	g := relayGroup(t, cfg, "lan")
	if !g.TrustOption82 {
		t.Error("TrustOption82 = false, want true (flat-set overrides trust-option-82)")
	}
	// The interface list must stay clean — the new keyword must not be swallowed.
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("Interfaces = %v, want [ge-0/0/0.0]", g.Interfaces)
	}
}

// Default: absent trust-option-82 leaves the group UNTRUSTED (the safe default
// that overwrites a client-forged giaddr).
func TestDHCPRelayOverrides_5414_TrustOption82_DefaultUntrusted(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if g := relayGroup(t, cfg, "lan"); g.TrustOption82 {
		t.Error("TrustOption82 = true, want false (absent override → untrusted default)")
	}
}

// Merged-Keys and block forms of trust-option-82 must also compile — the same
// three parse shapes #4309 covers for its knobs.
func TestDHCPRelayOverrides_5414_TrustOption82_MergedAndBlock(t *testing.T) {
	// Merged-Keys: trust-option-82 packed inline with interface in one node.
	merged := &Node{
		Keys: []string{"dhcp-relay"},
		Children: []*Node{
			{Keys: []string{"server-group", "sg", "10.1.1.1"}, IsLeaf: true},
			{
				Keys: []string{
					"group", "lan",
					"overrides", "trust-option-82",
					"interface", "ge-0/0/0.0",
				},
				IsLeaf: true,
			},
		},
	}
	fo := &ForwardingOptionsConfig{}
	if err := compileDHCPRelay(merged, fo); err != nil {
		t.Fatalf("compileDHCPRelay (merged): %v", err)
	}
	if g := fo.DHCPRelay.Groups["lan"]; g == nil || !g.TrustOption82 {
		t.Errorf("merged-Keys TrustOption82 not set: %+v", g)
	} else if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("merged-Keys Interfaces = %v, want [ge-0/0/0.0] (trust-option-82 swallowed?)", g.Interfaces)
	}

	// Block form: overrides { trust-option-82; } as a child node.
	block := &Node{
		Keys: []string{"dhcp-relay"},
		Children: []*Node{
			{Keys: []string{"server-group", "sg", "10.1.1.1"}, IsLeaf: true},
			{
				Keys: []string{"group", "lan"},
				Children: []*Node{
					{Keys: []string{"interface", "ge-0/0/0.0"}, IsLeaf: true},
					{Keys: []string{"overrides"}, Children: []*Node{
						{Keys: []string{"trust-option-82"}, IsLeaf: true},
					}},
				},
			},
		},
	}
	fo2 := &ForwardingOptionsConfig{}
	if err := compileDHCPRelay(block, fo2); err != nil {
		t.Fatalf("compileDHCPRelay (block): %v", err)
	}
	if g := fo2.DHCPRelay.Groups["lan"]; g == nil || !g.TrustOption82 {
		t.Errorf("block-form TrustOption82 not set: %+v", g)
	}
}

// Structural completion must offer trust-option-82 under overrides so an
// operator can discover the knob via `?`.
func TestDHCPRelayOverrides_5414_SchemaCompletion(t *testing.T) {
	comps := CompleteSetPath([]string{
		"forwarding-options", "dhcp-relay", "group", "lan", "overrides", "",
	})
	found := false
	for _, c := range comps {
		if c == "trust-option-82" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("overrides completion missing trust-option-82; got %v", comps)
	}
}

// #5670: `overrides maximum-packet-rate <pps>` is the per-interface DHCP relay
// ingress rate limit and must compile from the flat-set path to
// DHCPRelayGroup.MaximumPacketRate. RED-on-revert: without the compiler case
// the field reads back its zero value (silent drop) and the relay runs
// unbounded on that segment.
func TestDHCPRelayOverrides_5670_PacketRate_FlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
		"set forwarding-options dhcp-relay group lan overrides maximum-packet-rate 250",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	g := relayGroup(t, cfg, "lan")
	if g.MaximumPacketRate != 250 {
		t.Errorf("MaximumPacketRate = %d, want 250 (flat-set overrides)", g.MaximumPacketRate)
	}
	// The interface list must stay clean — the value token must not be swallowed.
	if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("Interfaces = %v, want [ge-0/0/0.0] (packet-rate value swallowed?)", g.Interfaces)
	}
}

// Default: absent maximum-packet-rate leaves the field 0 (the compiler's
// unset), which relay.go resolves to the 100 pps default.
func TestDHCPRelayOverrides_5670_PacketRate_DefaultUnset(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if g := relayGroup(t, cfg, "lan"); g.MaximumPacketRate != 0 {
		t.Errorf("MaximumPacketRate = %d, want 0 (absent override → resolver default)", g.MaximumPacketRate)
	}
}

// Merged-Keys and block forms of maximum-packet-rate must also compile — the
// same three parse shapes #4309/#5414 cover. The merged-Keys shape exercises
// the inline override loop's value consumption (the loop must advance past the
// value token, not treat "250" as an override keyword).
func TestDHCPRelayOverrides_5670_PacketRate_MergedAndBlock(t *testing.T) {
	merged := &Node{
		Keys: []string{"dhcp-relay"},
		Children: []*Node{
			{Keys: []string{"server-group", "sg", "10.1.1.1"}, IsLeaf: true},
			{
				Keys: []string{
					"group", "lan",
					"overrides", "maximum-packet-rate", "250",
					"interface", "ge-0/0/0.0",
				},
				IsLeaf: true,
			},
		},
	}
	fo := &ForwardingOptionsConfig{}
	if err := compileDHCPRelay(merged, fo); err != nil {
		t.Fatalf("compileDHCPRelay (merged): %v", err)
	}
	if g := fo.DHCPRelay.Groups["lan"]; g == nil || g.MaximumPacketRate != 250 {
		t.Errorf("merged-Keys MaximumPacketRate not 250: %+v", g)
	} else if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("merged-Keys Interfaces = %v, want [ge-0/0/0.0] (packet-rate value swallowed?)", g.Interfaces)
	}

	block := &Node{
		Keys: []string{"dhcp-relay"},
		Children: []*Node{
			{Keys: []string{"server-group", "sg", "10.1.1.1"}, IsLeaf: true},
			{
				Keys: []string{"group", "lan"},
				Children: []*Node{
					{Keys: []string{"interface", "ge-0/0/0.0"}, IsLeaf: true},
					{Keys: []string{"overrides"}, Children: []*Node{
						{Keys: []string{"maximum-packet-rate", "250"}, IsLeaf: true},
					}},
				},
			},
		},
	}
	fo2 := &ForwardingOptionsConfig{}
	if err := compileDHCPRelay(block, fo2); err != nil {
		t.Fatalf("compileDHCPRelay (block): %v", err)
	}
	if g := fo2.DHCPRelay.Groups["lan"]; g == nil || g.MaximumPacketRate != 250 {
		t.Errorf("block-form MaximumPacketRate not 250: %+v", g)
	}
}

// Structural completion must offer maximum-packet-rate under overrides so an
// operator can discover the knob via `?`.
func TestDHCPRelayOverrides_5670_SchemaCompletion(t *testing.T) {
	comps := CompleteSetPath([]string{
		"forwarding-options", "dhcp-relay", "group", "lan", "overrides", "",
	})
	found := false
	for _, c := range comps {
		if c == "maximum-packet-rate" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("overrides completion missing maximum-packet-rate; got %v", comps)
	}
}
