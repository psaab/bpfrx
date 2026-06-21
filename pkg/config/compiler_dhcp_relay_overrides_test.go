package config

import (
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
