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
