package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileFromSet compiles a config from flat `set` commands using the
// ParseSetCommand + SetPath loop (NewParser must not be used for set syntax —
// see CLAUDE.md "Testing flat set syntax").
func compileFromSet(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestScopedGlobalResolvesZoneLocalAddress pins the #3287 fix: a scoped global
// policy (#3148, `match from-zone <z>`) must resolve a zone-local address
// reference (#3061) against that zone's local book — the same zone-qualified
// resolution the compiler already does for zone-pair policies. Before the fix
// resolveZoneLocalAddressBooks rewrote zone-pair tokens only, so the scoped
// global kept the bare token, the global book held the entry only under its
// zone-qualified name, the constraint resolved to match-none, and legitimate
// zone-scoped global traffic silently fell through to default-deny.
func TestScopedGlobalResolvesZoneLocalAddress(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust address-book address LOCALNET 10.0.1.0/24",
		// #3355: the egress zone must be a DEFINED zone — a real flow's to-zone
		// is always derived from a configured zone. Define untrust so the
		// defined-zone transit guard does not (correctly) route an undefined
		// egress zone to the default-policy.
		"set security zones security-zone untrust",
		"set security policies global policy allow-local match source-address LOCALNET",
		"set security policies global policy allow-local match destination-address any",
		"set security policies global policy allow-local match application any",
		"set security policies global policy allow-local match from-zone trust",
		"set security policies global policy allow-local then permit",
		"set security policies default-policy deny-all",
	}
	cfg := compileFromSet(t, cmds)

	// A trust-sourced packet inside LOCALNET must match the scoped global and be
	// permitted. With the bug the source constraint resolved to match-none, so
	// the verdict was the default deny.
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"),
	})
	if !res.Matched || !res.Global {
		t.Fatalf("expected scoped-global match, got Matched=%v Global=%v action=%v",
			res.Matched, res.Global, res.Action)
	}
	if res.PolicyName != "allow-local" {
		t.Errorf("PolicyName = %q, want allow-local", res.PolicyName)
	}
	if res.Action != config.PolicyPermit {
		t.Errorf("Action = %v, want permit", res.Action)
	}

	// A source OUTSIDE LOCALNET must NOT match the global (the constraint is
	// real, not match-any) — falls through to default deny.
	res2 := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.9.9.9"),
	})
	if res2.Matched {
		t.Errorf("expected default (no match) for out-of-LOCALNET source, got policy %q", res2.PolicyName)
	}
	if res2.Action != config.PolicyDeny {
		t.Errorf("out-of-LOCALNET Action = %v, want deny", res2.Action)
	}
}
