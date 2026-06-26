package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestJunosHostPolicySnapshotCarriesRule is the Go-side #3019 guard. A
// `from-zone trust to-zone junos-host` security policy commits (the strict
// validator exempts the reserved `junos-host` self zone) and MUST reach the
// dataplane snapshot with its from/to zone NAME strings intact, so the Rust
// PolicyState::from_snapshots can resolve `junos-host` to the reserved
// JUNOS_HOST_ZONE_ID and INDEX the rule (the Go↔Rust agreement is on the
// reserved name string, not a wire zone id — `junos-host` is never put on the
// wire because zone ids are u8). Before #3019 the rule was accepted at commit
// but the snapshot/runtime never wired it to the LocalDelivery policy gate.
func TestJunosHostPolicySnapshotCarriesRule(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
		"set security policies from-zone trust to-zone junos-host policy deny-host match source-address any",
		"set security policies from-zone trust to-zone junos-host policy deny-host match destination-address any",
		"set security policies from-zone trust to-zone junos-host policy deny-host match application any",
		"set security policies from-zone trust to-zone junos-host policy deny-host then deny",
	}
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
		t.Fatalf("CompileConfig (junos-host policy must commit): %v", err)
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1, RingEntries: 2048}, 1, 1)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	var found *PolicyRuleSnapshot
	for i := range snap.Policies {
		if snap.Policies[i].ToZone == "junos-host" {
			found = &snap.Policies[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("policy snapshot must carry a to-zone junos-host rule; got %+v", snap.Policies)
	}
	if found.FromZone != "trust" {
		t.Fatalf("junos-host rule FromZone = %q, want %q", found.FromZone, "trust")
	}
	if found.ToZone != "junos-host" {
		t.Fatalf("junos-host rule ToZone = %q, want %q", found.ToZone, "junos-host")
	}
	if found.Action != "deny" {
		t.Fatalf("junos-host rule Action = %q, want %q", found.Action, "deny")
	}
	if found.Name != "deny-host" {
		t.Fatalf("junos-host rule Name = %q, want %q", found.Name, "deny-host")
	}
}
