package config

import "testing"

// #5878 phase 2 — the canonical reference-key SSOT. CanonicalInterfaceUnitRef
// folds every accepted textual spelling of a `.<unit>` suffix onto one identity,
// and zoneIfaceLogicalKeys (the zone-membership conflict-detection SSOT that
// mirrors buildInterfaceZoneMap's binding) claims that canonical key so `.01` and
// `.1` are treated as the SAME logical unit.

func TestCanonicalInterfaceUnitRef5878(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ge-0/0/0.01", "ge-0/0/0.1"},          // leading zero
		{"ge-0/0/0.1", "ge-0/0/0.1"},           // already canonical
		{"ge-0/0/0.+1", "ge-0/0/0.1"},          // redundant sign
		{"ge-0/0/0.00", "ge-0/0/0.0"},          // zero alias
		{"ge-0/0/0.-0", "ge-0/0/0.0"},          // signed zero
		{"ge-0/0/0", "ge-0/0/0"},               // bare interface — unchanged
		{"ge-0/0/0.", "ge-0/0/0."},             // trailing dot (bare) — unchanged
		{"ge-0/0/0.tenant", "ge-0/0/0.tenant"}, // malformed suffix — unchanged (rejected at commit by #5933)
		{"ge-0/0/0.99999", "ge-0/0/0.99999"},   // out-of-range — unchanged
	}
	for _, c := range cases {
		if got := CanonicalInterfaceUnitRef(c.in); got != c.want {
			t.Errorf("CanonicalInterfaceUnitRef(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestZoneIfaceLogicalKeysCanonical5878 pins that a unit-qualified zone member's
// claimed logical key is the CANONICAL unit — the property that keeps the #3072
// membership conflict gate aligned with the now-canonical buildInterfaceZoneMap
// binder. On revert (raw suffix), the key is `ge-0/0/0.01` and this goes RED.
func TestZoneIfaceLogicalKeysCanonical5878(t *testing.T) {
	cfg := &Config{}
	keys := zoneIfaceLogicalKeys(cfg, "ge-0/0/0.01")
	if len(keys) != 1 || keys[0] != "ge-0/0/0.1" {
		t.Fatalf("zoneIfaceLogicalKeys(ge-0/0/0.01) = %v, want [ge-0/0/0.1]", keys)
	}
	// `.01` and `.1` must claim the SAME key (they are one unit).
	if a, b := zoneIfaceLogicalKeys(cfg, "ge-0/0/0.01"), zoneIfaceLogicalKeys(cfg, "ge-0/0/0.1"); a[0] != b[0] {
		t.Fatalf("zoneIfaceLogicalKeys: `.01` claims %q, `.1` claims %q — must be identical", a[0], b[0])
	}
}

// TestZoneMembershipConflictCanonical5878 is the security consequence: two zones
// claiming the SAME unit under two spellings (`.01` in one, `.1` in the other)
// must be rejected as a duplicate zone assignment — otherwise buildInterfaceZone
// Map binds one of them first-writer-wins and silently drops the other (the
// #3072 fail-open, reopened by phase-2 canonicalization if the detector is not
// aligned). On revert this config is silently accepted and the test goes RED.
func TestZoneMembershipConflictCanonical5878(t *testing.T) {
	cmds := []string{
		"set interfaces ge-0/0/0 unit 1 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.1",
		"set security zones security-zone untrust interfaces ge-0/0/0.01",
	}
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
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted ge-0/0/0.1 in trust and ge-0/0/0.01 in untrust " +
			"(same canonical unit in two zones) — want a duplicate-zone-membership reject")
	}
}
