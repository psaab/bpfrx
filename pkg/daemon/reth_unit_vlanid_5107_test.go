package daemon

import (
	"io"
	"log/slog"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildRAConfigsRethUnitVlanIDMismatch is the #5107 bug-1 guard: RA
// interface resolution must map a RETH logical unit to its configured vlan-id
// for the kernel VLAN sub-interface suffix, not preserve the unit number.
//
// reth0 unit 80 carries `vlan-id 180`, so the kernel sub-interface is
// member.180. The old resolution (LinuxIfName(ResolveReth(...))) kept the unit
// suffix and bound RA to member.80, a netdev that does not exist. This also
// desynced buildRAConfigs from rethInterfacesForRG (which already suffixes by
// unit.VlanID), silently dropping the sender from the cluster RA owned set.
//
// Fail-on-revert: restoring `config.LinuxIfName(cfg.ResolveReth(ra.Interface))`
// in buildRAConfigs resolves reth0.80 to "ge-0-0-0.80" — the expected
// "ge-0-0-0.180" is absent and the forbidden "ge-0-0-0.80" appears, failing
// both assertions.
func TestBuildRAConfigsRethUnitVlanIDMismatch(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{NodeID: 0, ClusterID: 1}},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						// unit == vlan-id (common case, must still work).
						50: {Number: 50, VlanID: 50, Addresses: []string{
							"172.16.50.8/24", "2001:db8:50::8/64"}},
						// unit != vlan-id (the #5107 failure case).
						80: {Number: 80, VlanID: 180, Addresses: []string{
							"172.16.80.8/24", "2001:db8:80::8/64"}},
					},
				},
				// Node 0's local member is ge-0/0/0 (slot 0 -> node 0).
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-7/0/0": {Name: "ge-7/0/0", RedundantParent: "reth0"},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{
				{Interface: "reth0.80"},
				{Interface: "reth0.50"},
			},
		},
	}

	resolved := make(map[string]bool)
	for _, ra := range d.buildRAConfigs(cfg) {
		resolved[ra.Interface] = true
	}

	if !resolved["ge-0-0-0.180"] {
		t.Errorf("RA on reth0.80 (vlan-id 180) resolved to %v; want the set to "+
			"include ge-0-0-0.180 (vlan-id), not the unit suffix", keys(resolved))
	}
	if resolved["ge-0-0-0.80"] {
		t.Errorf("RA resolved to ge-0-0-0.80 (unit number) — unit# was used as "+
			"the kernel VLAN suffix instead of vlan-id 180 (#5107); got %v", keys(resolved))
	}
	// Same-value unit (50 == vlan-id 50): no regression.
	if !resolved["ge-0-0-0.50"] {
		t.Errorf("RA on reth0.50 (vlan-id 50) resolved to %v; want ge-0-0-0.50",
			keys(resolved))
	}
}

// TestRethUnitForVlanID exercises the vlan-id -> unit reverse lookup that the
// post-MAC IPv6 link-local repair uses to translate a kernel VLAN suffix back
// to the logical unit rethCfg.Units is keyed by (#5107 bug 2).
func TestRethUnitForVlanID(t *testing.T) {
	cfg := &config.InterfaceConfig{
		Name:            "reth0",
		RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0, VlanID: 0, Addresses: []string{"fe80::aaaa/64"}},
			50: {Number: 50, VlanID: 50},
			80: {Number: 80, VlanID: 180}, // unit != vlan-id
			90: {Number: 90, VlanID: 190},
		},
	}

	tests := []struct {
		name     string
		vid      int
		wantUnit int
		wantOK   bool
	}{
		{"mismatch: vlan-id 180 -> unit 80", 180, 80, true},
		{"same-value: vlan-id 50 -> unit 50", 50, 50, true},
		{"another mismatch: vlan-id 190 -> unit 90", 190, 90, true},
		// 80 is a UNIT number, not any unit's vlan-id: must NOT resolve.
		// The old direct Units[80] index would have matched here.
		{"unit-number-not-vlan-id: 80 -> miss", 80, 0, false},
		{"unknown vlan-id: miss", 999, 0, false},
		// vlan-id 0 is the untagged parent, not a VLAN sub-interface: miss.
		{"untagged vlan-id 0: miss", 0, 0, false},
	}
	for _, tt := range tests {
		gotUnit, gotOK := rethUnitForVlanID(cfg, tt.vid)
		if gotUnit != tt.wantUnit || gotOK != tt.wantOK {
			t.Errorf("%s: rethUnitForVlanID(vid=%d) = (%d, %v), want (%d, %v)",
				tt.name, tt.vid, gotUnit, gotOK, tt.wantUnit, tt.wantOK)
		}
	}
}

// TestRethUnitForVlanIDDuplicateDeterministic proves a duplicate vlan-id (an
// invalid config) resolves deterministically to the lowest unit number
// regardless of map iteration order.
func TestRethUnitForVlanIDDuplicateDeterministic(t *testing.T) {
	cfg := &config.InterfaceConfig{
		Name: "reth1",
		Units: map[int]*config.InterfaceUnit{
			70: {Number: 70, VlanID: 200, Addresses: []string{"2001:db8:70::1/64"}},
			90: {Number: 90, VlanID: 200, Addresses: []string{"2001:db8:90::1/64"}},
		},
	}
	// Silence the expected duplicate-vlan-id WARN across the loop.
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(prev)

	// Repeat to defeat Go's randomized map iteration order.
	for i := 0; i < 64; i++ {
		gotUnit, gotOK := rethUnitForVlanID(cfg, 200)
		if !gotOK || gotUnit != 70 {
			t.Fatalf("duplicate vlan-id 200: rethUnitForVlanID = (%d, %v), "+
				"want (70, true) deterministically (lowest unit)", gotUnit, gotOK)
		}
	}
}

// TestRethSubIfaceNeedsLinkLocal is the #5107 bug-2 fail-on-revert guard for
// the post-MAC IPv6 repair decision. The kernel VLAN suffix (vlan-id) must be
// translated to its logical unit before checking Units for IPv6.
//
// Fail-on-revert: replacing rethSubIfaceNeedsLinkLocal's body with the old
// `return rethUnitHasIPv6(rethCfg, vid)` indexes Units[180], which is absent
// (Units is keyed by unit 80), so the IPv6-bearing sub-interface is skipped and
// the vlan-id-180 assertion flips to false.
func TestRethSubIfaceNeedsLinkLocal(t *testing.T) {
	cfg := &config.InterfaceConfig{
		Name:            "reth0",
		RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VlanID: 0, Addresses: []string{"fe80::aaaa/64"}},
			// unit == vlan-id, has IPv6.
			50: {Number: 50, VlanID: 50, Addresses: []string{
				"172.16.50.8/24", "2001:db8:50::8/64"}},
			// unit != vlan-id, has IPv6 (the #5107 failure case).
			80: {Number: 80, VlanID: 180, Addresses: []string{
				"172.16.80.8/24", "2001:db8:80::8/64"}},
			// VLAN sub-interface present but IPv4-only: no link-local needed.
			90: {Number: 90, VlanID: 190, Addresses: []string{"172.16.90.8/24"}},
			// DHCPv6 counts as IPv6.
			100: {Number: 100, VlanID: 200, DHCPv6: true},
		},
	}

	tests := []struct {
		name string
		vid  int
		want bool
	}{
		{"mismatch unit 80 vlan-id 180 with IPv6", 180, true},
		{"same-value unit 50 vlan-id 50 with IPv6", 50, true},
		{"IPv4-only sub-interface vlan-id 190", 190, false},
		{"DHCPv6 sub-interface vlan-id 200", 200, true},
		// vid 80 is a unit number, not a vlan-id: no matching sub-interface.
		{"unit-number 80 is not a vlan-id", 80, false},
		{"unknown vlan-id", 999, false},
	}
	for _, tt := range tests {
		if got := rethSubIfaceNeedsLinkLocal(cfg, tt.vid); got != tt.want {
			t.Errorf("%s: rethSubIfaceNeedsLinkLocal(vid=%d) = %v, want %v",
				tt.name, tt.vid, got, tt.want)
		}
	}
}

// keys returns the set's members for error messages.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
