package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722: pin the two Go-side facts the Rust egress-zone resolver's design rests
// on. `ForwardingState::egress_zone_id` (userspace-dp/src/afxdp/types/forwarding.rs)
// falls back to `ifindex_to_zone_id` for an interface with no `egress` row — a
// MAC-less xfrmi — and the userspace-dp fixtures that exercise that path
// (`sibling_tunnel_units_snapshot_6722`, `secure_tunnel_snapshot_6713` in
// userspace-dp/src/afxdp/forwarding/tests.rs) hand-build ConfigSnapshot rows.
// A hand-built row can model a snapshot this builder never emits, and a fixture
// the builder cannot produce is not evidence — that is exactly how #6722's
// first two rounds went wrong.
//
// The two facts:
//
//  1. A unit-suffixed zone reference zones the BASE interface too
//     (buildInterfaceZoneMap). Zoning st0.1 zones st0.
//  2. A non-VLAN unit 0 COLLAPSES onto the base netdev (snapshotLinuxName), so
//     the base row and the unit-0 row carry ONE ifindex.
//
// Together they mean a MAC-less unit 0 sharing a base ifindex with a zoned
// sibling adjudicates under that zone — the behaviour #6722 documents. They
// also mean the Rust child→parent zone propagation in `populate_interfaces` is
// unreachable for a snapshot produced here: a zoned unit's parent row always
// arrives already carrying a zone of its own.
//
// FAIL-ON-REVERT: drop the `out[base] = zoneName` write in
// buildInterfaceZoneMap (zones.go) — a plausible move toward Junos per-unit
// zoning — and case A goes RED on the base row's zone. That is the signal to
// revisit the Rust-side reasoning, not to re-point this test.

func buildSnapshotsFromSet6722(t *testing.T, lines []string, ifindexOf map[string]int, macOf map[string]string) (map[string]string, []InterfaceSnapshot) {
	t.Helper()
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		idx, ok := ifindexOf[linuxName]
		if !ok {
			return 0, 0, "", nil
		}
		return idx, 1500, macOf[linuxName], nil
	}

	tree := &config.ConfigTree{}
	for _, cmd := range lines {
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
	return buildInterfaceZoneMap(cfg), buildInterfaceSnapshots(cfg)
}

func snapByName6722(t *testing.T, snaps []InterfaceSnapshot, name string) InterfaceSnapshot {
	t.Helper()
	for _, s := range snaps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no interface snapshot named %q (have %d rows)", name, len(snaps))
	return InterfaceSnapshot{}
}

// A: two secure tunnels on one st0, zone on st0.1 only. Mirrors
// `sibling_tunnel_units_snapshot_6722`.
func TestSiblingTunnelUnitsZoneTheBaseRow_6722(t *testing.T) {
	zoneByIface, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone vpnb interfaces st0.1",
	}, map[string]int{"ge-0-0-1": 24, "st0": 42, "st0.1": 43},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	if got := zoneByIface["st0"]; got != "vpnb" {
		t.Fatalf("buildInterfaceZoneMap[st0] = %q, want %q: a unit-suffixed zone "+
			"reference must zone the base interface too", got, "vpnb")
	}

	base := snapByName6722(t, snaps, "st0")
	unit0 := snapByName6722(t, snaps, "st0.0")
	unit1 := snapByName6722(t, snaps, "st0.1")

	if base.Zone != "vpnb" {
		t.Errorf("st0 base row Zone = %q, want %q: the userspace-dp fixture models "+
			"this row as zoned, and a MAC-less unit 0 sharing its ifindex resolves "+
			"its zone", base.Zone, "vpnb")
	}
	if unit0.Ifindex != base.Ifindex {
		t.Errorf("st0.0 ifindex %d != st0 base ifindex %d: a non-VLAN unit 0 must "+
			"collapse onto the base netdev", unit0.Ifindex, base.Ifindex)
	}
	if unit0.Zone != "" {
		t.Errorf("st0.0 Zone = %q, want empty: the operator referenced only st0.1, "+
			"so unit 0 gets no direct entry", unit0.Zone)
	}
	if unit1.Ifindex == base.Ifindex {
		t.Errorf("st0.1 ifindex %d must NOT collapse onto the base (%d): "+
			"bind-interface st0.1 is its own xfrmi netdev", unit1.Ifindex, base.Ifindex)
	}
	if unit1.Zone != "vpnb" {
		t.Errorf("st0.1 Zone = %q, want %q", unit1.Zone, "vpnb")
	}
	if base.HardwareAddr != "" || unit0.HardwareAddr != "" || unit1.HardwareAddr != "" {
		t.Errorf("the xfrmi rows must be MAC-less (ARPHRD_NONE) — that is what denies "+
			"them a populate_egress row and makes the #6713 fallback the only "+
			"resolver: base=%q unit0=%q unit1=%q",
			base.HardwareAddr, unit0.HardwareAddr, unit1.HardwareAddr)
	}
}

// B: a zoned trunk with a declared-but-unzoned unit 0. Mirrors the scoping
// control in `secure_tunnel_snapshot_6713` — the shape that makes
// `egress_zone_id`'s `Some(0)` short-circuit load-bearing, because both rows on
// the shared ifindex are MAC-ful and populate_egress is last-write-wins.
func TestZonedTrunkEmitsUnzonedUnit0OnTheSharedIfindex_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set firewall family inet filter guard term t1 then accept",
		"set interfaces ge-0/0/9 unit 0 family inet filter input guard",
		"set interfaces ge-0/0/9 unit 100 vlan-id 100 family inet address 10.100.9.1/24",
		"set security zones security-zone lan interfaces ge-0/0/9.100",
	}, map[string]int{"ge-0-0-9": 90, "ge-0-0-9.100": 91},
		map[string]string{"ge-0-0-9": "02:bf:72:09:00:00", "ge-0-0-9.100": "02:bf:72:09:00:00"})

	base := snapByName6722(t, snaps, "ge-0/0/9")
	unit0 := snapByName6722(t, snaps, "ge-0/0/9.0")
	unit100 := snapByName6722(t, snaps, "ge-0/0/9.100")

	if base.Zone != "lan" {
		t.Errorf("ge-0/0/9 base row Zone = %q, want %q: the VLAN unit's zone "+
			"reference zones the base", base.Zone, "lan")
	}
	if unit0.Zone != "" {
		t.Errorf("ge-0/0/9.0 Zone = %q, want empty", unit0.Zone)
	}
	if unit0.Ifindex != base.Ifindex {
		t.Errorf("ge-0/0/9.0 ifindex %d != base %d: unit 0 must collapse onto the "+
			"base netdev, which is what makes populate_egress overwrite the base "+
			"row's zone_id with 0", unit0.Ifindex, base.Ifindex)
	}
	if base.HardwareAddr == "" || unit0.HardwareAddr == "" {
		t.Errorf("both rows on the shared ifindex must be MAC-ful so BOTH reach "+
			"populate_egress: base=%q unit0=%q", base.HardwareAddr, unit0.HardwareAddr)
	}
	if unit100.Ifindex == base.Ifindex {
		t.Errorf("the tagged unit must have its own ifindex, got %d == base %d",
			unit100.Ifindex, base.Ifindex)
	}
	if unit100.Zone != "lan" {
		t.Errorf("ge-0/0/9.100 Zone = %q, want %q", unit100.Zone, "lan")
	}

	// The ordering populate_egress depends on: the base row is emitted BEFORE
	// its unit rows, so the unzoned unit-0 row is the last write on ifindex 90.
	baseIdx, unit0Idx := -1, -1
	for i, s := range snaps {
		switch s.Name {
		case "ge-0/0/9":
			baseIdx = i
		case "ge-0/0/9.0":
			unit0Idx = i
		}
	}
	if !(baseIdx >= 0 && unit0Idx > baseIdx) {
		t.Errorf("emission order base=%d unit0=%d: the unit-0 row must follow its "+
			"base row for populate_egress's last-write-wins to leave zone_id 0 on "+
			"the shared ifindex", baseIdx, unit0Idx)
	}
}
