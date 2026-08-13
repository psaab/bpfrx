package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722 B2, the GO half. The Rust agreement ledger
// (`userspace-dp/src/afxdp/forwarding_build/interfaces.rs`) exempts a row that
// carries `redundant_parent` AND no zone of its own from voting on its
// ifindex's zone, because a RETH's physical member is a PROJECTION of the
// RETH's netdev rather than an independent observer of it.
//
// That exemption is only sound if the Go builder actually produces the shape it
// assumes, and the Rust fixtures hand-build ConfigSnapshot rows. A hand-built
// row can model a snapshot this builder never emits — the failure mode the top
// of zone_propagation_6722_test.go documents. This file pins the producible
// facts:
//
//  1. `ResolveReth` collapses a RETH onto its physical member's netdev, so the
//     UNZONED member row, the zoned `reth1` base row and the zoned `reth1.0`
//     row all carry ONE ifindex.
//  2. That member row carries RedundantParent, so the Rust side can tell it
//     apart from a genuine unzoned logical unit.
//  3. A member's UNIT rows alias too — and not only via the unit-0 collapse. A
//     VLAN unit resolves to LinuxIfName(ResolveReth(base)).<vlan>, so
//     `ge-0/0/1.100` lands on `reth1.100`'s netdev. Those rows must carry
//     RedundantParent as well, or that second ifindex stays ambiguous.
//  4. A NON-member interface never carries RedundantParent, so the exemption
//     cannot reach a genuine logical unit (`wg0.0`, `st0.0`).
//
// FAIL-ON-REVERT: drop the `RedundantParent: iface.RedundantParent` stamp in
// buildInterfaceSnapshots (interfaces.go) and cases A and B go RED on the
// member rows. Dropping only the UNIT-row stamp reds case B alone.

// A: the reference bondless-RETH LAN. Three rows, one ifindex, and only the
// member is a projection.
func TestRethMemberRowIsMarkedAProjection_6722(t *testing.T) {
	zoneByIface, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	// Fact 1: Junos zones the RETH, never the member.
	if got := zoneByIface["ge-0/0/1"]; got != "" {
		t.Fatalf("buildInterfaceZoneMap[ge-0/0/1] = %q, want empty: Junos zones "+
			"the RETH, not its physical member. If this is no longer empty the "+
			"member is being given a zone somewhere and the Rust ledger's "+
			"projection exemption is solving a problem that no longer exists — "+
			"re-derive it rather than re-pointing this test", got)
	}
	if got := zoneByIface["reth1"]; got != "lan" {
		t.Fatalf("buildInterfaceZoneMap[reth1] = %q, want lan", got)
	}

	member := snapByName6722(t, snaps, "ge-0/0/1")
	base := snapByName6722(t, snaps, "reth1")
	unit0 := snapByName6722(t, snaps, "reth1.0")

	// All three rows are ONE kernel netdev. This is the premise of the whole
	// issue; assert it rather than assuming it.
	for _, row := range []InterfaceSnapshot{member, base, unit0} {
		if row.LinuxName != "ge-0-0-1" {
			t.Fatalf("%s LinuxName = %q, want ge-0-0-1: ResolveReth must collapse "+
				"the RETH onto its member's netdev", row.Name, row.LinuxName)
		}
		if row.Ifindex != 24 {
			t.Fatalf("%s Ifindex = %d, want 24: the three rows must SHARE one "+
				"ifindex or there is no ambiguity to adjudicate", row.Name, row.Ifindex)
		}
	}
	// And they disagree about the zone -- which is what made the ledger hold
	// the ifindex ambiguous and collapse the egress zone to the 0 sentinel.
	if member.Zone != "" || base.Zone != "lan" || unit0.Zone != "lan" {
		t.Fatalf("row zones = (%q, %q, %q), want (\"\", lan, lan): the DISAGREEMENT "+
			"is the shape under test", member.Zone, base.Zone, unit0.Zone)
	}

	// Fact 2: only the member is marked a projection.
	if member.RedundantParent != "reth1" {
		t.Errorf("ge-0/0/1 RedundantParent = %q, want reth1: without this mark the "+
			"Rust ledger counts the member's unzoned row as a dissenting vote, "+
			"holds ifindex 24 ambiguous, and every WAN->LAN transit flow on a "+
			"bondless-RETH cluster blackholes", member.RedundantParent)
	}
	if base.RedundantParent != "" {
		t.Errorf("reth1 RedundantParent = %q, want empty: the RETH is not a member "+
			"of itself", base.RedundantParent)
	}
	if unit0.RedundantParent != "" {
		t.Errorf("reth1.0 RedundantParent = %q, want empty", unit0.RedundantParent)
	}
}

// B: a member carrying its OWN units. Both the unit-0 collapse and a VLAN unit
// alias the matching reth unit, so the mark must be on the unit rows too.
func TestRethMemberUnitRowsAreMarkedAProjection_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/30",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100 family inet address 10.9.100.1/30",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24, "ge-0-0-1.100": 30},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	memberUnit0 := snapByName6722(t, snaps, "ge-0/0/1.0")
	memberUnit100 := snapByName6722(t, snaps, "ge-0/0/1.100")
	rethUnit100 := snapByName6722(t, snaps, "reth1.100")

	// The unit-0 collapse puts the member's unit 0 on the member's own netdev,
	// alongside the reth base row.
	if memberUnit0.Ifindex != 24 {
		t.Fatalf("ge-0/0/1.0 Ifindex = %d, want 24 (non-VLAN unit-0 collapse)",
			memberUnit0.Ifindex)
	}
	// The VLAN unit aliases the RETH's VLAN unit: BOTH resolve to
	// LinuxIfName(ResolveReth(base)).100.
	if memberUnit100.Ifindex != rethUnit100.Ifindex {
		t.Fatalf("ge-0/0/1.100 ifindex %d != reth1.100 ifindex %d: a member's VLAN "+
			"unit must alias the RETH's VLAN unit, or this case is not the shape "+
			"under test", memberUnit100.Ifindex, rethUnit100.Ifindex)
	}
	if memberUnit100.Zone != "" || rethUnit100.Zone != "lan" {
		t.Fatalf("VLAN-unit zones = (%q, %q), want (\"\", lan): the disagreement on "+
			"the SECOND ifindex is what case B exists to cover",
			memberUnit100.Zone, rethUnit100.Zone)
	}

	for _, row := range []InterfaceSnapshot{memberUnit0, memberUnit100} {
		if row.RedundantParent != "reth1" {
			t.Errorf("%s RedundantParent = %q, want reth1: stamping only the "+
				"member's BASE row leaves this ifindex ambiguous", row.Name,
				row.RedundantParent)
		}
	}
	if rethUnit100.RedundantParent != "" {
		t.Errorf("reth1.100 RedundantParent = %q, want empty", rethUnit100.RedundantParent)
	}
}

// C: OVER-REACH GUARD. A genuine logical unit must never be marked a
// projection, or the Rust exemption silences a real operator statement and
// reopens the #6722 fail-open. `wg0.0` unzoned beside a zoned `wg0.1` is the
// exact shape #6722 B1 closed.
func TestNonRethInterfacesCarryNoProjectionMark_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone vpnb interfaces st0.1",
	}, map[string]int{"ge-0-0-1": 24, "st0": 42, "st0.1": 43},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	// st0 / st0.0 share ifindex 42 and DISAGREE with the base's propagated
	// zone -- the #6722 shape that must keep failing closed.
	unit0 := snapByName6722(t, snaps, "st0.0")
	if unit0.Zone != "" || unit0.Ifindex != 42 {
		t.Fatalf("st0.0 = (zone %q, ifindex %d), want (\"\", 42): the ambiguous "+
			"shape must still be produced or this guard measures nothing",
			unit0.Zone, unit0.Ifindex)
	}
	for _, name := range []string{"st0", "st0.0", "st0.1", "ge-0/0/1", "ge-0/0/1.0"} {
		if got := snapByName6722(t, snaps, name).RedundantParent; got != "" {
			t.Errorf("%s RedundantParent = %q, want empty: only a PHYSICAL RETH "+
				"member is a projection. Marking a genuine logical unit exempts it "+
				"from the ledger and reopens the #6722 fail-open, which is worse "+
				"than the fail-closed B2 fixes", name, got)
		}
	}
}

// D: the field must survive the wire. The whole Rust-side fix reads a JSON key
// the Go builder has to actually emit; an `omitempty` typo would leave the
// helper defaulting to "" and silently restore the blackhole.
func TestRedundantParentRoundTripsOnTheWire_6722(t *testing.T) {
	cfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}, false)

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	blob, err := marshalSnapshotJSON6722(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !containsSubstring6722(blob, `"redundant_parent":"reth1"`) {
		t.Fatalf("serialized snapshot does not carry redundant_parent for the RETH "+
			"member; the Rust ledger will default it to \"\" and the member will "+
			"vote again. Payload: %s", truncate6722(blob, 2000))
	}
	// omitempty: a non-member row must not gain a key. This keeps the wire
	// byte-identical for every non-RETH deployment and keeps the
	// protocol_wire_v1 default specimen honest.
	if containsSubstring6722(blob, `"redundant_parent":""`) {
		t.Errorf("an empty redundant_parent was serialized: the field must be " +
			"omitempty so non-member rows stay byte-identical on the wire")
	}
}

func marshalSnapshotJSON6722(snap *ConfigSnapshot) (string, error) {
	b, err := json.Marshal(snap)
	return string(b), err
}

func containsSubstring6722(hay, needle string) bool {
	return strings.Contains(hay, needle)
}

func truncate6722(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
