package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722 B2, the GO half — and after the B1 re-derivation was retired, the
// DECIDING half. The Rust agreement ledger
// (`userspace-dp/src/afxdp/forwarding_build/interfaces.rs`) withholds the zone
// vote of a row carrying `reth_projection` AND no zone of its own, because a
// RETH's physical member is a PROJECTION of the RETH's netdev rather than an
// independent observer of it. The helper no longer decides which rows those
// are: `rethProjectionNetdevs` (interfaces.go) does, here, where `ResolveReth`
// and the whole interface table live.
//
// That matters because the predecessor of this field carried the raw
// `redundant-parent` string and left the helper to re-derive the answer from
// row names. `redundant-parent` is unvalidated operator input — strict
// `CompileConfig` accepts it under any interface name, pointing at anything,
// including the interface writing it — so every spelling of the re-derivation
// was a predicate the operator could satisfy by choosing names. Three were
// holed in turn; the last by `set interfaces st0 gigether-options
// redundant-parent st0`, where `st0.0` matched its own co-resident BASE row and
// exempted itself. E below is that config.
//
// The producible facts this file pins:
//
//  1. `ResolveReth` collapses a RETH onto its physical member's netdev, so the
//     UNZONED member row, the zoned `reth1` base row and the zoned `reth1.0`
//     row all carry ONE ifindex — and only the member is a projection.
//  2. A member's UNIT rows alias too, and not only via the unit-0 collapse: a
//     VLAN unit resolves to LinuxIfName(ResolveReth(base)).<vlan>, so
//     `ge-0/0/1.100` lands on `reth1.100`'s netdev.
//  3. A NON-member interface is never marked, so the exemption cannot reach a
//     genuine logical unit (`wg0.0`, `st0.0`).
//  4. The mark is decided PER ROW by where the row lands, not per interface: a
//     member unit resolving to a netdev the RETH has no row on is observing a
//     netdev of its own and votes.
//  5. A parent that is not a DECLARED redundant-ethernet interface — undefined,
//     or defined with no `redundancy-group` — is no authority, and a parent
//     that is the interface itself is no parent.
//
// FAIL-ON-REVERT, per clause of `rethProjectionNetdevs`:
//
//	drop `|| iface.RedundantParent == name`      -> E   (self-named parent)
//	drop `|| reth.RedundancyGroup <= 0`          -> F   (undeclared RETH)
//	drop the `out[name] = netdevs` publish       -> A+B (nothing ever marked)
//	drop the `netdevs[base] = true` insert       -> B   (member unit 0)
//	drop the `for _, unit := range reth.Units`   -> B   (member VLAN unit)
//	key the UNIT row on the interface            -> G   (unit off the netdevs)
//	key the BASE row on the interface            -> H   (peer node's member)
//
// C stays GREEN under every one of those — it is the over-reach guard, not a
// restatement of the fix. The measured cell table is in the commit message.

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

	// Fact 1, the mark: only the member is a projection.
	if !member.RethProjection {
		t.Errorf("ge-0/0/1 RethProjection = false, want true: without this mark the " +
			"Rust ledger counts the member's unzoned row as a dissenting vote, " +
			"holds ifindex 24 ambiguous, and every WAN->LAN transit flow on a " +
			"bondless-RETH cluster blackholes")
	}
	if base.RethProjection {
		t.Errorf("reth1 RethProjection = true, want false: the RETH's own row is " +
			"the AUTHORITY the exemption defers to. Marking it silences the only " +
			"row that names the zone")
	}
	if unit0.RethProjection {
		t.Errorf("reth1.0 RethProjection = true, want false")
	}
}

// B: a member carrying its OWN units. Both the unit-0 collapse and a VLAN unit
// alias the matching reth unit, so the mark must be on the unit rows too. The
// VLAN pair is what the `reth.Units` loop in rethProjectionNetdevs is for: the
// reth's unit-0 row resolves to the same netdev as its base, so a base-only
// netdev set covers ifindex 24 and leaves the VLAN ifindex ambiguous.
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
		if !row.RethProjection {
			t.Errorf("%s RethProjection = false, want true: marking only the "+
				"member's BASE row leaves this ifindex ambiguous", row.Name)
		}
	}
	if rethUnit100.RethProjection {
		t.Errorf("reth1.100 RethProjection = true, want false")
	}
}

// C: OVER-REACH GUARD. A genuine logical unit must never be marked a
// projection, or the Rust exemption silences a real operator statement and
// reopens the #6722 fail-open. `st0.0` unzoned beside a zoned `st0.1` is the
// exact shape #6722 B1 closed. This must stay GREEN under every mutation in
// the header's fail-on-revert table.
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
		if snapByName6722(t, snaps, name).RethProjection {
			t.Errorf("%s RethProjection = true, want false: only a row landing on "+
				"a DECLARED RETH's netdev is a projection. Marking a genuine "+
				"logical unit exempts it from the ledger and reopens the #6722 "+
				"fail-open, which is worse than the fail-closed B2 fixes", name)
		}
	}
}

// D: the field must survive the wire. The whole Rust-side fix reads a JSON key
// the Go builder has to actually emit; an `omitempty` typo would leave the
// helper defaulting to false and silently restore the blackhole.
func TestRethProjectionRoundTripsOnTheWire_6722(t *testing.T) {
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
	if !containsSubstring6722(blob, `"reth_projection":true`) {
		t.Fatalf("serialized snapshot does not carry reth_projection for the RETH "+
			"member; the Rust ledger will default it to false and the member will "+
			"vote again. Payload: %s", truncate6722(blob, 2000))
	}
	// omitempty: a non-projection row must not gain a key. This keeps the wire
	// byte-identical for every non-RETH deployment and keeps the
	// protocol_wire_v1 default specimen honest.
	if containsSubstring6722(blob, `"reth_projection":false`) {
		t.Errorf("an explicit false reth_projection was serialized: the field must " +
			"be omitempty so non-projection rows stay byte-identical on the wire")
	}
}

// E: the F1 COUNTEREXAMPLE — an interface naming ITSELF as its redundant-parent.
//
// Nothing rejects that line. `schema_interfaces.go` accepts `gigether-options`
// under any interface name and no compiler pass requires the named parent to
// differ from the interface naming it; all three sub-shapes below compile under
// strict CompileConfig (measured). `RethToPhysical` then maps the name to
// itself, so `ResolveReth` is a no-op and NOTHING is aliased — the rows share
// their ifindex through the ordinary non-VLAN unit-0 collapse, exactly as a
// plain `st0` does, and their "no zone" is a real operator statement.
//
// E2/E3 are the load-bearing cells: without the irreflexivity clause the
// interface becomes a projection of ITSELF. In E2 that silences `st0.0` and the
// ledger resolves `vpnb` for an ifindex whose own netdev row is unzoned — the
// measured fail-open, `egress_zone_id` 32521 where it must be 0. In E3 it is
// worse: the RETH silences its own rows, so the authority the exemption exists
// to defer to casts no vote at all.
func TestSelfNamedRedundantParentIsNotAProjection_6722(t *testing.T) {
	// E1: the config exactly as found. No redundancy-group anywhere.
	t.Run("no-redundancy-group", func(t *testing.T) {
		_, snaps := buildSnapshotsFromSet6722(t, []string{
			"set interfaces st0 gigether-options redundant-parent st0",
			"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
			"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
			"set security zones security-zone vpnb interfaces st0.1",
		}, map[string]int{"st0": 42, "st0.1": 43}, nil)

		base := snapByName6722(t, snaps, "st0")
		unit0 := snapByName6722(t, snaps, "st0.0")
		// Precondition: the ambiguity is real. A unit-suffixed zone reference
		// zones the BASE too, so `st0` carries vpnb while `st0.0` does not, and
		// the unit-0 collapse puts both on one ifindex.
		if base.Zone != "vpnb" || unit0.Zone != "" || base.Ifindex != unit0.Ifindex {
			t.Fatalf("st0=(zone %q, ifindex %d) st0.0=(zone %q, ifindex %d), want "+
				"(vpnb, N) and (\"\", N): without the shared ifindex and the "+
				"disagreement there is no fail-open to guard against",
				base.Zone, base.Ifindex, unit0.Zone, unit0.Ifindex)
		}
		for _, row := range []InterfaceSnapshot{base, unit0} {
			if row.RethProjection {
				t.Errorf("%s RethProjection = true, want false: `redundant-parent "+
					"st0` on st0 names no RETH. Marking it exempts st0.0's "+
					"dissenting vote, the ledger resolves vpnb for ifindex %d, and "+
					"transit out a unit the operator deliberately left unzoned is "+
					"PERMITTED", row.Name, row.Ifindex)
			}
		}
	})

	// E2: the same config plus a redundancy-group, which makes the interface a
	// declared RETH pointing at itself. This is the cell the RG clause does NOT
	// cover, and the one the irreflexivity clause exists for.
	t.Run("with-redundancy-group", func(t *testing.T) {
		_, snaps := buildSnapshotsFromSet6722(t, []string{
			"set interfaces st0 gigether-options redundant-parent st0",
			"set interfaces st0 redundant-ether-options redundancy-group 1",
			"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
			"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
			"set security zones security-zone vpnb interfaces st0.1",
		}, map[string]int{"st0": 42, "st0.1": 43}, nil)

		base := snapByName6722(t, snaps, "st0")
		unit0 := snapByName6722(t, snaps, "st0.0")
		if base.Zone != "vpnb" || unit0.Zone != "" || base.Ifindex != unit0.Ifindex {
			t.Fatalf("st0=(zone %q, ifindex %d) st0.0=(zone %q, ifindex %d), want "+
				"(vpnb, N) and (\"\", N)",
				base.Zone, base.Ifindex, unit0.Zone, unit0.Ifindex)
		}
		for _, row := range []InterfaceSnapshot{base, unit0} {
			if row.RethProjection {
				t.Errorf("%s RethProjection = true, want false: an interface is "+
					"never a projection of ITSELF, and a redundancy-group does not "+
					"make it one. Marking it reopens the measured fail-open "+
					"(egress_zone_id 32521 where it must be 0)", row.Name)
			}
		}
	})

	// E3: the same self-reference on an interface that really is named `reth*`.
	// Here the rows that would be marked are the RETH's OWN — the authority.
	t.Run("reth-names-itself", func(t *testing.T) {
		_, snaps := buildSnapshotsFromSet6722(t, []string{
			"set interfaces reth1 gigether-options redundant-parent reth1",
			"set interfaces reth1 redundant-ether-options redundancy-group 1",
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
			"set security zones security-zone lan interfaces reth1",
		}, map[string]int{"reth1": 24}, nil)

		for _, name := range []string{"reth1", "reth1.0"} {
			row := snapByName6722(t, snaps, name)
			if row.LinuxName != "reth1" {
				t.Fatalf("%s LinuxName = %q, want reth1: ResolveReth must be a "+
					"no-op when a reth names itself, or this is not the shape "+
					"under test", name, row.LinuxName)
			}
			if row.RethProjection {
				t.Errorf("%s RethProjection = true, want false: the RETH's own rows "+
					"are the authority the exemption defers to. Marking them makes "+
					"the RETH silence itself and no row on the ifindex votes at "+
					"all", name)
			}
		}
	})
}

// F: a parent that is not a DECLARED redundant-ethernet interface is no
// authority, so nothing pointing at it is a projection. Three ways to fail
// that, all accepted by strict CompileConfig.
//
// F1 is the clause `reth.RedundancyGroup <= 0` alone: `reth1` exists, is named
// `reth*`, and `ResolveReth` really does collapse it onto the member's netdev —
// the aliasing is genuine — but no `redundancy-group` was declared. This is the
// same test the adjacent rethRG loop already uses to decide whether a parent is
// a real RETH, and the degraded direction is fail-CLOSED: the ifindex stays
// ambiguous and the egress zone stays at the 0 sentinel. Every RETH config in
// this repository declares its redundancy-group.
func TestUndeclaredParentIsNotAProjection_6722(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			// F1: parent exists and aliases, but declares no redundancy-group.
			name: "parent-without-redundancy-group",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
		},
		{
			// F2: parent never defined at all.
			name: "dangling-parent",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/30",
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set security zones security-zone lan interfaces ge-0/0/2",
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.61.1/24",
			},
		},
		{
			// F3: a declared RETH whose name merely CONTAINS the parent's name
			// as a bare textual prefix. `reth10` is an ordinary RETH name
			// (Junos allows reth0..reth127) and `reth1` is undefined. Under the
			// retired string re-derivation this was a live escape — a textual
			// coincidence silencing a real observer. It is now unrepresentable:
			// the lookup is an exact map key, not a prefix match.
			name: "bare-prefix-sibling",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/2 gigether-options redundant-parent reth10",
				"set interfaces reth10 redundant-ether-options redundancy-group 2",
				"set interfaces reth10 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth10",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, snaps := buildSnapshotsFromSet6722(t, tc.lines,
				map[string]int{"ge-0-0-1": 24, "ge-0-0-2": 25, "reth1": 26},
				map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})
			member := snapByName6722(t, snaps, "ge-0/0/1")
			if member.RethProjection {
				t.Errorf("ge-0/0/1 RethProjection = true, want false: `reth1` is not "+
					"a declared redundant-ethernet interface here, so there is no "+
					"authority for the exemption to defer to and the member's own "+
					"vote must stand (linux_name %q, ifindex %d)",
					member.LinuxName, member.Ifindex)
			}
		})
	}
	// The F3 control: the member of the RETH that IS declared stays marked, so
	// the sub-test above is measuring the parent's identity rather than a
	// blanket refusal to mark anything.
	_, snaps := buildSnapshotsFromSet6722(t, cases[2].lines,
		map[string]int{"ge-0-0-1": 24, "ge-0-0-2": 25},
		map[string]string{"ge-0-0-2": "02:bf:72:01:00:02"})
	if sibling := snapByName6722(t, snaps, "ge-0/0/2"); !sibling.RethProjection {
		t.Errorf("ge-0/0/2 RethProjection = false, want true: reth10 IS declared " +
			"and resolves onto it, so the bare-prefix sub-test above would pass " +
			"even if nothing were ever marked")
	}
}

// G: the mark is decided PER ROW, by the netdev the row lands on — not per
// interface. `ge-0/0/1` is a real member of a real RETH, so an interface-keyed
// mark would cover ALL of its rows. But `reth1` carries no VLAN-100 unit, so
// `ge-0/0/1.100` lands on `ge-0-0-1.100`, a netdev no RETH row occupies. That
// row observes a netdev of its own and must vote.
//
// Key on the interface instead of the row (`len(rethProjection[name]) > 0`) and
// this reds while A and B stay green — which is the point: the interface-level
// answer is right for two of this config's three rows.
func TestMemberUnitOffTheRethsNetdevsIsNotAProjection_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/30",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100 family inet address 10.9.100.1/30",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24, "ge-0-0-1.100": 30},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	unit100 := snapByName6722(t, snaps, "ge-0/0/1.100")
	if unit100.LinuxName != "ge-0-0-1.100" {
		t.Fatalf("ge-0/0/1.100 LinuxName = %q, want ge-0-0-1.100", unit100.LinuxName)
	}
	// Precondition: reth1 really has no row there. If it grew one this test
	// would be measuring nothing.
	for _, row := range snaps {
		if row.LinuxName == "ge-0-0-1.100" && row.Name != "ge-0/0/1.100" {
			t.Fatalf("%s also lands on ge-0-0-1.100; this config must leave the "+
				"member's VLAN unit ALONE on its netdev", row.Name)
		}
	}
	if unit100.RethProjection {
		t.Errorf("ge-0/0/1.100 RethProjection = true, want false: no RETH row " +
			"occupies ge-0-0-1.100, so this unit is an independent observer of " +
			"its own netdev and its vote must count")
	}
	// Control: the two rows that DO land on the RETH's netdev stay marked, so
	// the assertion above cannot pass by the mark being universally absent.
	for _, name := range []string{"ge-0/0/1", "ge-0/0/1.0"} {
		if !snapByName6722(t, snaps, name).RethProjection {
			t.Errorf("%s RethProjection = false, want true: it lands on "+
				"ge-0-0-1, which reth1 occupies", name)
		}
	}
}

// H: the PEER NODE's member. A two-node cluster config declares both members
// of a RETH — `docs/ha-cluster-userspace.conf` carries `ge-0/0/1` and
// `ge-7/0/1` side by side — but `RethToPhysical` resolves the RETH onto exactly
// ONE of them. The other's rows land on its own netdev, which no RETH row
// occupies, so they are independent observers and must vote.
//
// This is the base-row half of the per-row keying, and the only cell that
// catches it: for the RESOLVED member the row's netdev and the interface's
// netdev coincide, so an interface-keyed base stamp is right there and wrong
// only here. Key the base row on the interface (`len(rethProjection[name]) > 0`)
// and this reds while A, B and G stay green.
//
// In a live deployment the peer's netdev usually does not exist locally, so its
// rows carry ifindex 0 and the Rust ledger skips them regardless. That is a
// mitigation, not the invariant: the mark states a fact about the row, and a
// fact that happens to be unobservable on one topology is still wrong.
func TestPeerNodeRethMemberIsNotAProjection_6722(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-7/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}
	ifindexOf := map[string]int{"ge-0-0-1": 24, "ge-7-0-1": 34}
	macOf := map[string]string{
		"ge-0-0-1": "02:bf:72:01:00:01",
		"ge-7-0-1": "02:bf:72:01:00:07",
	}
	cfg := compileWithStubbedLinks6722(t, lines, ifindexOf, macOf, false)

	// Premise: the RETH resolves onto exactly one member. Assert WHICH, so a
	// change to RethToPhysical's node-affinity scoring turns this into a loud
	// failure rather than silently swapping the two roles below.
	if got := cfg.ResolveReth("reth1"); got != "ge-0/0/1" {
		t.Fatalf("ResolveReth(reth1) = %q, want ge-0/0/1: this test needs to know "+
			"which member the RETH collapses onto", got)
	}
	snaps := buildInterfaceSnapshots(cfg)

	local := snapByName6722(t, snaps, "ge-0/0/1")
	peer := snapByName6722(t, snaps, "ge-7/0/1")
	if local.Ifindex == peer.Ifindex || peer.LinuxName != "ge-7-0-1" {
		t.Fatalf("local=(%q, %d) peer=(%q, %d): the two members must be DIFFERENT "+
			"netdevs, or there is no distinction to draw",
			local.LinuxName, local.Ifindex, peer.LinuxName, peer.Ifindex)
	}
	if !local.RethProjection {
		t.Errorf("ge-0/0/1 RethProjection = false, want true: the RETH resolves " +
			"onto it, so reth1's rows and its own are one netdev")
	}
	if peer.RethProjection {
		t.Errorf("ge-7/0/1 RethProjection = true, want false: reth1 resolves onto " +
			"ge-0/0/1, so no RETH row lands on ge-7-0-1. Marking the peer's row " +
			"withholds the only vote its ifindex has, on the strength of a " +
			"redundant-parent line that points somewhere else")
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
