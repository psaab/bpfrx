package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722 B2, the GO half — the DECIDING half. The Rust agreement ledger
// (`userspace-dp/src/afxdp/forwarding_build/interfaces.rs`) withholds the zone
// vote of a row carrying `reth_projection` AND no zone of its own, because a
// RETH's physical member is a PROJECTION of the RETH's netdev rather than an
// independent observer of it. `rethProjectionMembers` (interfaces.go) decides
// which interfaces those are, here, where `ResolveReth` and the whole interface
// table live.
//
// FIVE spellings of that predicate were holed in turn, and the pattern is the
// point. B1 carried the raw `redundant-parent` string on the wire and
// re-derived the answer from row names; the next three re-derived it from
// co-resident rows, then from a netdev SET the parent's rows occupied. Every
// one of them was a RECONSTRUCTION of `ResolveReth`'s answer, and every one was
// holed by a config strict `CompileConfig` accepted — the last by a member unit
// carrying its OWN address, which lands exactly where the RETH's unit lands and
// so satisfied the netdev-set test while being a genuinely independent L3
// interface. That is a FAIL-OPEN: measured, a flow to the member unit's subnet
// resolved the RETH's zone and was permitted where it must be denied.
//
// The reconstruction is gone. Two things replaced it:
//
//  1. `validateRethMemberStrict` (pkg/config/compiler_validate_strict_reth_member.go)
//     rejects the incoherent memberships at commit — a member naming ITSELF,
//     a member naming an unconfigured parent, and a member carrying its own
//     logical units. Those shapes are now UNREPRESENTABLE on the commit path
//     rather than excluded by a predicate clause.
//  2. What remains is the ALIAS ITSELF, asked of `snapshotLinuxName` — the
//     function that creates it: does the parent's base row resolve to the same
//     netdev as this interface's base row? There is no second opinion left to
//     disagree with the resolver.
//
// The producible facts this file pins:
//
//  1. `ResolveReth` collapses a RETH onto its physical member's netdev, so the
//     UNZONED member row and the zoned `reth1` / `reth1.0` rows carry ONE
//     ifindex — and only the member is a projection.
//  2. A NON-member interface is never marked, so the exemption cannot reach a
//     genuine logical unit (`wg0.0`, `st0.0`).
//  3. Which of a RETH's DECLARED members is the projection is `RethToPhysical`'s
//     node-affinity answer, not "declares redundant-parent": the peer node's
//     member votes.
//  4. The three incoherent memberships are commit REJECTIONS.
//  5. A member unit that reaches the builder anyway — via the tolerant load /
//     peer-sync path, where the gate is a warning — still VOTES, so its ifindex
//     stays ambiguous and fails CLOSED.
//
// FAIL-ON-REVERT, per production hunk:
//
//	drop the `out[name] = true` publish                -> A (nothing marked)
//	drop the netdev comparison (mark every member)     -> D (peer node's member)
//	stamp the unit row from the map instead of `false` -> F (member unit)
//	drop the unit clause of validateRethMemberStrict   -> G1/G2 (accepts)
//	drop the self clause of validateRethMemberStrict   -> H1 (accepts; H1 is the
//	                                                      no-unit sub-case, the
//	                                                      only one the unit
//	                                                      clause cannot also
//	                                                      catch)
//	drop the parent-exists clause                      -> I1/I2 (accepts)
//	drop the `opts.lenientRethMember` downgrade        -> G/H/I lenient halves
//	drop `parent != name` from rethProjectionMembers   -> J (self-parent)
//
// B is the OVER-REACH GUARD: it stays green under every one of those, because
// its config declares no `redundant-parent` at all. C is a BINDING cell despite
// reading like a guard — it reds with D when the netdev comparison is dropped.
// The measured cell table is in the commit message.

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

// B: OVER-REACH GUARD. A genuine logical unit must never be marked a
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
				"a RETH's own netdev is a projection. Marking a genuine logical "+
				"unit exempts it from the ledger and reopens the #6722 "+
				"fail-open, which is worse than the fail-closed B2 fixes", name)
		}
	}
}

// C: a `redundant-parent` naming an interface that is NOT aliased onto this one
// marks nothing. `ge-0/0/2` is a real, configured interface, so the
// parent-exists clause is satisfied — but `snapshotLinuxName` applies
// `ResolveReth` only to `reth`-prefixed names, so `ge-0/0/2`'s rows stay on
// `ge-0-0-2` and no aliasing happens. The predicate asks the aliasing function,
// so it says no.
//
// This is what keeps the predicate from degenerating back into "declares
// redundant-parent", and it BINDS the netdev comparison alongside D: measured,
// dropping that comparison reds C and D together. It is therefore a binding
// cell, not an over-reach guard — B is the only cell that stays green under
// every mutation in the table.
func TestRedundantParentThatDoesNotAliasMarksNothing_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent ge-0/0/2",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces ge-0/0/2.0",
	}, map[string]int{"ge-0-0-1": 24, "ge-0-0-2": 25},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	member := snapByName6722(t, snaps, "ge-0/0/1")
	parent := snapByName6722(t, snaps, "ge-0/0/2")
	// Precondition: no aliasing. If these ever landed on one netdev this cell
	// would be measuring the opposite of what it claims.
	if member.LinuxName == parent.LinuxName {
		t.Fatalf("ge-0/0/1 and ge-0/0/2 both resolve to %q; this cell needs them "+
			"on DIFFERENT netdevs", member.LinuxName)
	}
	if member.RethProjection {
		t.Errorf("ge-0/0/1 RethProjection = true, want false: `redundant-parent " +
			"ge-0/0/2` names a configured interface, but nothing was aliased — " +
			"ge-0/0/2's rows stay on their own netdev. Marking on the strength " +
			"of the redundant-parent line alone withholds the only vote " +
			"ifindex 24 has")
	}
}

// D: the PEER NODE's member. A two-node cluster config declares both members
// of a RETH — `docs/ha-cluster-userspace.conf` carries `ge-0/0/1` and
// `ge-7/0/1` side by side — but `RethToPhysical` resolves the RETH onto exactly
// ONE of them. The other's rows land on its own netdev, so they are independent
// observers and must vote.
//
// This is the cell that makes the netdev comparison load-bearing: both
// interfaces declare `redundant-parent reth1` and both name a configured,
// declared RETH, so every clause except the alias itself is satisfied for both.
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

// E: the field must survive the wire. The whole Rust-side fix reads a JSON key
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

// F: the LENIENT-PATH BACKSTOP, and the Codex F1 counterexample in the only
// form that can still reach the builder.
//
// `validateRethMemberStrict` rejects a member carrying its own units on the
// commit path (cell G), but the tolerant load / peer-sync path downgrades that
// to a warning (#1960 no-brick), so a config committed before the gate still
// boots — and its member unit rows still reach `buildInterfaceSnapshots`.
//
// `ge-0/0/1.0` carries its OWN address and lands on ifindex 24 beside the
// zoned `reth1` / `reth1.0` rows. It is an independently addressed L3 interface
// — it installs a connected route `10.9.9.0/30 -> 24` and a local address — so
// its missing zone is a real operator statement. Marking it withholds that
// vote, the ledger resolves `lan` for ifindex 24, and a flow to `10.9.9.2` is
// evaluated in the RETH's zone and PERMITTED. That is the measured fail-open
// that holed spelling four; the unit row must stay unmarked so the ifindex
// stays ambiguous and fails CLOSED.
func TestGrandfatheredMemberUnitStillVotes_6722(t *testing.T) {
	cfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/30",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}, true)

	// Precondition: the lenient path really did admit it, and said so.
	if !warnsAboutRethMember6722(cfg.Warnings) {
		t.Fatalf("CompileConfigLenient recorded no reth-member warning; the "+
			"tolerant path must ADMIT this config with a warning or this cell is "+
			"not exercising the grandfathered shape. Warnings: %v", cfg.Warnings)
	}
	snaps := buildInterfaceSnapshots(cfg)
	memberUnit0 := snapByName6722(t, snaps, "ge-0/0/1.0")
	rethUnit0 := snapByName6722(t, snaps, "reth1.0")

	// Precondition: the two units really do collide on one ifindex, and only
	// the RETH's is zoned. Without that there is no fail-open to guard.
	if memberUnit0.Ifindex != 24 || rethUnit0.Ifindex != 24 {
		t.Fatalf("ge-0/0/1.0 ifindex %d, reth1.0 ifindex %d, want both 24: the "+
			"shared ifindex is the shape under test",
			memberUnit0.Ifindex, rethUnit0.Ifindex)
	}
	if memberUnit0.Zone != "" || rethUnit0.Zone != "lan" {
		t.Fatalf("unit zones = (%q, %q), want (\"\", lan)",
			memberUnit0.Zone, rethUnit0.Zone)
	}
	// And it really is an independent L3 interface: its own address, hence its
	// own connected route and local address on ifindex 24.
	if len(memberUnit0.Addresses) == 0 {
		t.Fatalf("ge-0/0/1.0 carries no addresses; this cell needs the member " +
			"unit to be independently addressed, which is what makes its vote real")
	}

	if memberUnit0.RethProjection {
		t.Errorf("ge-0/0/1.0 RethProjection = true, want false: the unit carries " +
			"its own address 10.9.9.1/30, installs a connected route on ifindex " +
			"24 and is an INDEPENDENT L3 interface. Withholding its vote lets " +
			"the ledger resolve `lan` for that ifindex, and a flow to 10.9.9.2 " +
			"is then evaluated in the RETH's zone and PERMITTED where it must be " +
			"denied — the measured #6722 fail-open")
	}
	// Control: the member's BASE row stays marked, so the assertion above
	// cannot pass by the mark being universally absent on this config.
	if !snapByName6722(t, snaps, "ge-0/0/1").RethProjection {
		t.Errorf("ge-0/0/1 RethProjection = false, want true: the base row is " +
			"the RETH's port and is still a projection")
	}
}

// G: the Codex F1 counterexamples, as COMMIT REJECTIONS. Both configs compiled
// under strict CompileConfig before this change, and both put two
// independently addressed L3 units on one netdev.
//
// G1 is the unit-0 collapse: `ge-0/0/1.0` and `reth1.0` both resolve to
// `ge-0-0-1`. G2 is the VLAN form, and it is the one that disproves "a name can
// no longer satisfy the predicate": `ResolveReth("reth1")` selects `ge-0/0/1`,
// so the AUTHORED name `ge-0/0/1.100` resolves to the same Linux name as
// `reth1.100` and lands on the RETH's own VLAN netdev.
func TestRethMemberWithOwnUnitsIsRejected_6722(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "unit-0-collapse",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/30",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
		},
		{
			name: "vlan-unit-aliases-the-reths",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/1 vlan-tagging",
				"set interfaces ge-0/0/1 unit 100 vlan-id 100 family inet address 10.9.100.1/30",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 vlan-tagging",
				"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRethMemberRejected6722(t, tc.lines, "also configures `unit")
		})
	}
}

// H: a member naming ITSELF. `RethToPhysical` maps the name to itself, so
// `ResolveReth` is a no-op and the interface is a member of nothing — while
// still presenting as one. Four sub-shapes, all accepted by strict
// CompileConfig before this change; H4 is the worst, where the rows that would
// be silenced are the RETH's OWN.
//
// H1 carries NO units, and it is the sub-case that makes the self clause
// independently load-bearing: the other three would be rejected by the unit
// clause even with the self clause gone, so on its own each of them proves only
// that SOME clause fires. Measured — drop the self clause and H1 compiles
// cleanly while H2/H3/H4 are still rejected, by a different clause and with a
// different message.
func TestSelfNamedRedundantParentIsRejected_6722(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			// H1: no units anywhere on the self-parenting interface, so no
			// other clause of the gate can reach it.
			name: "no-units",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent ge-0/0/1",
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces ge-0/0/2.0",
			},
		},
		{
			name: "no-redundancy-group",
			lines: []string{
				"set interfaces st0 gigether-options redundant-parent st0",
				"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
				"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
				"set security zones security-zone vpnb interfaces st0.1",
			},
		},
		{
			name: "with-redundancy-group",
			lines: []string{
				"set interfaces st0 gigether-options redundant-parent st0",
				"set interfaces st0 redundant-ether-options redundancy-group 1",
				"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
				"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
				"set security zones security-zone vpnb interfaces st0.1",
			},
		},
		{
			name: "reth-names-itself",
			lines: []string{
				"set interfaces reth1 gigether-options redundant-parent reth1",
				"set interfaces reth1 redundant-ether-options redundancy-group 1",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRethMemberRejected6722(t, tc.lines, "names itself")
		})
	}
}

// I: a parent that is not configured at all. There is no RETH row on the shared
// netdev to defer TO, so the ifindex would be left with no zone and every
// transit flow out of it dropped — silently, behind a `redundant-parent` line
// that looks correct.
//
// The `bare-prefix` sub-case is the one the RETIRED string re-derivation was
// holed by: `reth10` is an ordinary Junos reth name that textually contains
// `reth1`. It is rejected here for the plain reason that `reth1` is undefined,
// and the sibling that names the DECLARED `reth10` compiles and is marked —
// the control that keeps this cell from passing by nothing ever compiling.
func TestUnconfiguredRedundantParentIsRejected_6722(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "dangling-parent",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set security zones security-zone lan interfaces ge-0/0/2",
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.61.1/24",
			},
		},
		{
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
			assertRethMemberRejected6722(t, tc.lines, "is not a configured interface")
		})
	}
	// The control: drop the dangling member and the same config compiles, with
	// the member of the DECLARED reth10 marked. Without this the sub-tests above
	// would pass even if every config in this file were rejected.
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth10",
		"set interfaces reth10 redundant-ether-options redundancy-group 2",
		"set interfaces reth10 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth10",
	}, map[string]int{"ge-0-0-2": 25},
		map[string]string{"ge-0-0-2": "02:bf:72:01:00:02"})
	if sibling := snapByName6722(t, snaps, "ge-0/0/2"); !sibling.RethProjection {
		t.Errorf("ge-0/0/2 RethProjection = false, want true: reth10 IS configured " +
			"and resolves onto it, so the rejection sub-tests above are measuring " +
			"the parent's identity rather than a blanket refusal to compile")
	}
}

// J: the self-parent's LENIENT-PATH cell, and the reason
// `rethProjectionMembers` still tests `parent != name` after the strict gate
// rejects the shape (cell H).
//
// `RethToPhysical` maps a self-naming interface to itself, so `ResolveReth` is
// a no-op and `snapshotLinuxName(parent) == snapshotLinuxName(self)` holds
// TRIVIALLY — the alias comparison alone would call every self-parenting
// interface a projection of itself, on a config where nothing was aliased at
// all. The irreflexivity test is the definition of a parent relation, not a
// clause excluding a case, and it is the only thing standing on this path.
//
// The BOUND is worth stating exactly rather than as "it fails open". The Rust
// gate is `reth_projection && zone.is_empty()`, and a unit-suffixed zone
// reference zones the BASE row too (`buildInterfaceZoneMap`), so on this config
// the marked row carries `vpnb` and the ledger would still count its vote. What
// the mark would corrupt here is the FACT on the wire — `st0` reported as a
// projection of a RETH it is not a member of — and every consumer that reads it
// without re-deriving. The quarantine (`zones_quarantine.go`) runs after
// `buildInterfaceSnapshots` and blanks `Zone` on rows bound to a quarantined
// zone, which is a reachable way for a marked row to arrive unzoned and lose
// its vote for real.
func TestSelfNamedRedundantParentIsNotAProjectionOnTheLenientPath_6722(t *testing.T) {
	cfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces st0 gigether-options redundant-parent st0",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone vpnb interfaces st0.1",
	}, map[string]int{"st0": 42, "st0.1": 43}, nil, true)

	// Precondition: the tolerant path admitted it, with a warning.
	if !warnsAboutRethMember6722(cfg.Warnings) {
		t.Fatalf("CompileConfigLenient recorded no reth-member warning; this cell "+
			"needs the grandfathered self-parent to be ADMITTED. Warnings: %v",
			cfg.Warnings)
	}
	// Precondition: nothing was aliased. `ResolveReth` is a no-op, so the rows
	// share their ifindex through the ordinary unit-0 collapse, exactly as a
	// plain `st0` does.
	if got := cfg.ResolveReth("st0"); got != "st0" {
		t.Fatalf("ResolveReth(st0) = %q, want st0: a self-naming redundant-parent "+
			"must resolve to a no-op or this is not the shape under test", got)
	}
	snaps := buildInterfaceSnapshots(cfg)
	base := snapByName6722(t, snaps, "st0")
	unit0 := snapByName6722(t, snaps, "st0.0")
	if base.Ifindex != 42 || unit0.Ifindex != 42 {
		t.Fatalf("st0 ifindex %d, st0.0 ifindex %d, want both 42",
			base.Ifindex, unit0.Ifindex)
	}
	for _, row := range []InterfaceSnapshot{base, unit0} {
		if row.RethProjection {
			t.Errorf("%s RethProjection = true, want false: `redundant-parent st0` "+
				"on st0 names no RETH and aliases nothing, so the interface is "+
				"reported as a projection of ITSELF — a false fact on the wire, "+
				"and one that silences this row outright wherever it arrives "+
				"unzoned (the StableZoneID quarantine blanks Zone after this "+
				"builder runs)", row.Name)
		}
	}
}

// assertRethMemberRejected6722 compiles lines under STRICT CompileConfig and
// requires the reth-member coherence gate to reject them, then requires the
// TOLERANT path to admit the same config with a warning (#1960 no-brick). Both
// halves matter: a gate that also bricks the tolerant load is a different bug.
func assertRethMemberRejected6722(t *testing.T, lines []string, wantFragment string) {
	t.Helper()
	tree := treeFromSet6722(t, lines)
	_, err := config.CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted an incoherent reth membership; it must "+
			"be rejected at commit so the operator sees it before it mis-zones "+
			"traffic. Config: %v", lines)
	}
	if !strings.Contains(err.Error(), wantFragment) {
		t.Errorf("CompileConfig error = %q, want it to contain %q: the rejection "+
			"must come from the reth-member coherence gate, not from an unrelated "+
			"validator that happens to fire on this config too", err, wantFragment)
	}
	cfg, lerr := config.CompileConfigLenient(treeFromSet6722(t, lines))
	if lerr != nil {
		t.Fatalf("CompileConfigLenient rejected the same config (%v); the tolerant "+
			"load / peer-sync path must DOWNGRADE this gate to a warning or an "+
			"already-committed config stops booting (#1960 no-brick)", lerr)
	}
	if !warnsAboutRethMember6722(cfg.Warnings) {
		t.Errorf("CompileConfigLenient admitted the config but recorded no "+
			"reth-member warning; a silent tolerant admission leaves the operator "+
			"with no signal at all. Warnings: %v", cfg.Warnings)
	}
}

func warnsAboutRethMember6722(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "reth member (downgraded to warning on tolerant path)") {
			return true
		}
	}
	return false
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
