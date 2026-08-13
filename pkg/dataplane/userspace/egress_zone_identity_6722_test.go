package userspace

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722, the GO half — the DECIDING half. `stampEgressZones` (interfaces.go)
// answers, per ifindex, which security zone that ifindex EGRESSES into, and the
// Rust resolver (`ForwardingState::egress_zone_id`) reads the answer instead of
// adjudicating one from the rows.
//
// WHY THE ANSWER MOVED HERE. Rounds 4 through 9 built the answer on the Rust
// side by polling the snapshot rows — "does every row on this ifindex agree?" —
// and exempting the rows whose agreement or dissent turned out to be an
// artefact. NINE spellings of that exemption were holed in turn, each by a
// config shape it had not enumerated:
//
//	the raw `redundant-parent` string on the wire, re-derived from row names
//	co-resident row names
//	the SET of netdevs the parent's rows occupy
//	`snapshotLinuxName` of the parent's BASE row  (round 9)
//	  ... holed by: `ge-0/0/1` with units 0 and 1 in different zones, where the
//	      BASE row's zone is fanned up from unit 1 and votes against unit 0
//	  ... holed by: an AUTHORED dotted name `ge-0/0/1.100` aliasing `reth1.100`
//	  ... holed by: a WireGuard interface named as a reth member (fail-OPEN)
//	  ... holed by: #5832 + reth-member warnings combining on the tolerant path
//
// The pattern, not any one case, is the finding. A row's `Zone` is the OUTCOME
// of `buildInterfaceZoneMap`'s fan-up/fan-down derivation, and the outcome
// cannot say whether the operator zoned THIS identity or whether the row
// inherited another identity's words. Provenance is not reconstructible
// downstream, so it is carried: `authoredZoneRefs` records the literal
// `security-zone <z> interfaces <ref>` bindings, and the builder resolves them
// through the same aliasing it performs.
//
// The producible facts this file pins:
//
//  1. AUTHORED beats DERIVED on a shared ifindex. `ge-0/0/1` units 0/1 in `lan`
//     and `dmz`: ifindex 10 egresses `lan`, unit 0's authored zone, NOT the base
//     row's fanned-up `dmz` — and not a function of which zone name sorts first.
//  2. The reference bondless-RETH cluster still resolves its zone: `[ge-0/0/1=""
//     reth1="lan" reth1.0="lan"]` on ONE ifindex egresses `lan`.
//  3. An authored dotted member name aliasing a RETH's VLAN unit resolves the
//     RETH unit's authored zone rather than going ambiguous.
//  4. A tagged-parent netdev with no unit on it inherits its units' unanimous
//     zone (the reference cluster's `reth0`).
//  5. Contested ownership fails CLOSED: a tunnel named as a member, a reth named
//     as a member, a member carrying its own units, a canonicalization collision
//     with no reth in it, and two units of one interface on one netdev.
//  6. The four incoherent memberships are commit REJECTIONS.
//
// FAIL-ON-REVERT, per production hunk. Each row was MEASURED by reverting that
// hunk alone and recording which cell fires; the cells named are the ones that
// actually reddened, not the ones the hunk looks like it should reach.
//
//	rule 2 reads the ROW's zone instead of authored[]            -> A1, A2, J
//	authoredZoneRefs also fans a unit ref up to the base         -> A1, A2, J
//	drop the egressIdentitiesCohere gate                         -> E1/E2/E3/E4/E5
//	drop `ifc.Tunnel != nil` from egressMemberIsBarePort         -> E1 only
//	drop the unit check from egressMemberIsBarePort              -> E3 only
//	drop `HasPrefix(reth, "reth")` from egressRethMemberOf       -> E4 only
//	drop the unanimousUnitZone arm (rule 3)                      -> D
//	fire rule 3 even when a unit row IS on the ifindex           -> J
//	drop the `unitNum == 0` conjunct in the identity fold        -> E5 only
//	drop the quarantine exclusion from the authored bindings     -> the quarantine
//	                                                                cell in
//	                                                                zone_propagation_6722_test.go,
//	                                                                and F2
//	drop the unit clause of validateRethMemberStrict             -> G1/G2 (accepts)
//	drop the tunnel clause of validateRethMemberStrict           -> G3 (accepts)
//	drop the self clause of validateRethMemberStrict             -> H1 (accepts)
//	drop the parent-exists clause                                -> I1/I2 (accepts)
//	drop the reth clause of validateRethMemberStrict             -> L1/L2/L3 (accepts)
//	drop the `opts.lenientRethMember` downgrade                  -> G/H/I/L lenient halves
//
// The Rust half of the matrix is in userspace-dp/src/afxdp/forwarding/tests.rs:
// the corroboration, the DECIDED-empty override of unanimous rows, the
// conflicting-claim fail-close, the compatibility arm (both halves), and the
// resolver reading `ifindex_to_zone_id` instead of the ledger.

// egressZoneOfIfindex6722 returns the EgressZone every row on `ifindex` carries,
// failing if the rows disagree — the invariant the Rust side relies on (it
// treats a disagreement as version drift and fails closed) — or if no row
// resolved to that ifindex at all, which would otherwise let a "no zone"
// assertion pass against an empty snapshot.
func egressZoneOfIfindex6722(t *testing.T, snaps []InterfaceSnapshot, ifindex int) string {
	t.Helper()
	seen := map[string][]string{}
	for _, s := range snaps {
		if s.Ifindex == ifindex {
			seen[s.EgressZone] = append(seen[s.EgressZone], s.Name)
		}
	}
	if len(seen) == 0 {
		t.Fatalf("no snapshot row resolved to ifindex %d; the stub was primed with "+
			"a Linux name no row carries, so this cell is asserting about nothing",
			ifindex)
	}
	if len(seen) > 1 {
		keys := make([]string, 0, len(seen))
		for z := range seen {
			keys = append(keys, z)
		}
		sort.Strings(keys)
		t.Fatalf("rows on ifindex %d carry DIFFERENT EgressZone values %v (%v); "+
			"stampEgressZones must stamp one answer per ifindex, and the Rust "+
			"builder reads a disagreement as version drift and fails closed",
			ifindex, keys, seen)
	}
	for z := range seen {
		return z
	}
	return ""
}

func assertEgressZone6722(t *testing.T, snaps []InterfaceSnapshot, ifindex int, want, why string) {
	t.Helper()
	if got := egressZoneOfIfindex6722(t, snaps, ifindex); got != want {
		t.Errorf("egress zone of ifindex %d = %q, want %q: %s", ifindex, got, want, why)
	}
}

// A: AUTHORED beats DERIVED on a shared ifindex.
//
// A1 is the round-10 blocking regression in its own right. `buildInterfaceZoneMap`
// writes `out[base]` first-write-wins over SORTED ZONE NAMES, so the `ge-0/0/1`
// base row carries "dmz" — a zone no identity on that netdev was ever put in —
// purely because "dmz" sorts before "lan". Unit 0 collapses onto the base netdev
// and carries the operator's real "lan". The row-polling ledger read that as a
// disagreement and answered the 0 sentinel, turning every permit to that
// interface into a deny; origin/master answered `lan`.
//
// A2 and A3 are the two CONTROLS the round-10 report asked for, and they are
// what separates "the fix works" from "the fix hard-codes lan":
//
//	A2 renames dmz to "aaa" so the OTHER unit's zone sorts first. The derived
//	   base zone changes from "dmz" to "aaa"; the answer must not move.
//	A3 drops unit 1 entirely. A single-unit interface was never affected and
//	   must still resolve lan.
func TestAuthoredUnitZoneBeatsTheDerivedBaseZone_6722(t *testing.T) {
	// A1.
	zoneMap, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.62.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone dmz interfaces ge-0/0/1.1",
	}, map[string]int{"ge-0-0-1": 10, "ge-0-0-1.1": 11},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	// The precondition, measured rather than assumed: the base row really does
	// carry a zone the operator never wrote for it. Without this the cell below
	// would pass on a snapshot where nothing ever disagreed.
	if got := zoneMap["ge-0/0/1"]; got != "dmz" {
		t.Fatalf("precondition: buildInterfaceZoneMap[ge-0/0/1] = %q, want %q — the "+
			"fanned-up base zone is the whole subject of this cell", got, "dmz")
	}
	if got := snapByName6722(t, snaps, "ge-0/0/1").Zone; got != "dmz" {
		t.Fatalf("precondition: the ge-0/0/1 BASE row's Zone = %q, want %q", got, "dmz")
	}
	if base, unit0 := snapByName6722(t, snaps, "ge-0/0/1"), snapByName6722(t, snaps, "ge-0/0/1.0"); base.Ifindex != 10 || unit0.Ifindex != 10 {
		t.Fatalf("precondition: ge-0/0/1 ifindex = %d and ge-0/0/1.0 ifindex = %d, "+
			"want 10 and 10 — a non-VLAN unit 0 collapses onto its base netdev, "+
			"which is what puts a derived zone and an authored one on ONE ifindex",
			base.Ifindex, unit0.Ifindex)
	}
	assertEgressZone6722(t, snaps, 10, "lan",
		"unit 0 is the identity the operator zoned on this netdev; the base row's "+
			"\"dmz\" is a restatement of the sentence written about ge-0/0/1.1, which "+
			"lives on its own netdev. Answering 0 here is the round-10 fail-CLOSED "+
			"regression (master answers lan); answering dmz would make the "+
			"adjudicated to-zone a function of zone NAMING")
	assertEgressZone6722(t, snaps, 11, "dmz",
		"unit 1 is alone on its own VLAN-less netdev and keeps its authored zone")

	// A2 — the alphabetical control. Rename dmz to "aaa" so the derived base
	// zone flips; the answer must not.
	zoneMapA, snapsA := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.62.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone aaa interfaces ge-0/0/1.1",
	}, map[string]int{"ge-0-0-1": 10, "ge-0-0-1.1": 11},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})
	if got := zoneMapA["ge-0/0/1"]; got != "aaa" {
		t.Fatalf("control A2 precondition: buildInterfaceZoneMap[ge-0/0/1] = %q, "+
			"want %q — the derived base zone must actually have CHANGED, or this "+
			"control is not varying the thing it claims to vary", got, "aaa")
	}
	assertEgressZone6722(t, snapsA, 10, "lan",
		"renaming the sibling's zone so it sorts FIRST must not move the answer; "+
			"the answer comes from the authored binding on ge-0/0/1.0, not from the "+
			"sort order buildInterfaceZoneMap used to pick a base zone")

	// A3 — the single-unit control. Never affected, must stay lan.
	_, snapsS := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
	}, map[string]int{"ge-0-0-1": 10},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})
	assertEgressZone6722(t, snapsS, 10, "lan",
		"an interface with a single unit 0 has one identity on its netdev and "+
			"resolves its authored zone, exactly as before this change")
}

// B: the reference bondless-RETH LAN — the shape #6722 exists to protect.
// `ResolveReth` collapses `reth1` onto its member's netdev, so the UNZONED
// member row and the zoned `reth1` / `reth1.0` rows are ONE ifindex. The member
// is a bare L2 port of the reth, so the two identities cohere and the reth's
// authored zone decides.
//
// Counting the member's "no zone" as dissent is what blackholed every WAN->LAN,
// sfmix->LAN and tunnel->LAN transit flow on the reference cluster: zone 0 is
// the sentinel `evaluate_policy_result_l3_aware` matches no rule against.
func TestBondlessRethMemberDoesNotContestTheRethsZone_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	member := snapByName6722(t, snaps, "ge-0/0/1")
	base := snapByName6722(t, snaps, "reth1")
	unit0 := snapByName6722(t, snaps, "reth1.0")
	if member.Ifindex != 24 || base.Ifindex != 24 || unit0.Ifindex != 24 {
		t.Fatalf("precondition: ge-0/0/1=%d reth1=%d reth1.0=%d, want 24/24/24 — "+
			"three rows on ONE netdev is the whole subject",
			member.Ifindex, base.Ifindex, unit0.Ifindex)
	}
	if member.Zone != "" {
		t.Fatalf("precondition: the member row's Zone = %q, want empty — Junos "+
			"zones the RETH, not the port", member.Zone)
	}
	assertEgressZone6722(t, snaps, 24, "lan",
		"the member is a bare L2 port of reth1, so the two identities describe ONE "+
			"device coherently and the reth's authored zone decides. Answering 0 here "+
			"blackholes every WAN->LAN transit flow on the reference HA cluster")
}

// C: an authored DOTTED member name that aliases the RETH's VLAN unit.
//
// Authored dotted interface NAMES are legal, and `ResolveReth("reth1")` selects
// `ge-0/0/1`, so `reth1.100` resolves onto `ge-0-0-1.100` — exactly where the
// authored interface named `ge-0/0/1.100` lands. The round-9 predicate compared
// only BASE rows, so it never exempted the dotted name and the ifindex went
// ambiguous where master resolved the operator's zone.
//
// This is the cell that shows why the answer had to stop being a row
// classification: the dotted name is a real, separate configured interface AND
// an alias of a reth unit, and no amount of inspecting the two rows
// distinguishes it from a genuine conflict. Resolving the AUTHORED binding
// through the aliasing does.
func TestAuthoredDottedMemberNameResolvesTheRethUnitsZone_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/1.100 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1.100",
	}, map[string]int{"ge-0-0-1": 31, "ge-0-0-1.100": 32},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	dotted := snapByName6722(t, snaps, "ge-0/0/1.100")
	rethUnit := snapByName6722(t, snaps, "reth1.100")
	if dotted.Ifindex != 32 || rethUnit.Ifindex != 32 {
		t.Fatalf("precondition: ge-0/0/1.100=%d reth1.100=%d, want 32/32 — the "+
			"authored dotted NAME and the reth's VLAN unit must land on one netdev",
			dotted.Ifindex, rethUnit.Ifindex)
	}
	if dotted.Zone != "" || rethUnit.Zone != "lan" {
		t.Fatalf("precondition: ge-0/0/1.100 Zone=%q reth1.100 Zone=%q, want \"\" "+
			"and \"lan\" — the rows must genuinely DISAGREE, or a row-polling "+
			"ledger would never have gone ambiguous here", dotted.Zone, rethUnit.Zone)
	}
	assertEgressZone6722(t, snaps, 32, "lan",
		"the operator EXPLICITLY zoned reth1.100; ge-0/0/1.100 is a bare port of "+
			"reth1 and adds no competing L3 identity. Answering 0 strips the "+
			"destination zone from an explicitly zoned interface (master: lan)")
}

// D: the TRUNK-CARRIER rule, and the reason it exists.
//
// The reference cluster's `reth0` is `vlan-tagging` with units 50 and 80, both
// zoned `wan`. Neither unit is on the base netdev — a VLAN unit lands on
// `<dev>.<vlan>` — so ifindex 25 carries only BASE rows and no authored binding
// resolves to it. Master answers `wan` there, from the base row's fanned-up
// zone. Rule 3 keeps that answer without reopening cell A, because it fires only
// when NO unit row is on the ifindex.
//
// This cell is the reason rule 3 is not folded into rule 2: with rule 3 removed,
// ifindex 25 fails closed against both master and round 9's head.
func TestTaggedParentNetdevInheritsItsUnitsUnanimousZone_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 50 vlan-id 50 family inet address 172.16.50.8/24",
		"set interfaces reth0 unit 80 vlan-id 80 family inet address 172.16.80.8/24",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone wan interfaces reth0.50",
		"set security zones security-zone wan interfaces reth0.80",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24, "ge-0-0-2": 25, "ge-0-0-2.50": 26, "ge-0-0-2.80": 27},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-2": "02:bf:72:01:00:02"})

	for _, name := range []string{"reth0.50", "reth0.80"} {
		if got := snapByName6722(t, snaps, name).Ifindex; got == 25 {
			t.Fatalf("precondition: %s resolved to ifindex 25, the BASE netdev; a "+
				"VLAN unit must land on its own <dev>.<vlan> device or rule 3's "+
				"'no unit row on this ifindex' condition is not being exercised", name)
		}
	}
	assertEgressZone6722(t, snaps, 25, "wan",
		"reth0's base netdev carries no logical unit of its own, so it is a bare "+
			"tagged-parent carrier and takes the zone its units unanimously name — "+
			"the same answer origin/master gives")
	assertEgressZone6722(t, snaps, 24, "lan", "the reference LAN reth is unaffected")
	assertEgressZone6722(t, snaps, 26, "wan", "reth0.50 owns its own netdev")
	assertEgressZone6722(t, snaps, 27, "wan", "reth0.80 owns its own netdev")
}

// D2: the TRUNK-CARRIER rule, driven from the SHIPPED cluster config itself.
//
// Cell D above builds the shape by hand. This one parses
// `docs/ha-cluster-userspace.conf` — the file
// `test/incus/loss-userspace-cluster.env` points every HA smoke at — through
// the real parser, the real `${node}` group expansion and the real
// `CompileConfig`, and asserts the two ifindexes the reference topology
// depends on.
//
// It exists because rule 3 made that file a LIVE DEPENDENCY of a rule this
// round introduces, not merely a regression check: an edit to the conf that
// moved a zone binding off `reth0.50`/`reth0.80`, or added an untagged unit to
// `reth0`, would silently take ifindex 25's zone away. Without this cell that
// shows up as a smoke failure on a cluster; with it, as a unit-test failure
// here.
func TestShippedClusterConfigResolvesBothRethIfindexes_6722(t *testing.T) {
	src, err := os.ReadFile("../../../docs/ha-cluster-userspace.conf")
	if err != nil {
		t.Fatalf("read the shipped cluster config: %v", err)
	}
	tree, errs := config.NewParser(string(src)).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse docs/ha-cluster-userspace.conf: %v", errs)
	}
	// The file is `apply-groups "${node}"`; node 0 is the topology the smoke
	// targets and the one every #6722 measurement in this issue quotes.
	if err := tree.ExpandGroupsWithVars(map[string]string{"node": "node0"}); err != nil {
		t.Fatalf("ExpandGroupsWithVars: %v", err)
	}

	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	ifindexOf := map[string]int{
		"ge-0-0-1": 24, "ge-0-0-2": 25, "ge-0-0-2.50": 26, "ge-0-0-2.80": 27,
	}
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		idx, ok := ifindexOf[linuxName]
		if !ok {
			return 0, 0, "", nil
		}
		return idx, 1500, "02:bf:72:01:00:01", nil
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig on the shipped cluster config: %v", err)
	}
	snaps := buildInterfaceSnapshots(cfg)

	// Preconditions, so a conf edit that moves these bindings fails LOUDLY here
	// rather than making the assertions below vacuous.
	if got := snapByName6722(t, snaps, "reth1").Zone; got != "lan" {
		t.Fatalf("precondition: reth1 Zone = %q, want %q — the shipped config no "+
			"longer zones the LAN reth and cell D2 is measuring something else", got, "lan")
	}
	for _, unit := range []string{"reth0.50", "reth0.80"} {
		row := snapByName6722(t, snaps, unit)
		if row.Zone != "wan" {
			t.Fatalf("precondition: %s Zone = %q, want %q", unit, row.Zone, "wan")
		}
		if row.Ifindex == 25 {
			t.Fatalf("precondition: %s landed on ifindex 25, the BASE netdev; rule 3 "+
				"requires the tagged units to live on their OWN devices", unit)
		}
	}

	assertEgressZone6722(t, snaps, 24, "lan",
		"the LAN reth and its member port are one device; this is the ifindex whose "+
			"loss blackholed every WAN->LAN, sfmix->LAN and tunnel->LAN transit flow")
	assertEgressZone6722(t, snaps, 25, "wan",
		"reth0 is `vlan-tagging` with only tagged units, so its base netdev carries "+
			"no logical unit and takes the zone its units unanimously name — the same "+
			"answer origin/master gives. Losing it is a fail-CLOSED regression against "+
			"both master and the previous head")
}

// E: CONTESTED OWNERSHIP fails closed. Five shapes in which two identities
// claim one netdev without a valid reth membership between them. All five are
// admitted on the TOLERANT load / peer-sync path (#1960 no-brick), where the
// gates that reject them at commit are downgraded to warnings — so this is not a
// theoretical set, it is what a grandfathered config presents.
//
// E1 and E4 are the two the round-10 report measured as DELTAS against master in
// the permissive direction on the previous head.
func TestContestedNetdevOwnershipFailsClosed_6722(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		ifindex int
		links   map[string]int
		why     string
	}{
		{
			// E1: a WireGuard tunnel named as a reth member. The reth validator
			// rejected member UNITS but not a base-level tunnel, and WireGuard's
			// own interface-level validation accepts the shape. `ResolveReth`
			// then puts reth1's rows on the TUN, whose MAC gate admits it via
			// `iface.tunnel.then_some([0; 6])` — so wg0 RECEIVED reth1's zone.
			// Master answers 0. This was the round's only FAIL-OPEN.
			name: "wireguard-tunnel-as-member",
			lines: []string{
				"set interfaces wg0 gigether-options redundant-parent reth1",
				"set interfaces wg0 tunnel mode wireguard",
				"set interfaces wg0 tunnel wireguard listen-port 51820",
				"set interfaces wg0 tunnel wireguard private-key b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
				"set interfaces wg0 tunnel wireguard peer a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 allowed-ips 10.66.0.0/24",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
				"set routing-options static route 10.66.0.0/24 next-hop wg0",
			},
			ifindex: 41,
			links:   map[string]int{"wg0": 41},
			why: "a WireGuard endpoint is an independently ROUTED L3 identity, not " +
				"an L2 port; inheriting reth1's zone would adjudicate its transit " +
				"under a policy written for the LAN reth",
		},
		{
			// E2: a reth naming a redundant parent of its own, combined with a
			// #5832 canonicalization collision. R(reth0)=ge-0/0/1 and
			// R(reth1)=ge-0-0-1 both canonicalize onto ONE netdev, so reth0's
			// authored zone would cross onto the independently authored reth1
			// side. Master answers 0.
			name: "reth-as-member-plus-canonical-collision",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
				"set interfaces ge-0-0-1 gigether-options redundant-parent reth1",
				"set interfaces reth1 gigether-options redundant-parent reth0",
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces reth0 unit 0 family inet address 10.0.62.1/24",
				"set security zones security-zone lan interfaces reth0",
			},
			ifindex: 31,
			links:   map[string]int{"ge-0-0-1": 31},
			why: "a reth is the L3 OWNER of a redundant pair and never a member " +
				"port, so reth1 is not a bare port of reth0 and the two sides are " +
				"independent claims on one device",
		},
		{
			// E3: a member carrying its OWN addressed unit. Two independently
			// addressed L3 units on one netdev, only one of them zoned. This was
			// the measured round-7 fail-open.
			name: "member-with-its-own-addressed-unit",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/30",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
			ifindex: 24,
			links:   map[string]int{"ge-0-0-1": 24},
			why: "the member's unit installs its own connected route and local " +
				"address on the shared ifindex, so its lack of a zone is a real " +
				"operator statement about a real L3 interface",
		},
		{
			// E4: a canonicalization collision with NO reth anywhere (#5832 row
			// 2). The deference premise — "the member is a port, the reth owns
			// the L3" — is simply absent when neither side is a reth.
			//
			// This cell is a DELIBERATE behaviour change beyond #6722's four
			// round-10 findings, argued separately and measured on all three
			// trees rather than predicted:
			//
			//	origin/master (edefb7570)   egress_zone_id(24) = 0
			//	PR head c9b020695           resolves `lan`   <-- fail-OPEN
			//	here                        egress_zone_id(24) = 0
			//
			// At c9b020695 the collision row is MARKED
			// (`RethProjection = true`, measured), its empty vote is withheld,
			// and the ledger resolves the zone the operator wrote on the OTHER
			// name for that same device. The PR's own doc admitted that as a
			// fail-OPEN delta. So this RESTORES master rather than changing it:
			// what it retires is a delta an earlier round of this PR introduced.
			// It is called out because the config is ACCEPTED on the tolerant
			// path, so the change is observable to an operator who has one.
			name: "canonical-collision-without-a-reth",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent ge-0-0-1",
				"set interfaces ge-0-0-1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces ge-0-0-1",
			},
			ifindex: 24,
			links:   map[string]int{"ge-0-0-1": 24},
			why: "neither name is a reth, so nothing designates either as the " +
				"other's port; two independently authored interfaces on one device " +
				"identify no single zone",
		},
		{
			// E5: two units of ONE interface-level tunnel on one netdev.
			// `TunnelNameMap` maps every unit of `wg0` onto the `wg0` device, so
			// `wg0`, `wg0.0` and `wg0.1` are one ifindex — and the operator zoned
			// only one of the two logical interfaces.
			name: "two-tunnel-units-on-one-device",
			lines: []string{
				"set interfaces wg0 tunnel mode wireguard",
				"set interfaces wg0 tunnel wireguard listen-port 51820",
				"set interfaces wg0 tunnel wireguard private-key b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
				"set interfaces wg0 tunnel wireguard peer a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 allowed-ips 10.66.0.0/24",
				"set interfaces wg0 unit 0 family inet address 10.5.5.1/30",
				"set interfaces wg0 unit 1 family inet address 10.6.6.1/30",
				"set security zones security-zone vpnb interfaces wg0.1",
			},
			ifindex: 41,
			links:   map[string]int{"wg0": 41},
			why: "wg0.0 and wg0.1 are two logical interfaces the kernel gives one " +
				"device; the operator zoned one of them and left the other out, and " +
				"that omission is a statement",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileWithStubbedLinks6722(t, tc.lines, tc.links,
				map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}, true)
			snaps := buildInterfaceSnapshots(cfg)
			// The precondition that makes the cell non-vacuous: some row on the
			// ifindex must carry a NONZERO zone, or "no egress zone" would be
			// indistinguishable from a snapshot with no zones in it at all.
			zoned := false
			for _, s := range snaps {
				if s.Ifindex == tc.ifindex && s.Zone != "" {
					zoned = true
				}
			}
			if !zoned {
				t.Fatalf("precondition: no row on ifindex %d carries a zone, so a "+
					"\"\" answer here proves nothing", tc.ifindex)
			}
			assertEgressZone6722(t, snaps, tc.ifindex, "", tc.why)
		})
	}
}

// F: the field must survive the wire, and the StableZoneID quarantine must
// reach it.
//
// F1: the Rust resolver reads a JSON key. A rename or an `omitempty` that
// dropped a real answer would leave the helper reading "" and failing closed on
// every reth cluster — green in Go, blackholed in production.
//
// F2: `quarantineCollidingZones` unzones the interfaces of a colliding zone
// expressly so they fail CLOSED. It runs AFTER buildInterfaceSnapshots, so it
// must blank the EGRESS answer too — the answer is a separate field and rule 3
// can put a zone on an ifindex whose rows are all unzoned.
func TestEgressZoneCrossesTheWireAndTheQuarantine_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	raw, err := json.Marshal(snapByName6722(t, snaps, "ge-0/0/1"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob := string(raw)
	if !strings.Contains(blob, `"egress_zone":"lan"`) {
		t.Fatalf("serialized member row does not carry egress_zone=lan; the Rust "+
			"resolver reads this key (`InterfaceSnapshot::egress_zone`, "+
			"userspace-dp/src/protocol/snapshot.rs) and an absent one fails CLOSED "+
			"on every bondless RETH cluster. Got: %s", truncate6722(blob, 400))
	}

	// F2 — the quarantine. Two zone names that collide on the same StableZoneID
	// slot; the later-sorting one is quarantined and its interfaces unzoned.
	// Lenient: a StableZoneID collision is REJECTED at commit (#3075), so the
	// quarantine only ever sees a config that arrived through the tolerant load /
	// peer-sync path.
	cfgQ := compileWithStubbedLinks6722(t, quarantineCollisionLines6722(t), map[string]int{
		"ge-0-0-1": 24, "ge-0-0-2": 25,
	}, map[string]string{
		"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-2": "02:bf:72:01:00:02",
	}, true)
	ucfg := deriveUserspaceConfig(cfgQ)
	snapQ, err := buildSnapshot(cfgQ, ucfg, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snapQ.zoneIDCollisions) == 0 {
		t.Fatalf("precondition: no zone-ID collision was quarantined, so this cell " +
			"is not exercising the quarantine at all")
	}
	dropped := snapQ.zoneIDCollisions[0].Quarantined
	for _, s := range snapQ.Interfaces {
		if s.EgressZone == dropped {
			t.Errorf("interface %q still carries EgressZone %q, a zone the "+
				"StableZoneID quarantine DROPS from the published set. "+
				"stampEgressZones excludes a to-be-quarantined binding before it "+
				"decides, precisely so these interfaces fail CLOSED; naming a "+
				"dropped zone here would also fail the Rust corroboration, so the "+
				"ifindex would lose its zone for the wrong reason", s.Name, dropped)
		}
	}
}

// G: incoherent memberships as COMMIT REJECTIONS. G1/G2 put two independently
// addressed L3 units on one netdev; G3 is the round-10 addition — a base-level
// TUNNEL on a member, which the unit clause cannot see because a WireGuard
// interface configures no logical unit at all.
func TestRethMemberWithItsOwnL3IdentityIsRejected_6722(t *testing.T) {
	cases := []struct {
		name     string
		lines    []string
		fragment string
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
			fragment: "also configures `unit",
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
			fragment: "also configures `unit",
		},
		{
			// G3: no logical unit anywhere on wg0, so the unit clause cannot
			// reach it — this sub-case is what makes the tunnel clause
			// independently load-bearing.
			name: "wireguard-tunnel-as-member",
			lines: []string{
				"set interfaces wg0 gigether-options redundant-parent reth1",
				"set interfaces wg0 tunnel mode wireguard",
				"set interfaces wg0 tunnel wireguard listen-port 51820",
				"set interfaces wg0 tunnel wireguard private-key b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
				"set interfaces wg0 tunnel wireguard peer a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 allowed-ips 10.66.0.0/24",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
			fragment: "also configures a `tunnel`",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRethMemberRejected6722(t, tc.lines, tc.fragment)
		})
	}
}

// H: a member naming ITSELF. `RethToPhysical` maps the name to itself, so
// `ResolveReth` is a no-op and the interface is a member of nothing — while
// still presenting as one.
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
// netdev to take the L3 identity from, so the ifindex is left with no zone and
// every transit flow out of it is dropped — silently, behind a
// `redundant-parent` line that looks correct.
//
// The `bare-prefix` sub-case is the one an earlier string re-derivation was
// holed by: `reth10` is an ordinary Junos reth name that textually contains
// `reth1`. It is rejected here for the plain reason that `reth1` is undefined,
// and the sibling that names the DECLARED `reth10` compiles and resolves its
// zone — the control that keeps this cell from passing by nothing ever
// compiling.
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
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth10",
		"set interfaces reth10 redundant-ether-options redundancy-group 2",
		"set interfaces reth10 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth10",
	}, map[string]int{"ge-0-0-2": 25},
		map[string]string{"ge-0-0-2": "02:bf:72:01:00:02"})
	assertEgressZone6722(t, snaps, 25, "lan",
		"reth10 IS configured and resolves onto ge-0/0/2, so the rejection "+
			"sub-tests above are measuring the parent's identity rather than a "+
			"blanket refusal to compile")
}

// J: the SELF-PARENT lenient-path cell. `RethToPhysical` maps a self-naming
// interface to itself, so any comparison of "does the parent resolve where this
// interface resolves" is trivially true. The commit gate rejects the shape (cell
// H); on the tolerant path it is admitted with a warning, and what holds the
// line there is that `egressRethMemberOf` requires a `reth*` PARENT — `st0` is
// not one, so `st0` is not a member of itself and the identities on its netdev
// are judged on their own.
//
// The measured consequence: `st0` (base, zone fanned up from st0.1) and `st0.0`
// (unzoned) share ifindex 42, no authored binding resolves there, and a unit row
// IS on the ifindex, so rule 3 does not fire either. Fails closed.
func TestSelfParentOnTheLenientPathStillFailsClosed_6722(t *testing.T) {
	cfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces st0 gigether-options redundant-parent st0",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone vpnb interfaces st0.1",
	}, map[string]int{"st0": 42, "st0.1": 43}, map[string]string{}, true)
	snaps := buildInterfaceSnapshots(cfg)

	if got := snapByName6722(t, snaps, "st0").Zone; got != "vpnb" {
		t.Fatalf("precondition: the st0 BASE row's Zone = %q, want %q — "+
			"buildInterfaceZoneMap's out[base] write is what makes this shape "+
			"interesting", got, "vpnb")
	}
	assertEgressZone6722(t, snaps, 42, "",
		"st0.0 is in no zone and the base row's vpnb is fanned up from st0.1, "+
			"which lives on its own netdev; a self-named redundant parent is not a "+
			"reth membership and cannot make one identity the other's port")
	assertEgressZone6722(t, snaps, 43, "vpnb",
		"st0.1 owns its own netdev and keeps its authored zone — the gate must be "+
			"scoped to the contested ifindex")
}

// L: a `reth*` interface that declares a `redundant-parent` of its OWN. A reth
// is the L3 OWNER of a redundant pair and never a member port, so this inverts
// the relation the whole model rests on.
//
// Measured at 195fcad51 with strict `CompileConfig`, against origin/master
// (edefb7570) as the control, all three were ACCEPTED — and the first two put a
// reth's rows on a netdev name no NIC carries, or marked the L3 owner as a
// projection of its own supposed parent. The third splits the two resolvers:
// `ResolveKernelIfName` (types.go) reads `RethToPhysical` UNGATED for a dotted
// ref, so `ge-0/0/1.0` DISPLAYS as `reth1` while the dataplane binds
// `ge-0-0-1`.
//
// FAIL-ON-REVERT: drop the reth clause from `validateRethMemberStrict` and all
// three sub-cases compile. The control at the end keeps that from passing by
// nothing ever compiling.
func TestRethNamingARedundantParentIsRejected_6722(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "reth-names-a-reth",
			lines: []string{
				"set interfaces reth1 gigether-options redundant-parent reth0",
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth0",
			},
		},
		{
			name: "two-cycle",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces reth1 gigether-options redundant-parent ge-0/0/1",
				"set security zones security-zone lan interfaces ge-0/0/1",
			},
		},
		{
			name: "reth-names-a-physical",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
				"set interfaces reth1 gigether-options redundant-parent ge-0/0/1",
				"set security zones security-zone lan interfaces ge-0/0/1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRethMemberRejected6722(t, tc.lines, "is a redundant-ethernet interface")
		})
	}

	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})
	assertEgressZone6722(t, snaps, 24, "lan",
		"the reth clause must reject a reth that declares a redundant-parent "+
			"WITHOUT rejecting the ordinary membership that declares it on the "+
			"physical port — without this control the sub-tests above would pass on "+
			"a blanket refusal to compile anything with a reth in it")
}

// M: the PEER NODE's member. A two-node cluster config declares BOTH nodes'
// members, and only the one `ResolveReth` actually selects on this node shares
// the reth's netdev. The peer's member resolves to a Linux name that does not
// exist here, so it never reaches an ifindex at all — which is why "declares
// redundant-parent" was never the right question and the answer had to come
// from the resolver.
func TestPeerNodeRethMemberDoesNotReachAnIfindex_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-7/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	peer := snapByName6722(t, snaps, "ge-7/0/1")
	if peer.Ifindex != 0 {
		t.Fatalf("precondition: ge-7/0/1 resolved to ifindex %d; the peer node's "+
			"netdev does not exist locally and must resolve to 0, or this cell is "+
			"not modelling a two-node config", peer.Ifindex)
	}
	assertEgressZone6722(t, snaps, 24, "lan",
		"the LOCAL member is the one reth1 resolves onto; declaring both nodes' "+
			"members must not make the shared ifindex contested")
}

// quarantineCollisionLines6722 builds a config with two zone names that collide
// on one StableZoneID slot, so quarantineCollidingZones drops the later-sorting
// one. Searching for the pair rather than hard-coding it keeps the cell from
// going vacuous if the hash changes.
func quarantineCollisionLines6722(t *testing.T) []string {
	t.Helper()
	base := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.62.1/24",
	}
	for _, pair := range zoneIDCollisionPairs6722() {
		names := []string{pair[0], pair[1]}
		if len(config.QuarantinedZoneNames(names)) == 0 {
			continue
		}
		return append(append([]string{}, base...),
			"set security zones security-zone "+pair[0]+" interfaces ge-0/0/1.0",
			"set security zones security-zone "+pair[1]+" interfaces ge-0/0/2.0",
		)
	}
	t.Skip("no StableZoneID collision pair found in the search space; the " +
		"quarantine cell cannot be built without one")
	return nil
}

func zoneIDCollisionPairs6722() [][2]string {
	byID := map[uint16]string{}
	out := [][2]string{}
	for i := 0; i < 4096; i++ {
		name := "z" + itoa6722(i)
		id := config.StableZoneID(name)
		if prev, ok := byID[id]; ok {
			out = append(out, [2]string{prev, name})
			if len(out) >= 4 {
				return out
			}
			continue
		}
		byID[id] = name
	}
	return out
}

func itoa6722(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

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

func truncate6722(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
