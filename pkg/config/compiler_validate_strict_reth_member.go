package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateRethMemberStrict rejects a config whose `gigether-options
// redundant-parent` declarations do not describe a coherent redundant-ethernet
// membership (#6722).
//
// Junos models a redundant-ethernet interface as ONE interface described by
// several config nodes: the `rethN` node owns the L3 identity (units,
// addresses, security zone, CoS) and each member node contributes only a
// physical port. xpf implements exactly that. `ResolveReth` (types.go) collapses
// a RETH reference onto its LOCAL member's name, and `snapshotLinuxName`
// (pkg/dataplane/userspace/interfaces.go) applies it to the RETH's base row and
// to every one of its units — so on a bondless cluster `reth1`, `reth1.0` and
// `ge-0/0/1` are three rows describing ONE kernel netdev, and the RETH is the
// one of the three that names the zone.
//
// The Rust forwarding builder relies on that: its egress-zone agreement ledger
// (userspace-dp/src/afxdp/forwarding_build/interfaces.rs) treats each snapshot
// row as an INDEPENDENT observer of its ifindex and holds the ifindex ambiguous
// when two rows disagree. A member's row is not an independent observer — it is
// the RETH's port — so the Go builder marks it and the ledger withholds its
// (empty) vote. That deference is only sound while the member really is nothing
// but a port. Four authored shapes break it, and all four were accepted
// before this gate:
//
//   - A member naming ITSELF as its redundant parent. Nothing is its own
//     parent; `RethToPhysical` maps the name to itself, `ResolveReth` becomes a
//     no-op, and no aliasing happens at all — yet the interface would present
//     as a member whose "parent" is the very row the deference silences.
//
//   - A RETH naming a redundant parent of ITS OWN (#6722 round 7). A reth is
//     the L3 OWNER of a redundant pair, never a port, so this inverts the
//     relation the deference is built on. It is also the ONLY way the CANDIDATE
//     side of `rethProjectionMembers`' netdev comparison can be a `reth*` name,
//     and `snapshotLinuxName` resolves that side through `ResolveReth` — which
//     is what makes two further shapes satisfy the predicate, both measured
//     ACCEPTED by strict `CompileConfig` before this clause and both marking a
//     reth: `reth1 gigether-options redundant-parent reth0` (`RethToPhysical
//     [reth0] = reth1`, so reth0's rows land on the netdev name `reth1` that no
//     NIC carries, and reth1 is marked a projection of reth0), and the
//     two-cycle `ge-0/0/1 redundant-parent reth1` beside `reth1
//     redundant-parent ge-0/0/1`, where BOTH rows on the one ifindex are
//     marked. A non-cycling `reth1 redundant-parent ge-0/0/1` marks nothing but
//     still splits the two resolvers: `ResolveKernelIfName` (types.go) reads
//     `RethToPhysical` UNGATED for a dotted ref, so `ge-0/0/1.0` displays as
//     `reth1` while the dataplane binds `ge-0-0-1`.
//
//   - A member naming a parent that is not configured. There is no RETH row on
//     the shared netdev to defer TO, so the ifindex is left with no zone at all
//     and every transit flow out of it fails closed against the 0 sentinel —
//     silently, with a `redundant-parent` line that looks correct.
//
//   - A member carrying its OWN logical units. The gate fires on the PRESENCE
//     of a unit — Junos forbids logical-unit configuration on a reth child
//     outright, so a family-less `unit 0` is rejected for parity — and an
//     ADDRESSED unit is the case that fails OPEN.
//     `ge-0/0/1 unit 0 family inet address 10.9.9.1/30` beside `reth1 unit 0
//     family inet address 10.0.61.1/24` puts TWO independently addressed L3
//     units on ONE netdev: both install connected routes and local addresses on
//     that ifindex, but only the RETH's is zoned. The member's unit is a real,
//     independent L3 interface whose lack of a zone is a real operator
//     statement — measured, a flow to the member unit's subnet resolved the
//     RETH's zone and was PERMITTED where it must be denied. Junos does not
//     allow logical-unit configuration on a reth child for exactly this reason:
//     the child is L2-only and the reth owns the L3.
//
// Rejecting these four is what lets the projection mark be the resolver's own
// answer instead of a re-derivation of it: after this gate a member has exactly
// one row, and the only question left is whether the RETH resolves onto THIS
// member or onto its peer-node sibling — which is `ResolveReth`, asked directly.
//
// The reth clause is also what makes the case split over that comparison
// FINITE. `snapshotLinuxName` is `LinuxIfName(ResolveReth(x))` for a `reth*`
// name and `LinuxIfName(x)` otherwise, and either side of the comparison can
// be either, so the split is four-way, not two-way (#6722 round 7 — earlier
// rounds argued two branches and called them exhaustive). Forbidding a `reth*`
// CANDIDATE empties the two rows where the candidate is a reth, leaving the
// candidate side unconditionally `LinuxIfName(name)`; the remaining two rows
// are "the parent is a reth and resolves onto this member" (the designed case)
// and "neither is a reth and the two names merely canonicalize together", the
// second of which is rejected by `validateInterfaceNameCollisionStrict`
// (#5832). Only then is the two-branch reading of the predicate true.
//
// Strict on commit / commit-check (hard reject, so the operator sees the
// incoherence before it can silently mis-zone traffic); downgraded to a warning
// on the tolerant load / peer-sync paths (opts.lenientRethMember) so a config
// committed before this gate still boots (#1960 no-brick). The Go builder stays
// fail-CLOSED for the shapes that reach it that way: the mark is stamped on a
// member's BASE row only, so a grandfathered member unit still votes and still
// holds its ifindex ambiguous.
func validateRethMemberStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Deterministic walk so the first-error commit-check message is stable
	// across map-ordered runs, matching the sibling strict validators.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		ifc, ok := LookupInterface(cfg, name)
		if !ok || ifc.RedundantParent == "" {
			continue
		}
		parent := ifc.RedundantParent
		if parent == name {
			return fmt.Errorf(
				"interface %q names itself as its `gigether-options "+
					"redundant-parent`; an interface is not its own redundant "+
					"parent, and the self-reference resolves to a no-op that "+
					"leaves the interface presenting as a member of nothing — "+
					"name the redundant-ethernet interface this port belongs to, "+
					"or remove the redundant-parent line",
				name)
		}
		if strings.HasPrefix(name, "reth") {
			return fmt.Errorf(
				"interface %q is a redundant-ethernet interface and also names "+
					"`gigether-options redundant-parent %s`; a reth OWNS the L3 "+
					"identity of a redundant pair and is never a member port of "+
					"another interface, so this makes the L3 owner a port of "+
					"something else. `RethToPhysical` keys its map on the "+
					"redundant-parent NAME, so %q becomes what %q resolves to: with "+
					"a reth parent the parent's rows land on the netdev name %q, "+
					"which no NIC is ever named, and the snapshot builder then marks "+
					"%q as a PROJECTION of %q and withholds its egress-zone vote — "+
					"the L3 owner silenced in favour of its own supposed parent. "+
					"Name the physical ports (ge-/xe-/et-) as the members of %q and "+
					"remove the redundant-parent line from it",
				name, parent, name, parent, name, name, parent, name)
		}
		if _, ok := LookupInterface(cfg, parent); !ok {
			return fmt.Errorf(
				"interface %q names `gigether-options redundant-parent %s`, but "+
					"%q is not a configured interface; the redundant-ethernet "+
					"interface owns the L3 identity of the shared device, so "+
					"without it the port has no zone and every transit flow out "+
					"of it is dropped — configure %q, or correct the "+
					"redundant-parent name",
				name, parent, parent, parent)
		}
		if unitNum, ok := firstUnitNumber(ifc); ok {
			// Deliberately says what the gate KNOWS. It fires on the presence of
			// a logical unit, not on that unit being addressed: `unit 0` with no
			// family, and `unit 0 description member-port`, are rejected too, and
			// neither installs a route. The rejection is right for both (Junos
			// forbids logical-unit configuration on a reth child outright — this
			// is parity), so the message states the parity rule as the reason and
			// the addressed case as the consequence it guards against, rather
			// than asserting an address the config may not carry.
			return fmt.Errorf(
				"interface %q is a member of redundant-ethernet interface %q and "+
					"also configures `unit %d`; a reth member is an L2 port and "+
					"the reth owns the logical units, addresses and security zone "+
					"of the shared device, so Junos does not allow logical-unit "+
					"configuration on a reth child. Any address on that unit makes "+
					"it a second, independently addressed L3 interface on the SAME "+
					"device as the reth's unit — a competing connected route on an "+
					"ifindex where only the reth's row names a zone, so traffic to "+
					"the member unit's subnet is evaluated in the RETH's zone "+
					"— move the unit configuration onto %q",
				name, parent, unitNum, parent)
		}
	}
	return nil
}

// firstUnitNumber returns the lowest configured (non-nil) logical unit number on
// ifc. Deterministic so the commit-check message names the same unit on every
// run; a present-but-nil unit slot (tolerant load / HA config-sync, #3494/#5068)
// is not a configured unit.
func firstUnitNumber(ifc *InterfaceConfig) (int, bool) {
	lowest, found := 0, false
	RangeUnits(ifc, func(unitNum int, _ *InterfaceUnit) {
		if !found || unitNum < lowest {
			lowest, found = unitNum, true
		}
	})
	return lowest, found
}
