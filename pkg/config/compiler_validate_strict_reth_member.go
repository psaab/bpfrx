package config

import (
	"fmt"
	"sort"
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
// but a port. Three authored shapes break it, and all three were accepted
// before this gate:
//
//   - A member naming ITSELF as its redundant parent. Nothing is its own
//     parent; `RethToPhysical` maps the name to itself, `ResolveReth` becomes a
//     no-op, and no aliasing happens at all — yet the interface would present
//     as a member whose "parent" is the very row the deference silences.
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
// Rejecting these three is what lets the projection mark be the resolver's own
// answer instead of a re-derivation of it: after this gate a member has exactly
// one row, and the only question left is whether the RETH resolves onto THIS
// member or onto its peer-node sibling — which is `ResolveReth`, asked directly.
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
