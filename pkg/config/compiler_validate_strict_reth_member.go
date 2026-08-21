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
// The dataplane relies on that. `stampEgressZones`
// (pkg/dataplane/userspace/interfaces.go) decides which security zone an ifindex
// EGRESSES into, and an ifindex claimed by two configured identities identifies
// no single zone unless one of them is the other's member port — the one
// relation under which two identities are DESIGNED to be one netdev. The
// deference is only sound while the member really is nothing but a port, so the
// conditions of the model ARE the conditions of the deference. Five authored
// shapes break it, and all five were accepted before this gate:
//
//   - A member naming ITSELF as its redundant parent. Nothing is its own
//     parent; `RethToPhysical` maps the name to itself, `ResolveReth` becomes a
//     no-op, and no aliasing happens at all — yet the interface would present
//     as a member whose "parent" is the very row the deference defers to.
//
//   - A RETH naming a redundant parent of ITS OWN (#6722 round 7). A reth is
//     the L3 OWNER of a redundant pair, never a port, so this inverts the
//     relation the deference is built on. Measured ACCEPTED by strict
//     `CompileConfig` before this clause: `reth1 gigether-options
//     redundant-parent reth0` gives `RethToPhysical[reth0] = reth1`, so reth0's
//     rows land on the netdev name `reth1` that no NIC carries. A non-cycling
//     `reth1 redundant-parent ge-0/0/1` splits the two resolvers instead:
//     `ResolveKernelIfName` (types.go) reads `RethToPhysical` UNGATED for a
//     dotted ref, so `ge-0/0/1.0` displays as `reth1` while the dataplane binds
//     `ge-0-0-1`.
//
//   - A member naming a parent that is not configured. There is no RETH row on
//     the shared netdev to take the L3 identity from, so the ifindex is left
//     with no zone at all and every transit flow out of it fails closed —
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
//     RETH's zone and was PERMITTED where it must be denied.
//
//   - A member carrying its own `tunnel` stanza (#6722 round 10). An
//     interface-level WireGuard or GRE tunnel is an independently routed L3
//     endpoint with its own peers and routes, and it declares NO logical unit,
//     so the unit clause above cannot see it. Measured: `wg0 redundant-parent
//     reth1` puts reth1, reth1.0 and wg0 on the TUN's ifindex and wg0 RECEIVED
//     the LAN reth's zone, where origin/master answered none.
//
// Rejecting these five is what lets the runtime deference be a single positive
// rule instead of a growing list of exceptions: after this gate a member is a
// bare port, and `egressMemberIsBarePort`
// (pkg/dataplane/userspace/interfaces.go) states the same rule in the same terms
// for the tolerant load / peer-sync path, where these rejections are downgraded
// to warnings (#1960 no-brick) and a grandfathered config still presents them.
//
// Strict on commit / commit-check (hard reject, so the operator sees the
// incoherence before it can silently mis-zone traffic); downgraded to a warning
// on the tolerant paths via opts.lenientRethMember. What bounds a shape that
// reaches the builder that way is the runtime half above: an incoherent
// membership leaves the shared device with two independent claimants, so its
// ifindex identifies no zone and fails CLOSED.
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
			// The consequences are stated as POSSIBILITIES on purpose, and each
			// one names the sub-branch it belongs to. Which of them follows
			// depends on the rest of the config — on whether this interface wins
			// `RethToPhysical`'s scoring against the parent's real physical
			// ports, and on whether the parent is itself a reth — and every
			// earlier spelling asserted one unconditionally and was measured
			// false for a shape this very gate rejects (#6722 rounds 8 and 9: a
			// reth parent that already has a real member marks nothing; a
			// two-name cycle whose reth has a lower-named third member marks
			// neither cycle row). What IS unconditional is the entry into the
			// scoring and the contested device, so those two are stated flatly.
			//
			// The remedy names %q = `name` — the interface carrying the
			// offending line — in both sub-branches. Round 9 pointed it at
			// `parent`, which reads as advice to edit a physical port that has no
			// members and no redundant-parent line of its own (#6722 round 10 N2).
			return fmt.Errorf(
				"interface %q is a redundant-ethernet interface and also names "+
					"`gigether-options redundant-parent %s`; a reth OWNS the L3 "+
					"identity of a redundant pair and is never a member port of "+
					"another interface, so this makes the L3 owner a port of "+
					"something else. `RethToPhysical` keys its map on the "+
					"redundant-parent NAME, so this line enters %q into the "+
					"scoring for what %q resolves to, competing with %q's real "+
					"physical ports. It leaves the shared device with two "+
					"independent claimants and no member relation between them, so "+
					"the snapshot builder refuses to name an egress security zone "+
					"for it and every transit flow out of it falls to the default "+
					"policy. When %s IS itself a reth, winning that scoring also "+
					"puts %q's addresses, security zone and ifindex on the netdev "+
					"name %q — which, a reth not being a kernel device, no NIC "+
					"carries. When %s is NOT a reth it splits the two resolvers "+
					"instead, because `ResolveKernelIfName` honours this map entry "+
					"for a dotted reference where the dataplane's "+
					"`snapshotLinuxName` does not, so units under %s DISPLAY on one "+
					"device and forward on another. Name the physical ports "+
					"(ge-/xe-/et-) as the members of %q and remove the "+
					"redundant-parent line from it",
				name, parent,
				name, parent, parent,
				parent, parent, name,
				parent, parent,
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
		if ifc.Tunnel != nil {
			// #6722 round 10. The unit clause below cannot reach this: an
			// interface-level tunnel (WireGuard, GRE) configures its L3 identity
			// in the `tunnel` stanza and may declare no logical unit at all, so
			// a WireGuard member passed every clause of this gate — and
			// WireGuard's own interface-level validation accepts the shape too.
			// Measured: `wg0 redundant-parent reth1` puts reth1, reth1.0 and wg0
			// on the TUN's ifindex, and the egress MAC gate admits wg0 through
			// `iface.tunnel.then_some([0; 6])` where the reth's own rows fail it
			// — so an independently ROUTED WireGuard endpoint received the LAN
			// reth's zone. That is the fail-OPEN direction.
			return fmt.Errorf(
				"interface %q is a member of redundant-ethernet interface %q and "+
					"also configures a `tunnel`; a reth member contributes a "+
					"physical PORT and nothing else, while a tunnel interface is an "+
					"independently routed L3 endpoint with its own peers and routes. "+
					"`ResolveReth` collapses %q's addresses, security zone and "+
					"ifindex onto %q's device, so traffic routed out %q would be "+
					"evaluated in %q's zone. Name a physical port (ge-/xe-/et-) as "+
					"the member of %q, or remove the redundant-parent line from %q",
				name, parent,
				parent, name, name, parent,
				parent, name)
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
