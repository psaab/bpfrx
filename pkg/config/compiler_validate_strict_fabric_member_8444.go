package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateFabricMemberDefinedStrict hard-rejects a `interfaces fabN
// fabric-options member-interfaces` entry whose name cannot be attributed to a
// cluster node, because the consequence is a node with NO fabric link at all.
//
// THE DEFECT (#8444). A one-character typo commits clean and takes the fabric
// down silently. Measured through configstore.CheckText on the canonical
// two-fab shape from docs/ha-cluster-userspace.conf:
//
//	member fab0=ge-0/0/0 fab1=ge-7/0/0  node=0 -> FabricInterface="fab0"
//	member fab0=fabster  fab1=ge-7/0/0  node=0 -> FabricInterface=""      <-- outage
//	member fab0=ge-0-0-0 fab1=ge-7-0-0  node=0 -> FabricInterface=""      <-- outage
//	member fab0=ge-0-0-0 fab1=ge-7-0-0  node=1 -> FabricInterface=""      <-- outage
//
// `deriveFabricInterface` (compiler_derivations.go) selects the fabric
// interface ONLY from a member for which `InterfaceSlot(member) >= 0` and
// `SlotToNodeID(slot) == cc.NodeID`. A name that does not parse to an FPC slot
// matches nothing, `cc.FabricInterface` stays EMPTY, and every fabric bring-up
// in daemon_run_bringup.go is gated on it — so cross-chassis forwarding,
// session sync and config sync are all silently skipped. The operator sees a
// connectivity failure, never a config one.
//
// WHAT THE GATE CHECKS, AND WHY NOT EXISTENCE. The obvious gate — "the member
// must be defined under `interfaces`", reusing zoneReferenceableInterfaceBases
// the way validateZoneInterfaceDefinedStrict does — is UNSOUND here, and
// measuring the canonical config is what showed it: neither `ge-0/0/0` nor
// `ge-7/0/0` has an `interfaces` stanza in docs/ha-cluster-userspace.conf.
// They appear exactly once each, as the member entry itself. A fabric member is
// a bare physical NIC; unlike a zone member it carries no unit, address or
// family of its own, so it has no reason to be declared separately. An
// existence gate would therefore hard-reject the working production config on
// BOTH nodes — the #4191 over-rejection class, with a cluster outage attached.
//
// The property that actually separates the good name from the typo is the one
// the derivation itself consumes: does the name parse to an FPC slot. That is
// node-agnostic, which also dissolves the node-scoping hazard — one config
// describes both nodes and is synced verbatim between them, so a check whose
// answer depended on WHICH node evaluated it would accept on one node and
// reject on its peer. `ge-0/0/0` and `ge-7/0/0` both parse on both nodes;
// `fabster` and `ge-0-0-0` parse on neither.
//
// DELIBERATELY OUT OF SCOPE: a member that parses but names no real NIC
// (`ge-0/0/99`). Measured, that one DOES derive — FabricInterface is set and
// bring-up runs and fails at netlink with a visible error. It is a different,
// non-silent defect, and catching it would require exactly the existence check
// shown unsound above.
func validateFabricMemberDefinedStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		if strings.HasPrefix(name, "fab") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, fabName := range names {
		ifc := cfg.Interfaces.Interfaces[fabName]
		if ifc == nil {
			continue
		}
		for _, member := range ifc.FabricMembers {
			base := member
			if idx := strings.Index(base, "."); idx > 0 {
				base = base[:idx]
			}
			if InterfaceSlot(base) >= 0 {
				continue
			}
			return fmt.Errorf(
				"chassis cluster: `interfaces %s fabric-options member-interfaces` "+
					"names %q, which is not a valid FPC-slotted interface name "+
					"(expected the `<type>-<fpc>/<pic>/<port>` form, e.g. ge-0/0/0 for "+
					"node 0 or ge-7/0/0 for node 1); the fabric interface is derived "+
					"from the member matching this node's slot, so a name that does not "+
					"parse selects nothing, leaves the fabric interface unset, and the "+
					"node comes up with NO fabric link — cross-chassis forwarding, "+
					"session sync and config sync are all gated on it",
				fabName, member)
		}
	}
	return nil
}
