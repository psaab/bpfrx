package config

import (
	"fmt"
	"hash/fnv"
	"sort"
)

// StableTunnelEndpointID maps a tunnel interface name (unit-qualified,
// e.g. "wg0.0", "gr-0/0/0.0") to a stable nonzero u16 tunnel-endpoint
// id: FNV-1a 64 xor-folded to 16 bits, mapped into [1, 0xFFFF].
//
// THE FOLD IS WIRE-ADJACENT AND MUST NEVER CHANGE (#1873): tunnel
// endpoint ids cross the cluster as bare numbers (SessionValue.FibGen
// in pkg/cluster/sync_protocol.go), and both HA nodes must compute
// identical ids from identical config. The id is a pure function of
// the interface NAME alone — never of runtime state, the rest of the
// tunnel set, or allocation history — so adding or removing one
// tunnel can never renumber another (the positional-id defect this
// replaces), and both nodes agree by construction.
//
// 0 is never returned: id 0 means "not a tunnel" across the
// dataplane.
func StableTunnelEndpointID(name string) uint16 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	s := h.Sum64()
	folded := uint16(s) ^ uint16(s>>16) ^ uint16(s>>32) ^ uint16(s>>48)
	return folded%0xFFFF + 1
}

// collectTunnelEndpointNamesAST appends the unit-qualified tunnel
// endpoint names declared under one "interfaces" hierarchy node,
// mirroring buildTunnelEndpointSnapshots naming exactly:
//
//   - interface-level tunnel, no units  -> "name"
//   - interface-level tunnel with units -> "name.N" per unit
//   - unit-level tunnel                 -> "name.N"
//
// Handles both AST shapes (hierarchical merged keys and flat-set
// single-key chains) via the same namedInstances helper the compiler
// uses for unit nodes.
func collectTunnelEndpointNamesAST(ifacesNode *Node, out map[string]struct{}) {
	if ifacesNode == nil {
		return
	}
	for _, iface := range ifacesNode.Children {
		if iface.IsLeaf {
			continue
		}
		name := iface.Name()
		if name == "" {
			continue
		}
		hasIfaceTunnel := iface.FindChild("tunnel") != nil
		units := namedInstances(iface.FindChildren("unit"))
		if hasIfaceTunnel && len(units) == 0 {
			out[name] = struct{}{}
			continue
		}
		for _, unit := range units {
			if unit.name == "" {
				continue
			}
			if hasIfaceTunnel || unit.node.FindChild("tunnel") != nil {
				out[fmt.Sprintf("%s.%s", name, unit.name)] = struct{}{}
			}
		}
	}
}

// validateTunnelEndpointIDCollisionAST checks the UNION of tunnel
// endpoint names across the main "interfaces" hierarchy AND every
// "groups" block for StableTunnelEndpointID collisions (#1873 R-B).
//
// The union (rather than the per-node effective config) keeps the
// accept/reject decision identical on both chassis-cluster nodes: a
// collision involving a `groups node0`-scoped tunnel must fail commit
// on node1 too, or config-sync would split (originator accepts, peer
// rejects). It runs on the PRE-expansion tree because ExpandGroups
// removes the groups stanza.
//
// Strict (commit / commit-check) returns an error; lenient (load /
// peer-sync of an already-active config) returns a warning so an
// upgraded node still boots — the snapshot builder independently
// drops the later-sorting collider (fail-closed belt-and-braces in
// buildTunnelEndpointSnapshots).
func validateTunnelEndpointIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
	names := make(map[string]struct{})
	collectTunnelEndpointNamesAST(tree.FindChild("interfaces"), names)
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			// Node{Keys:["groups","node0"]} merges the group name
			// into Keys[1]; the children are then the group body.
			if len(child.Keys) >= 2 {
				collectTunnelEndpointNamesAST(child.FindChild("interfaces"), names)
				break
			}
			collectTunnelEndpointNamesAST(group.FindChild("interfaces"), names)
		}
	}
	if len(names) < 2 {
		return nil, nil
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	byID := make(map[uint16]string, len(sorted))
	var warnings []string
	for _, name := range sorted {
		id := StableTunnelEndpointID(name)
		owner, taken := byID[id]
		if !taken {
			byID[id] = name
			continue
		}
		msg := fmt.Sprintf(
			"tunnel endpoint id collision between %q and %q (both fold to %d) — rename one interface (#1873)",
			owner, name, id)
		if !lenient {
			return nil, fmt.Errorf("interfaces: %s", msg)
		}
		warnings = append(warnings, msg+
			"; the later-sorting tunnel is NOT installed in the dataplane")
	}
	return warnings, nil
}
