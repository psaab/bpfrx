package config

import (
	"fmt"
	"hash/fnv"
	"sort"
)

// ZoneIDReservedMin is the Go mirror of the Rust ZONE_ID_RESERVED_MIN
// (userspace-dp/src/policy.rs: u16::MAX-1 = 0xFFFE). The top two ids of the
// u16 zone space are reserved sentinels — JUNOS_GLOBAL_ZONE_ID (u16::MAX) and
// the junos-host self-traffic zone (u16::MAX-1) — so the largest id a
// CONFIGURED zone may carry is ZoneIDReservedMin-1 (65533). StableZoneID folds
// strictly into [1, ZoneIDReservedMin-1] so a hashed zone id can never collide
// with either sentinel.
const ZoneIDReservedMin uint16 = 0xFFFE // mirrors Rust ZONE_ID_RESERVED_MIN

// StableZoneID maps a security-zone name to a stable nonzero u16 zone id:
// FNV-1a/64 xor-folded to 16 bits, mapped into [1, ZoneIDReservedMin-1].
//
// THE FOLD IS WIRE-ADJACENT AND MUST NEVER CHANGE (#3075): zone ids ride the
// daemon↔helper event-stream delta wire (a u16 field after #3075) and the
// per-flow conntrack value, and both HA nodes must compute identical ids from
// identical config. The id is a pure function of the zone NAME alone — never of
// the rest of the zone set, the compile order, or allocation history — so
// adding, renaming, or removing a zone can never renumber another zone (the
// sorted-positional defect this replaces; see #3075), and both nodes plus a
// cold-booting node agree by construction with zero synced/persisted state.
//
// This is the #1873 tunnelid.go pattern, ported to zones now that the two
// same-host event-stream u8 chokepoints have been widened to u16 (#3075). It
// supersedes the #2391 u8 zone-count cap: the binding constraint is no longer a
// 255-id wire field but the reserved-sentinel range, so the usable space is
// [1, ZoneIDReservedMin-1] = [1, 65533].
//
// 0 is never returned: id 0 means "unassigned / unknown zone" across the
// dataplane.
func StableZoneID(name string) uint16 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	s := h.Sum64()
	folded := uint16(s) ^ uint16(s>>16) ^ uint16(s>>32) ^ uint16(s>>48)
	return folded%(ZoneIDReservedMin-1) + 1 // [1, 65533]
}

// collectZoneNamesAST appends the security-zone names declared under one
// "security" hierarchy node into out. The AST path mirrors compileZones
// (compiler_security.go): security -> zones -> security-zone <name>, handling
// both the hierarchical merged-key shape and the flat-set single-key chain via
// the shared namedInstances helper.
func collectZoneNamesAST(securityNode *Node, out map[string]struct{}) {
	if securityNode == nil {
		return
	}
	zonesNode := securityNode.FindChild("zones")
	if zonesNode == nil {
		return
	}
	for _, inst := range namedInstances(zonesNode.FindChildren("security-zone")) {
		if inst.name == "" {
			continue
		}
		out[inst.name] = struct{}{}
	}
}

// emitNodeExpandedZoneNames returns the security-zone names that survive
// expanding the candidate tree for chassis-cluster node nodeID (View 2 for
// node0, View 3 for node1), used by validateZoneIDCollisionAST. It is the
// post-`${node}`/apply-groups view: a `${node}`-interpolated or wildcard
// apply-group zone name is only concrete after expansion.
//
// It is RECURSION-FREE by construction: it clones the candidate, expands groups
// for the node, and reads the zone names straight off the expanded AST — it
// NEVER calls CompileConfig* (which would call this gate and recurse). Per-node
// expansion errors are NON-FATAL: the view contributes the EMPTY set. A config
// that defines only `groups node0` and references `${node}` legitimately has no
// `groups node1`, so expanding for node1 hits `undefined group "node1"`; that
// is already handled on the real per-node compile path (CompileConfig falls
// back to node0), and the collision gate must not turn it into a spurious
// commit failure. View 1's pre-expansion presence union still covers any
// collision inside the un-expandable group, so dropping the failed node's view
// loses no real coverage and keeps the verdict a pure function of the candidate
// (both nodes compute identical error-to-empty-set handling).
func emitNodeExpandedZoneNames(tree *ConfigTree, nodeID int, out map[string]struct{}) {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return
	}
	collectZoneNamesAST(clone.FindChild("security"), out)
}

// validateZoneIDCollisionAST checks the UNION of security-zone names across
// three views of the candidate config for StableZoneID collisions (#3075),
// mirroring validateTunnelEndpointIDCollisionAST (#1873/#1914):
//
//	View 1 — the PRE-expansion presence union across the main "security"
//	  hierarchy AND every "groups" block. It runs on the pre-expansion tree
//	  (ExpandGroups removes the groups stanza) so the check covers the union of
//	  zone names across all groups, keeping the accept/reject decision identical
//	  on both chassis-cluster nodes: a collision involving a `groups node0`-scoped
//	  zone must fail commit on node1 too, or config-sync would split (originator
//	  accepts, peer rejects).
//	View 2 — the zone names that survive expanding the candidate for node0.
//	View 3 — the same for node1.
//
// Zones ARE group/`${node}`-scoped (docs/ha-cluster-userspace.conf uses
// `groups { node0 {...} node1 {...} }` + `apply-groups "${node}"`), so Views 2/3
// are REQUIRED, not optional: a `${node}`-interpolated or wildcard-apply-group
// zone name is only concrete post-expansion, and the verdict must be identical
// on both nodes. All three views are pure functions of the SAME candidate
// config, so the union stays a pure function of config (HA symmetry preserved),
// and it is monotone over View 1 (Views 2/3 only ADD rejects).
//
// Strict (commit / commit-check) returns an error; lenient (load / peer-sync of
// an already-active config) returns a warning so an upgraded node still boots —
// the fold guarantees no reserved-sentinel id and the dataplane independently
// fails closed on an unresolvable zone, so a leniently-loaded colliding config
// is inert on the later-folding zone rather than mis-attributed.
func validateZoneIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
	names := make(map[string]struct{})
	// View 1 — pre-expansion presence union (main + every groups block).
	collectZoneNamesAST(tree.FindChild("security"), names)
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			// Node{Keys:["groups","node0"]} merges the group name into
			// Keys[1]; the children are then the group body. The other shape
			// nests the group name as a child node.
			if len(child.Keys) >= 2 {
				collectZoneNamesAST(child.FindChild("security"), names)
				break
			}
			collectZoneNamesAST(group.FindChild("security"), names)
		}
	}
	// Views 2/3 — post-expansion zone names for node0 and node1. Both computed
	// on both nodes from the shared candidate, so the union stays HA-symmetric;
	// per-node expansion errors contribute the empty set (non-fatal).
	emitNodeExpandedZoneNames(tree, 0, names)
	emitNodeExpandedZoneNames(tree, 1, names)
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
		id := StableZoneID(name)
		owner, taken := byID[id]
		if !taken {
			byID[id] = name
			continue
		}
		msg := fmt.Sprintf(
			"zone id collision between %q and %q (both fold to %d) — rename one zone (#3075)",
			owner, name, id)
		if !lenient {
			return nil, fmt.Errorf("security zones: %s", msg)
		}
		warnings = append(warnings, msg+
			"; the later-sorting zone is NOT installed in the dataplane")
	}
	return warnings, nil
}
