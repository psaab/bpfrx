package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_interface_unit_alias.go carries the #5631 (codex-review-181 M23)
// reject-at-commit gate for numeric interface-unit ALIASES — two distinct
// unit-number spellings under one interface that canonicalize to the SAME
// logical unit — PROMOTED in #5878 to a BOTH-NODE-EFFECTIVE union gate that
// runs PRE-expansion so a peer-only alias is caught at either node's commit.
//
// The compiler keys logical units by the numeric value: compileInterfaces
// (compiler_interfaces.go) iterates `namedInstances(child.FindChildren("unit"))`
// and canonicalizes each RAW spelling through `strconv.Atoi` — but only AFTER
// the AST has already split `unit 00` and `unit 0` into two SEPARATE named
// instances. The two instances then collide on the same `ifc.Units[unitNum]`
// key, and the two side effects disagree:
//
//   - `ifc.Units[unitNum] = unit` is LAST-WRITER-WINS: the later spelling's
//     unit (its filter, its addresses, its flags) completely REPLACES the
//     earlier one — so the interface's input/output firewall filter is decided
//     by config order.
//   - the interface-level tunnel address collection
//     (`ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)`)
//     is APPEND-ONLY: it accumulates the addresses of EVERY spelling, so a
//     stale address from the spelling that LOST the filter race still survives
//     on the tunnel.
//
// The observable result is order-dependent AND self-inconsistent: compiling
// `unit 00` then `unit 0` versus the reverse order yields a different final
// filter, a different unit address set, and a different tunnel-address set
// (see interface_unit_alias_5631_test.go). Because the winning filter flips
// with config order, an operator who reorders two otherwise-equivalent set
// lines can silently disarm the interface's firewall filter — a fail-open on
// a security hook — while the tunnel keeps forwarding on the stale address.
//
// Junos treats a logical unit as an integer identity: `unit 00` and `unit 0`
// are the SAME unit, and there is no meaningful configuration in which two
// numeric aliases of one unit carry DIFFERENT security state. Rather than pick
// an arbitrary winner (which spelling's filter survives is exactly the
// order-dependent ambiguity that makes this unsafe), this gate REJECTS the
// aliased config at commit so the operator authors a single canonical
// `unit <n>`. This matches how the rest of the compiler resolves unit
// identity (numeric) and the reject-at-commit / warn-on-load doctrine used by
// the sibling silent-inconsistency gates (validateApplicationNameCollisionsAST,
// validateFirewallFilterFamilyCollisionsAST, #1960 / #3261).
//
// # Both-node union (#5878)
//
// The #5631 gate originally ran INSIDE compileExpanded (runPreWalkGates) AFTER
// `tree.ExpandGroupsWithVars({node: nodeN})`, so it saw exactly the SUBMITTING
// node's post-`${node}` effective view. A `groups node1 { … unit 01 }` block
// applied through `apply-groups "${node}"` folds its aliasing spelling onto a
// base `unit 1` ONLY in the standby node's effective view — invisible at a
// node0 commit (Store.compileTree compiles s.nodeID only). The active node
// commits green; the standby's compiled config then diverges (a different
// firewall filter / address set) and a failover silently changes forwarding
// or security posture despite a "synchronized" commit (#5878).
//
// This gate is now the BOTH-NODE UNION, modeled EXACTLY on
// validateTunnelEndpointIDCollisionAST (tunnelid.go), and runs in the
// PRE-expansion gate block of compileConfigForNodeWithOpts /
// compileConfigWithOpts (beside the tunnel/zone/table-id gates):
//
//	View 1 — the PRE-expansion presence union across every top-level
//	  "interfaces" root AND every "groups" block, grouping raw unit spellings
//	  under each interface by canonical unit. Catches a collision hidden inside
//	  an un-expandable / node-inverted group and keeps the verdict identical on
//	  both nodes (a `groups node0`-scoped alias must reject on node1 too, or
//	  config-sync would split — originator accepts, peer rejects).
//	View 2 — the concrete per-interface unit spellings after expanding the
//	  candidate for node0 (ExpandGroupsWithVars + expandInterfaceRanges).
//	View 3 — the same for node1.
//
// Views 2/3 close the wildcard / interface-range gap: an apply-group that
// carries the aliasing spelling onto interfaces named by a wildcard or range
// registers only the literal wildcard name in View 1 (which never matches the
// base interface), so only post-expansion do both concrete spellings land on
// the same interface. Per-node expansion errors are NON-FATAL and contribute
// the EMPTY set (mirrors emitNodeExpandedTunnelNames): a config with only
// `groups node0` legitimately fails node1 expansion, and View 1 still covers
// any collision inside the un-expandable group. Because all three views are
// pure functions of the SAME candidate config (Views 2/3 both computed on both
// nodes), the union — and therefore the accept/reject verdict — is IDENTICAL on
// node0 and node1, and it is MONOTONE over the old single-view gate (it only
// ADDS rejects). Same HA-symmetry / monotonicity safety argument tunnelid.go
// makes.
//
// Strict path (commit / commit-check, lenient=false): the lowest colliding
// canonical unit on the lowest-named interface is a hard compile error naming
// the interface, the colliding spellings, and the canonical unit number.
//
// Lenient path (load / peer-sync, lenient=true): every collision is returned as
// a warning and compilation continues, so an already-persisted or peer-synced
// config an older binary silently accepted still BOOTS (#1960 no-brick
// doctrine). The operator gets the warning as the signal to collapse the
// aliases.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf) for the same
// reason as validateUnsupportedInterfaceStanzasAST: the colliding instances
// are merged away by last-writer-wins by the time the typed `ifc.Units` map
// exists — only the raw AST still carries every spelling. Inactive subtrees are
// pruned before the pre-expansion gate block runs (cloneForExpansion), so an
// `inactive:` unit is ignored for free.
//
// Detection is scoped to DISTINCT spellings that canonicalize to the same
// number: a single canonical `unit 0` (the overwhelming common case) never
// trips it, and flat-set `set` lines with the SAME spelling merge into one AST
// node upstream (they are the same unit, not an alias). A non-numeric or
// out-of-range unit token is skipped — the compiler `continue`s on the
// identical CanonicalLogicalUnit error, so it never reaches `ifc.Units` and
// cannot collide.

// collectInterfaceUnitSpellingsAST folds the distinct raw unit spellings under
// each interface of one "interfaces" hierarchy node into perIface, keyed by
// interface name then by CANONICAL logical unit (#5878). Two spellings that
// CanonicalLogicalUnit maps to the same int land in the same inner set — that
// is the collision the gate rejects. A malformed / out-of-range unit token is
// dropped (the compiler drops it too), mirroring the pre-#5878 strconv.Atoi
// skip so detection matches what compileInterfaces actually consumes.
func collectInterfaceUnitSpellingsAST(ifacesNode *Node, perIface map[string]map[int]map[string]bool) {
	if ifacesNode == nil {
		return
	}
	for _, iface := range ifacesNode.Children {
		ifName := iface.Name()
		if ifName == "" {
			continue
		}
		for _, inst := range namedInstances(iface.FindChildren("unit")) {
			num, _, err := CanonicalLogicalUnit(inst.name)
			if err != nil {
				continue
			}
			if perIface[ifName] == nil {
				perIface[ifName] = make(map[int]map[string]bool)
			}
			if perIface[ifName][num] == nil {
				perIface[ifName][num] = make(map[string]bool)
			}
			perIface[ifName][num][inst.name] = true
		}
	}
}

// collectNodeExpandedInterfaceUnitSpellings folds the per-interface unit
// spellings the compiler would see after expanding the candidate tree for
// chassis-cluster node nodeID into perIface (#5878 Views 2/3). It clones the
// candidate, resolves apply-groups "${node}" for the node, expands interface
// ranges (so a range/wildcard member's alias is seen exactly as the real
// runPreWalkGates path sees it), and collects every top-level "interfaces"
// root's units. Mirrors emitNodeExpandedTunnelNames: per-node expansion errors
// are NON-FATAL and contribute the empty set (View 1 still covers a collision
// inside an un-expandable group), so the verdict stays a pure function of the
// candidate config and is identical on both nodes.
func collectNodeExpandedInterfaceUnitSpellings(tree *ConfigTree, nodeID int, perIface map[string]map[int]map[string]bool) {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return
	}
	// expandInterfaceRanges mutates the clone in place; its warnings are
	// emitted on the real path (runPreWalkGates) and discarded here.
	_ = expandInterfaceRanges(clone)
	for _, ifaces := range clone.FindChildren("interfaces") {
		collectInterfaceUnitSpellingsAST(ifaces, perIface)
	}
}

func validateInterfaceUnitAliasCollisionsAST(tree *ConfigTree, lenient bool) ([]string, error) {
	// perIface[ifName][canonicalUnit] = set of raw spellings.
	perIface := make(map[string]map[int]map[string]bool)

	// View 1 — pre-expansion presence union across every top-level `interfaces`
	// root (#5744: a split config can declare an interface's units across two
	// sibling `interfaces { }` stanzas, and compileSections compiles them all)
	// AND every `groups` block. Modeled on validateTunnelEndpointIDCollisionAST.
	for _, ifaces := range tree.FindChildren("interfaces") {
		collectInterfaceUnitSpellingsAST(ifaces, perIface)
	}
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			// Node{Keys:["groups","node0"]} merges the group name into
			// Keys[1]; the children are then the group body directly.
			if len(child.Keys) >= 2 {
				for _, ifaces := range child.FindChildren("interfaces") {
					collectInterfaceUnitSpellingsAST(ifaces, perIface)
				}
				break
			}
			for _, ifaces := range group.FindChildren("interfaces") {
				collectInterfaceUnitSpellingsAST(ifaces, perIface)
			}
		}
	}

	// Views 2/3 — post-expansion per-interface unit spellings for node0 and
	// node1. Both computed on both nodes from the shared candidate, so the
	// union stays HA-symmetric; per-node expansion errors contribute the empty
	// set (non-fatal).
	collectNodeExpandedInterfaceUnitSpellings(tree, 0, perIface)
	collectNodeExpandedInterfaceUnitSpellings(tree, 1, perIface)

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// Deterministic, node-symmetric first error: lowest-named interface, then
	// lowest colliding canonical unit.
	ifNames := make([]string, 0, len(perIface))
	for ifName := range perIface {
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		byUnit := perIface[ifName]
		nums := make([]int, 0, len(byUnit))
		for num := range byUnit {
			if len(byUnit[num]) >= 2 {
				nums = append(nums, num)
			}
		}
		sort.Ints(nums)

		for _, num := range nums {
			spellings := make([]string, 0, len(byUnit[num]))
			for s := range byUnit[num] {
				spellings = append(spellings, s)
			}
			sort.Strings(spellings)
			quoted := make([]string, len(spellings))
			for i, s := range spellings {
				quoted[i] = "`unit " + s + "`"
			}
			if err := emit(
				"interfaces %s: %s all name the same logical unit %d — numeric "+
					"unit aliases collapse to one unit whose firewall-filter and "+
					"address ownership then depends on config order (the later "+
					"spelling wins the unit filter while tunnel-address side "+
					"effects accumulate from every spelling, a fail-open on the "+
					"security filter); the aliasing spelling may live in a "+
					"peer-only `groups node{0,1}`/`${node}` block that only "+
					"collides in the STANDBY node's effective view — use a single "+
					"canonical `unit %d` (#5631; both-node union #5878)",
				ifName, strings.Join(quoted, ", "), num, num); err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}
