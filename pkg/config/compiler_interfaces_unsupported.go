package config

import "fmt"

// compiler_interfaces_unsupported.go carries the #2008 H9/H10 parity
// reject-at-commit gate for interface stanzas that xpf parses but cannot
// honour. Both stanzas are silent-drops on master: the parser accepts
// them, the compiler never reads them, and the userspace AF_XDP
// dataplane has no mechanism to enforce them. Admitting them on a commit
// is a silent functional lie, so the gate hard-rejects them at commit /
// commit-check and warns (does not fail) on the tolerant load / peer-
// sync paths per the #1960 fail-closed-on-load doctrine.
//
//   - H9: `interfaces <if> unit <n> family inet|inet6 policer arp <name>`
//     — a per-logical-interface ARP policer. The dataplane has NO
//     per-interface policer enforcement (feature-gaps.md "Interface
//     Policer ... Missing"); the only policer enforcement is the
//     admitted firewall-filter path and the color-blind three-color
//     discard slice (pkg/dataplane/userspace/filters.go). A real
//     implementation is a net-new dataplane subsystem.
//   - H10: `interfaces <if> [unit <n>] mac <addr>` — a static MAC
//     override. xpf computes the RETH virtual MAC deterministically per
//     node (programRethMAC, 02:bf:72:CC:RR:NN) and Junos treats the
//     interface MAC as read-only, so a static override is both
//     unimplemented and divergent.
//   - #2354: `interfaces <if> unit <n> inner-vlan-id <x>` — a QinQ /
//     stacked-VLAN (802.1ad S-tag + 802.1Q C-tag) inner tag. The parser
//     accepts it and the compiler stores it in Unit.InnerVlanID, but that
//     field has ZERO dataplane consumers: the AF_XDP shim's parse_l2
//     unwinds exactly ONE VLAN tag, so a double-tagged frame keeps
//     eth_proto=0x8100 → the dispatch `_` arm XDP_PASSes it to the kernel
//     forwarding path, never reaching the userspace firewall. A committed
//     inner-vlan-id is therefore a false promise of firewalled stacked-
//     VLAN transit. This gate is the honest-posture half of #2354; the
//     multi-layer QinQ feature build (two-tag parse/deliver/serialize +
//     networkd stacked netdev + zone binding on the inner tag) stays
//     plan-deferred pending operator demand (see the 4-PR decomposition
//     in the issue). Single 802.1Q / single 802.1ad tagging via `vlan-id`
//     is fully supported and CORRECT (#2346) — this gate keys strictly on
//     `inner-vlan-id`, so `flexible-vlan-tagging` WITHOUT an inner tag is
//     never tripped (Junos-parity, single-tag transit works).
//
// Why reject at commit (vs the warn-only M1 persist-groups-inheritance
// or the PR #659 import-compat warnings): M1 is a daemon-behaviour knob
// that is harmless as a no-op (the firewall posture is correct either
// way), so a warning is honest. H9/H10 are FALSE PROMISES about
// dataplane enforcement / interface identity — a committed `policer arp`
// claims ARP is rate-limited and a committed `mac` claims a specific
// hardware address, neither of which the running firewall delivers.
// Blocking the new operator edit at commit stops an operator deploying a
// config they believe enforces security/identity when it does not; the
// lenient load/peer-sync downgrade still lets an already-imported or
// peer-synced config (which an older binary silently accepted) boot.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf) because
// SchemaValidate is opt-in per known leaf and returns nil for unknown
// keywords by design (schema_walk.go) — it cannot REJECT an unknown
// stanza. Every other reject-at-commit-for-unsupported gate
// (validateVRRPTrackInterfaceAST, validateTCPMSSRanges,
// validateNodesControlChars, validateTunnelEndpointIDCollisionAST) is an
// AST pre-walk in compileExpanded for the same reason. The walk runs on
// the group-expanded, inactive-pruned tree (compileConfigWithOpts /
// compileConfigForNodeWithOpts strip inactive subtrees and expand groups
// before compileExpanded), so an apply-groups-inherited stanza is caught
// and an `inactive:` stanza is ignored (#2008 H1 doctrine) for free.

// validateUnsupportedInterfaceStanzasAST walks the `interfaces` subtree
// of the group-expanded AST and rejects the H9/H10/#2354 silent-drop
// stanzas.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// stanza is a hard compile error, naming the exact interface/unit path.
//
// Lenient path (load / peer-sync, lenient=true): every offending stanza
// is returned as a warning and compilation continues. The stanza is NOT
// pruned — it is already a no-op (no compiler reads it), so leaving it in
// the cloned tree is harmless and the warning is the operator signal.
// This differs from validateVRRPTrackInterfaceAST, which must prune
// because its duplicates change which statement the compiler picks; here
// there is nothing to pick.
//
// Detection is scoped to the `interfaces` stanza so the firewall
// `policer <name>` definition and the chassis `device-map interface ...
// mac` identity key (both legitimate uses of these keywords elsewhere)
// are never touched.
func validateUnsupportedInterfaceStanzasAST(nodes []*Node, lenient bool) ([]string, error) {
	// #5744: union across EVERY top-level `interfaces` root, not just the first.
	// A hierarchical config can split its interfaces across two sibling
	// `interfaces { }` stanzas, and compileSections compiles them all — so an
	// unsupported / silently-dropped interface stanza living in a SECOND root
	// was skipped by the old first-root-only scan, the sibling gap PR #5741
	// closed for the interface-range / stable-ID gates. Flattening every
	// interfaces root's children into one per-interface pass is equivalent to
	// nesting a loop over the roots; each stanza is flagged independently.
	var ifaceChildren []*Node
	sawInterfaces := false
	for _, n := range nodes {
		if n.Name() == "interfaces" {
			sawInterfaces = true
			ifaceChildren = append(ifaceChildren, n.Children...)
		}
	}
	if !sawInterfaces {
		return nil, nil
	}

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// Each direct child of `interfaces` is a physical/aggregate interface
	// instance (wildcard name slot).
	for _, iface := range ifaceChildren {
		ifName := iface.Name()
		if ifName == "" {
			continue
		}

		// H10: a static MAC override at the physical-interface scope.
		for _, c := range iface.Children {
			if c.Name() == "mac" {
				if err := emit(
					"interfaces %s: static `mac` override is not supported "+
						"(the interface MAC is read-only; for cluster RETH it is "+
						"computed deterministically per node) — remove it (#2008 H10)",
					ifName); err != nil {
					return nil, err
				}
			}
		}

		for _, unit := range iface.Children {
			if unit.Name() != "unit" {
				continue
			}
			unitID := unitIdentity(unit)

			// H10: a static MAC override at the logical-unit scope.
			for _, c := range unit.Children {
				if c.Name() == "mac" {
					if err := emit(
						"interfaces %s unit %s: static `mac` override is not "+
							"supported (the interface MAC is read-only; for cluster "+
							"RETH it is computed deterministically per node) — "+
							"remove it (#2008 H10)",
						ifName, unitID); err != nil {
						return nil, err
					}
				}
			}

			// #2354: a QinQ / stacked-VLAN inner tag on the unit. The
			// AF_XDP shim parses exactly one VLAN tag, so a double-tagged
			// (S-tag + C-tag) frame is XDP_PASSed to the kernel and never
			// firewalled — Unit.InnerVlanID has no dataplane consumer.
			// Committing it is a false promise of firewalled stacked-VLAN
			// transit. Keyed strictly on `inner-vlan-id` so single-tag
			// `vlan-id` / `flexible-vlan-tagging` (both supported, #2346)
			// are never tripped.
			for _, c := range unit.Children {
				if c.Name() == "inner-vlan-id" {
					iv := nodeVal(c)
					if err := emit(
						"interfaces %s unit %s: `inner-vlan-id %s` (QinQ / "+
							"stacked-VLAN inner tag) is not enforced by the AF_XDP "+
							"dataplane — a double-tagged (802.1ad S-tag + 802.1Q "+
							"C-tag) frame is parsed as a single tag and falls to the "+
							"kernel forwarding path, never firewalled; single 802.1Q "+
							"tagging via `vlan-id` is supported — remove it (#2354)",
						ifName, unitID, iv); err != nil {
						return nil, err
					}
				}
			}

			// H9: a per-unit ARP policer under family inet / inet6.
			for _, fam := range unit.Children {
				if fam.Name() != "family" || !isInetFamily(fam) {
					continue
				}
				famName := familyAfterKeyword(fam)
				if hasARPPolicer(fam) {
					if err := emit(
						"interfaces %s unit %s family %s: `policer arp` is not "+
							"supported (xpf has no per-interface ARP policer; ARP "+
							"is not rate-limited per logical interface) — remove it "+
							"(#2008 H9)",
						ifName, unitID, famName); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return warnings, nil
}

// unitIdentity returns the unit number token for an error message. The
// `unit <n>` node packs the number as Keys[1] in both AST shapes
// (flat-set `set ... unit 0 ...` and hierarchical `unit 0 { ... }`).
func unitIdentity(unit *Node) string {
	if len(unit.Keys) >= 2 {
		return unit.Keys[1]
	}
	return "?"
}

// isInetFamily reports whether a `family` node is the inet or inet6
// family. The family token is Keys[1] in both shapes (flat-set packs
// `family inet` into one node's Keys; hierarchical `family inet { ... }`
// is the compoundKey shape with the same Keys layout).
func isInetFamily(fam *Node) bool {
	name := familyAfterKeyword(fam)
	return name == "inet" || name == "inet6"
}

// familyAfterKeyword returns the family-name token (Keys[1]) of a
// `family <name>` node, or "" if absent.
func familyAfterKeyword(fam *Node) string {
	if len(fam.Keys) >= 2 {
		return fam.Keys[1]
	}
	return ""
}

// hasARPPolicer reports whether a `family inet|inet6` node carries a
// `policer arp` statement in either AST shape:
//
//   - flat-set: a single child node Keys=["policer","arp",<name>...]
//   - hierarchical: a `policer` child node containing an `arp` child.
func hasARPPolicer(fam *Node) bool {
	for _, c := range fam.Children {
		if len(c.Keys) == 0 || c.Keys[0] != "policer" {
			continue
		}
		// Flat-set: policer arp <name> packed into this node's Keys.
		if len(c.Keys) >= 2 && c.Keys[1] == "arp" {
			return true
		}
		// Hierarchical: policer { arp <name>; }.
		for _, pc := range c.Children {
			if pc.Name() == "arp" {
				return true
			}
		}
	}
	return false
}
