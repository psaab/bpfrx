package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_chassis.go compiles and strictly validates the #1956 bare-metal
// device-map subtree. The device-map binds host NICs (by stable identity —
// PCI bus address with permanent-MAC fallback) to xpf logical names and
// governs everything not named via unmapped-interface-policy. The compile
// is independent of `chassis cluster` (R-7): a standalone box has a
// device-map but no cluster.

// compileDeviceMap converts the parsed `chassis device-map` subtree into a
// typed *DeviceMapConfig. Returns nil only when the subtree carries no
// usable content (so an empty/garbage block does not force device-map mode;
// the Active() predicate keys on len(Entries) > 0 anyway — R-7/V-7).
func compileDeviceMap(node *Node) *DeviceMapConfig {
	dm := &DeviceMapConfig{}

	if n := node.FindChild("unmapped-interface-policy"); n != nil {
		if v := nodeVal(n); v != "" {
			dm.UnmappedPolicy = v
		}
	}

	for _, inst := range namedInstances(node.FindChildren("interface")) {
		entry := DeviceMapEntry{LogicalName: inst.name}
		entry.PCIAddr = deviceMapProp(inst.node, "pci")
		entry.MAC = deviceMapProp(inst.node, "mac")
		entry.KeyOrder = deviceMapProp(inst.node, "key")
		dm.Entries = append(dm.Entries, entry)
	}

	// Stable order so the map is deterministic across compiles (config
	// archive diffs, show output) regardless of AST iteration order.
	sort.Slice(dm.Entries, func(i, j int) bool {
		return dm.Entries[i].LogicalName < dm.Entries[j].LogicalName
	})

	if dm.UnmappedPolicy == "" && len(dm.Entries) == 0 {
		// Truly empty block — treat as absent (positional mode).
		return nil
	}
	return dm
}

// deviceMapProp reads a single property of a device-map `interface` instance,
// handling both AST shapes: nested (`interface ge-0/0/3 { pci 0000:09:00.0; }`)
// and inline flat-set (`Keys: [interface ge-0/0/3 pci 0000:09:00.0]`).
func deviceMapProp(instNode *Node, prop string) string {
	// Inline form: the property keyword appears in the instance node's
	// Keys, with its value the following token.
	for i := 2; i+1 < len(instNode.Keys); i++ {
		if instNode.Keys[i] == prop {
			return instNode.Keys[i+1]
		}
	}
	// Nested form: a child node named prop with its value.
	if n := instNode.FindChild(prop); n != nil {
		if v := nodeVal(n); v != "" {
			return v
		}
	}
	return ""
}

// validateDeviceMapStrict is the #1956 cross-entry commit-check validator.
// It runs ONLY on the strict compile path (commit / commit-check), so the
// lenient paths (Store.Load, peer SyncApply, display) DOWNGRADE these to
// warnings — load-bearing for HA, where node 0's strict commit cannot fail
// on node 1's section (different hardware) but node 1's SyncApply must not
// reject the whole sync (V-1). The node-local boot-time safety (mgmt
// lockout, live hardware presence) is enforced separately in the daemon's
// commit pre-flight (R-8) — this validator covers the purely structural
// invariants that hold without touching live sysfs.
func validateDeviceMapStrict(cfg *Config) error {
	dm := cfg.Chassis.DeviceMap
	if dm == nil || len(dm.Entries) == 0 {
		return nil
	}

	clusterMode := cfg.Chassis.Cluster != nil
	nodeID := 0
	if clusterMode {
		nodeID = cfg.Chassis.Cluster.NodeID
	}

	// Build the RETH-member set so a key-mac override on a RETH member can
	// be rejected (R-6): a RETH member's MAC alternates physical<->virtual.
	rethMembers := make(map[string]bool)
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" {
			rethMembers[ifc.Name] = true
		}
	}

	seenName := make(map[string]string) // logical name -> first identity
	seenPCI := make(map[string]string)  // pci addr -> first logical name
	seenMAC := make(map[string]string)  // mac -> first logical name

	for _, e := range dm.Entries {
		if e.LogicalName == "" {
			return fmt.Errorf("chassis device-map: entry with empty logical interface name")
		}
		// Duplicate logical name → FATAL (two NICs cannot both be ge-0/0/3).
		if prev, ok := seenName[e.LogicalName]; ok {
			return fmt.Errorf("chassis device-map: logical name %q is mapped twice "+
				"(first to %s); each logical name binds exactly one NIC",
				e.LogicalName, prev)
		}
		seenName[e.LogicalName] = entryIdentityDesc(e)

		// An entry must carry at least one identity key.
		if e.PCIAddr == "" && e.MAC == "" {
			return fmt.Errorf("chassis device-map: interface %q has neither a pci nor a "+
				"mac identity key — add `pci <addr>` (preferred) or `mac <addr>`",
				e.LogicalName)
		}

		// Duplicate PCI / duplicate MAC → FATAL (one NIC, two names).
		if e.PCIAddr != "" {
			if prev, ok := seenPCI[e.PCIAddr]; ok {
				return fmt.Errorf("chassis device-map: PCI address %s is bound to both %q "+
					"and %q — one NIC cannot be two interfaces", e.PCIAddr, prev, e.LogicalName)
			}
			seenPCI[e.PCIAddr] = e.LogicalName
		}
		if e.MAC != "" {
			macKey := strings.ToLower(e.MAC)
			if prev, ok := seenMAC[macKey]; ok {
				return fmt.Errorf("chassis device-map: MAC %s is bound to both %q and %q — "+
					"one NIC cannot be two interfaces", e.MAC, prev, e.LogicalName)
			}
			seenMAC[macKey] = e.LogicalName
		}

		// Key-order sanity: a mac-only key order needs a mac; a pci-only
		// key order needs a pci.
		switch e.EffectiveKeyOrder() {
		case DeviceMapKeyMAC:
			if e.MAC == "" {
				return fmt.Errorf("chassis device-map: interface %q sets `key mac` but has no "+
					"`mac` identity", e.LogicalName)
			}
		case DeviceMapKeyPCI:
			if e.PCIAddr == "" {
				return fmt.Errorf("chassis device-map: interface %q sets `key pci` but has no "+
					"`pci` identity", e.LogicalName)
			}
		}

		// R-6: RETH member must stay PCI-keyed (OriginalName= match); a
		// mac-leading key order is rejected.
		if rethMembers[e.LogicalName] {
			switch e.EffectiveKeyOrder() {
			case DeviceMapKeyMAC, DeviceMapKeyMACThenPCI:
				return fmt.Errorf("chassis device-map: interface %q is a RETH member; its MAC "+
					"alternates physical<->virtual, so it must be PCI-keyed (drop `key mac`/"+
					"`key mac-then-pci`)", e.LogicalName)
			}
			if e.PCIAddr == "" {
				return fmt.Errorf("chassis device-map: RETH member %q must be bound by `pci` "+
					"(its MAC is unreliable)", e.LogicalName)
			}
		}

		// V-6: generalized FPC/node alignment — in cluster mode EVERY
		// logical name whose FPC slot is set must align with the local
		// node-id, not just RETH members. ge-7/0/3 on node 0 would
		// silently misattribute to the peer.
		if clusterMode {
			if slot := InterfaceSlot(e.LogicalName); slot >= 0 {
				if SlotToNodeID(slot) != nodeID {
					return fmt.Errorf("chassis device-map: interface %q has FPC slot %d which "+
						"maps to node %d, but this device-map section is for node %d — use the "+
						"per-node groups (node%d) section or the right FPC slot",
						e.LogicalName, slot, SlotToNodeID(slot), nodeID, nodeID)
				}
			}
		}
	}

	// Validate the unmapped policy value (defense in depth; the schema
	// enum already gates the set path, but a hand-imported config or a
	// future caller could bypass it).
	switch dm.UnmappedPolicy {
	case "", DeviceMapPolicyLeaveAlone, DeviceMapPolicyManageDown:
	default:
		return fmt.Errorf("chassis device-map: unknown unmapped-interface-policy %q "+
			"(expected leave-alone or manage-down)", dm.UnmappedPolicy)
	}
	return nil
}

// entryIdentityDesc renders an entry's identity for diagnostics.
func entryIdentityDesc(e DeviceMapEntry) string {
	switch {
	case e.PCIAddr != "" && e.MAC != "":
		return fmt.Sprintf("pci %s / mac %s", e.PCIAddr, e.MAC)
	case e.PCIAddr != "":
		return "pci " + e.PCIAddr
	case e.MAC != "":
		return "mac " + e.MAC
	default:
		return "(no identity)"
	}
}
