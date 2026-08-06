package config

import (
	"hash/fnv"
	"strconv"
	"strings"
)

// ClusterStableInterfaceName maps a config interface name to the name that is
// IDENTICAL on both chassis-cluster nodes (#4983).
//
// A RETH MEMBER is node-local by construction: the same logical member slot of
// the same redundant interface is `ge-0/0/1` on node 0 and `ge-7/0/1` on node
// 1 (see docs/ha-cluster-userspace.conf, and Config.RethToPhysical, which
// resolves reth -> member by the LOCAL node id). Its redundant-parent name —
// `reth1` — is the cross-node invariant, and zones are bound to the reth unit
// (`reth0.50`, `reth1`), not to the member. So a member resolves to its
// parent, and a unit suffix is carried across: `ge-0/0/1.0` -> `reth1.0`.
//
// This resolution is DELIBERATELY EXPLICIT. The dataplane's
// `ifindex_to_config_name` map happens to end up holding the reth-relative
// name for a member's ifindex today, but only because Go emits interface rows
// in sorted-name order into a last-writer-wins insert and "reth*" sorts after
// "ge-*". That is an emergent property of iteration order, not a contract: it
// would break silently — and in the confidently-wrong direction, naming
// someone else's interface — the first time a naming scheme or a sort changed.
// Nothing here depends on it.
//
// Every other interface (a plain physical port, a tunnel, `fxp0`, a reth or
// reth unit itself) is already identical across nodes and is returned
// unchanged. On a standalone firewall there are no reth members, so this is
// the identity function and the id is simply the interface's own name.
func ClusterStableInterfaceName(cfg *Config, name string) string {
	if cfg == nil || name == "" {
		return name
	}
	base, unit, hasUnit := strings.Cut(name, ".")
	ifc, ok := cfg.Interfaces.Interfaces[base]
	if !ok || ifc == nil || ifc.RedundantParent == "" {
		return name
	}
	if hasUnit {
		return ifc.RedundantParent + "." + unit
	}
	return ifc.RedundantParent
}

// StableInterfaceID maps a CLUSTER-STABLE interface name (the output of
// ClusterStableInterfaceName) to a stable nonzero u32 interface id: FNV-1a/64
// xor-folded to 32 bits, mapped into [1, 0xFFFFFFFF].
//
// THE FOLD IS WIRE-ADJACENT AND MUST NEVER CHANGE (#4983), for exactly the
// reason StableZoneID's must not (#3075): the id is stamped on a session by
// the dataplane, rides the HA session-sync wire, and is resolved back to a
// name by a CLI that recomputes the fold from its own config. It is a pure
// function of the NAME alone — never of the interface set, the compile order,
// or allocation history — so adding, renaming, or removing an interface can
// never renumber another one, and both cluster nodes plus a cold-booting node
// agree by construction with zero synced or persisted state.
//
// 0 is never returned: id 0 means "no ingress-interface identity carried"
// across the dataplane and the CLI, and must stay unambiguous.
//
// Collisions are astronomically unlikely at real interface counts but are NOT
// assumed away: two distinct names folding to one id would make a filter for
// one interface match sessions on the other, a confidently-wrong answer. The
// consumer detects that locally and drops the colliding id rather than
// guessing — see BuildStableInterfaceIDs.
func StableInterfaceID(clusterStableName string) uint32 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(clusterStableName))
	s := h.Sum64()
	folded := uint32(s) ^ uint32(s>>32)
	return folded%0xFFFFFFFF + 1 // [1, 0xFFFFFFFF]
}

// InterfaceStableID is the composition callers want: the stable id of a config
// interface name, resolved reth-relative first.
func InterfaceStableID(cfg *Config, name string) uint32 {
	return StableInterfaceID(ClusterStableInterfaceName(cfg, name))
}

// BuildStableInterfaceIDs inverts InterfaceStableID over the whole config:
// stable id -> the DISPLAY name to report for it. Consumers use it to turn a
// session's recorded ingress-interface id back into a name.
//
// Two properties make it safe to trust the result:
//
//   - A reth member and its reth resolve to the SAME id (that is the point),
//     so the map reports the RETH-relative display name for both. That is the
//     name the operator configured the zone with and the name that means the
//     same thing on either node.
//   - A colliding id — two genuinely different interfaces that fold together,
//     or a config that binds a member and some unrelated interface onto one id
//     — is DROPPED entirely rather than resolved to whichever name won. A
//     dropped id leaves the session with no nameable identity, so the caller
//     falls back to the zone approximation: strictly less precise, never
//     wrong. Guessing would produce exactly the cross-interface match #4983
//     exists to remove.
func BuildStableInterfaceIDs(cfg *Config) map[uint32]string {
	if cfg == nil {
		return nil
	}
	ids := make(map[uint32]string)
	collided := make(map[uint32]struct{})
	claim := func(displayName string) {
		id := InterfaceStableID(cfg, displayName)
		if id == 0 {
			return
		}
		if _, dead := collided[id]; dead {
			return
		}
		prev, seen := ids[id]
		if !seen {
			ids[id] = displayName
			return
		}
		if prev == displayName {
			return
		}
		// Two distinct display names on one id. A reth member and its reth
		// unit legitimately share an id; keep the reth-relative name (the
		// cross-node invariant) and treat anything else as a real collision.
		prevStable := ClusterStableInterfaceName(cfg, prev)
		curStable := ClusterStableInterfaceName(cfg, displayName)
		if prevStable == curStable {
			if displayName == curStable {
				ids[id] = displayName
			}
			return
		}
		delete(ids, id)
		collided[id] = struct{}{}
	}

	RangeInterfaces(cfg, func(ifName string, ifc *InterfaceConfig) {
		claim(ifName)
		RangeUnits(ifc, func(unitNum int, unit *InterfaceUnit) {
			if unitNum == 0 && unit.VlanID == 0 {
				// Unit 0 with no VLAN collapses onto the base interface name
				// everywhere else in the CLI (buildSessionEgressIfaces uses
				// the bare name for it), so do not mint a second display name.
				return
			}
			claim(ifName + "." + strconv.Itoa(unitNum))
		})
	})
	return ids
}
