package config

import (
	"fmt"
	"sort"
)

// MaxHeartbeatRedundancyGroups is the largest number of chassis-cluster
// redundancy groups the HA heartbeat wire format can advertise. The
// heartbeat group-count field is a single byte
// (pkg/cluster/heartbeat.go marshalHeartbeatBody writes
// buf[8] = uint8(len(pkt.Groups))), so a 256th group would overflow the
// count to 0 while 256 records are still written — the count byte and the
// body desync and the peer mis-parses the group section. (The marshaler
// also indexes a fixed maxHeartbeatSize buffer, so ~293 groups panic on
// write.) 255 is the binding uint8 count limit.
const MaxHeartbeatRedundancyGroups = 255

// MaxHeartbeatRedundancyGroupID is the largest redundancy-group id the HA
// heartbeat wire format can carry. The per-group GroupID field is a single
// byte (pkg/cluster/heartbeat.go HeartbeatGroup.GroupID is uint8, populated
// via uint8(rg.GroupID) in heartbeat_manager.go buildHeartbeat), so an id
// above 255 truncates on the wire and two distinct redundancy groups would
// then collide on the same GroupID byte and corrupt peer election.
const MaxHeartbeatRedundancyGroupID = 255

// MinRedundancyGroupNodePriority / MaxRedundancyGroupNodePriority bound a
// redundancy-group node priority (Junos vSRX 1..254). 0 is treated as unset
// (VRRP maps pri==0 to the default 100) and 255 is the RFC 5798 IP-owner
// reserved value; both are excluded. The schema `priority` leaf
// (schema_chassis.go ValidateInteger(1,254)) enforces this on the flat-set /
// expanded shape, but the packed hierarchical one-liner
// `node 0 priority <v>;` carries the value inside the node instance's own key
// tail, which the schema walker consumes as identity and never validates —
// compileChassis still reads it into NodePriorities under no bound (#4880). The
// value feeds VRRP, which truncates it to uint8 on the wire
// (pkg/vrrp/instance.go), while the private control-link election uses the raw
// int (pkg/cluster/group_state.go), so an out-of-range priority both truncates
// on the wire and diverges the two election views.
const (
	MinRedundancyGroupNodePriority = 1
	MaxRedundancyGroupNodePriority = 254
)

// MinInterfaceMonitorWeight / MaxInterfaceMonitorWeight bound a
// redundancy-group `interface-monitor <if> weight <w>` (Junos vSRX 0..255 —
// the same range the schema already types on the sibling ip-monitoring
// weights, schema_chassis.go `global-weight` / `global-threshold` / per-target
// `weight`).
//
// #6549: the interface-monitor leaf packs `<ifname> weight <n>` onto ONE node
// key, so it has NO typed schema leaf (schema_chassis.go documents the
// deferral: typing it would need a children/wildcard map, which flips
// SetPath's replace-vs-container grouping) and compileChassis reads the weight
// with strconv.Atoi under no bound. The weight is the DEBT subtracted from the
// redundancy group's weight, which starts at 255
// (pkg/cluster/election.go recalcWeight: `rg.Weight = 255 - totalLost`, with
// only a `< 0` floor and no ceiling), so a NEGATIVE weight on a down monitor
// raises rg.Weight ABOVE 255.
//
// That is the divergence: the LOCAL election reads the raw wide int
// (EffectivePriority = priority * weight / 255, election.go), while the
// heartbeat advertises the same weight through a SINGLE BYTE
// (HeartbeatGroup.Weight is uint8, populated via `uint8(rg.Weight)` in
// heartbeat_manager.go buildHeartbeat). With `weight -100` on a down monitor
// the local node holds 355 and the peer receives uint8(355) == 99, so at base
// priority 100 the local node computes its own effective priority as 139 while
// the peer computes 38 for it. The two nodes then elect from DIFFERENT views of
// identical state and can both take primary — duplicate VIP and duplicate RETH
// virtual MAC on the LAN. Same failure shape (wide local int vs single wire
// byte) as the #4880 node-priority gate above.
//
// The runtime carries the matching belts: ClampInterfaceMonitorWeight bounds
// the configured debt where pkg/cluster reads it, and rgWeightFromDebt bounds
// rg.Weight itself to the same [0,255] domain at every recompute site, so a
// config that reaches the tolerant load / peer-sync path (where this gate is
// downgraded to a warning per #1960) still cannot diverge.
const (
	MinInterfaceMonitorWeight = 0
	MaxInterfaceMonitorWeight = 255
)

// ClampInterfaceMonitorWeight bounds a configured interface-monitor weight to
// [MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight]. It returns the
// effective weight and whether clamping occurred.
//
// The strict commit / commit-check path never needs this — validateChassisCluster
// Strict rejects an out-of-range weight outright. It exists for the TOLERANT
// paths (Store.Load of a persisted config, Store.SyncApply of a peer-pushed
// one), which downgrade that gate to a warning so an already-persisted config
// still BOOTS (#1960 no-brick). Without the clamp those paths would install the
// out-of-range debt verbatim and reproduce exactly the local-vs-wire divergence
// the gate exists to prevent. Mirrors ClampGratuitousARPCount (#5695): the
// commit path signals, the runtime bounds.
func ClampInterfaceMonitorWeight(w int) (int, bool) {
	switch {
	case w < MinInterfaceMonitorWeight:
		return MinInterfaceMonitorWeight, true
	case w > MaxInterfaceMonitorWeight:
		return MaxInterfaceMonitorWeight, true
	default:
		return w, false
	}
}

// validateChassisClusterStrict hard-rejects, at commit / commit-check, a
// chassis-cluster config whose redundancy-group cardinality or ids exceed
// what the HA heartbeat wire format can encode (#4434, codex-172 C172-H02),
// whose per-RG node priority is out of the VRRP range (#4880), or whose
// interface-monitor weight is out of the [0,255] heartbeat weight domain
// (#6549).
//
// The heartbeat count byte and per-group id byte are both uint8. There is
// no schema-level value validation on the `redundancy-group <id>` instance
// slot (schema_chassis.go documents it as an unvalidated identity token),
// and compileChassis parses the id with strconv.Atoi under no bound, so an
// operator could commit 256+ groups (count byte wraps to 0 — the peer sees
// "zero groups" while the body still carries them) or a group id > 255 (the
// id byte truncates and aliases another group). Both silently corrupt
// election on the wire.
//
// On the tolerant load / peer-sync paths the compileExpanded call site
// downgrades this to a warning (opts.lenientChassisRG) so an already-
// persisted or peer-synced config still boots (#1960 no-brick); the
// heartbeat marshaler independently caps the group section to the wire
// limit (pkg/cluster/heartbeat.go marshalHeartbeatBody, maxHeartbeatGroups),
// so a leniently-loaded over-size config is bounded on the wire, not a
// panic.
func validateChassisClusterStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups

	if len(rgs) > MaxHeartbeatRedundancyGroups {
		return fmt.Errorf("chassis cluster: %d redundancy-groups exceeds the "+
			"heartbeat wire limit of %d (the heartbeat group-count field is one "+
			"byte, so %d groups would advertise as a count of 0 and desync the "+
			"peer's group parse) — reduce the number of redundancy-groups",
			len(rgs), MaxHeartbeatRedundancyGroups, len(rgs))
	}

	// RedundancyGroups is built from a map-ordered AST walk; sort the ids so
	// the first-error commit-check message is deterministic across runs.
	ids := make([]int, 0, len(rgs))
	for _, rg := range rgs {
		if rg == nil { // #3494: tolerant/HA-sync path may carry a nil entry.
			continue
		}
		ids = append(ids, rg.ID)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if id < 0 || id > MaxHeartbeatRedundancyGroupID {
			return fmt.Errorf("chassis cluster: redundancy-group id %d is out of "+
				"range 0..%d (the heartbeat per-group id field is one byte; an id "+
				"above %d truncates on the wire and collides with another "+
				"redundancy-group) — renumber the redundancy-group",
				id, MaxHeartbeatRedundancyGroupID, MaxHeartbeatRedundancyGroupID)
		}
	}

	// #4880: node-priority range gate. The schema `priority` leaf validates the
	// flat-set / expanded shape, but the packed hierarchical one-liner
	// `node 0 priority <v>;` bypasses the walker (see
	// MinRedundancyGroupNodePriority doc). compileChassis stores whatever the
	// operator wrote into NodePriorities, and it flows to VRRP (uint8-truncated
	// on the wire) and the private election (raw int) — so re-assert the
	// [1,254] range on the compiled priorities here, closing BOTH shapes.
	// Iterate rgs sorted by id, then node ids, so the first-error message is
	// deterministic across the map-ordered AST walk.
	rgByID := make([]*RedundancyGroup, 0, len(rgs))
	for _, rg := range rgs {
		if rg != nil { // #3494: tolerant/HA-sync path may carry a nil entry.
			rgByID = append(rgByID, rg)
		}
	}
	sort.Slice(rgByID, func(i, j int) bool { return rgByID[i].ID < rgByID[j].ID })
	for _, rg := range rgByID {
		nodeIDs := make([]int, 0, len(rg.NodePriorities))
		for nodeID := range rg.NodePriorities {
			nodeIDs = append(nodeIDs, nodeID)
		}
		sort.Ints(nodeIDs)
		for _, nodeID := range nodeIDs {
			pri := rg.NodePriorities[nodeID]
			if pri < MinRedundancyGroupNodePriority || pri > MaxRedundancyGroupNodePriority {
				return fmt.Errorf("chassis cluster: redundancy-group %d node %d priority "+
					"%d is out of range %d..%d (0 is treated as unset and 255 is the "+
					"RFC 5798 IP-owner reserved value; the priority feeds VRRP and "+
					"truncates to a single wire byte, and the private control-link "+
					"election reads the raw value) — set a priority in %d..%d",
					rg.ID, nodeID, pri,
					MinRedundancyGroupNodePriority, MaxRedundancyGroupNodePriority,
					MinRedundancyGroupNodePriority, MaxRedundancyGroupNodePriority)
			}
		}

		// #6549: interface-monitor weight range gate. The leaf packs
		// `<ifname> weight <n>` onto one node key and has no typed schema leaf
		// at all (unlike the ip-monitoring weight siblings), so the range is
		// asserted here on the compiled int — which covers BOTH parser shapes
		// (flat-set and hierarchical) at once. Out of range, the debt makes
		// rg.Weight leave the [0,255] domain the single-byte heartbeat field
		// can carry, and the local election and the peer's view of it diverge
		// (see MinInterfaceMonitorWeight). InterfaceMonitors is an
		// AST-order slice (not a map), so the first-error message is already
		// deterministic without sorting.
		for _, im := range rg.InterfaceMonitors {
			if im == nil { // tolerant/HA-sync path may carry a nil entry (#3494).
				continue
			}
			if im.Weight < MinInterfaceMonitorWeight || im.Weight > MaxInterfaceMonitorWeight {
				return fmt.Errorf("chassis cluster: redundancy-group %d interface-monitor %s "+
					"weight %d is out of range %d..%d (the weight is subtracted from the "+
					"redundancy-group weight, which the heartbeat advertises through a single "+
					"wire byte while the local election reads the raw value — an out-of-range "+
					"weight makes the two nodes compute different effective priorities from "+
					"identical state and both elect primary) — set a weight in %d..%d",
					rg.ID, im.Interface, im.Weight,
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight,
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight)
			}
		}
	}
	return nil
}
