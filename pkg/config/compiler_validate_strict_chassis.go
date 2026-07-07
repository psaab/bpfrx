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

// validateChassisClusterStrict hard-rejects, at commit / commit-check, a
// chassis-cluster config whose redundancy-group cardinality or ids exceed
// what the HA heartbeat wire format can encode (#4434, codex-172 C172-H02).
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
	return nil
}
