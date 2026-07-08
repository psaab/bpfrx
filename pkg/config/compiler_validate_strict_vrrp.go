package config

import (
	"fmt"
	"sort"
)

// MinVRRPGroupID / MaxVRRPGroupID bound the VRRP Virtual Router ID (VRID) that
// a `vrrp-group <id>` block may carry. RFC 5798 §5.2.3 defines the VRID as an
// 8-bit field whose valid range is 1..255 — 0 is not a usable VRID (a router
// that receives an advertisement with VRID 0 has no group 0 to match it
// against, so a strict RFC peer such as Juniper silently discards it). The
// native VRRP engine truncates the configured id straight onto that byte
// (pkg/vrrp/instance.go writes `uint8(vi.cfg.GroupID)` into the VRID field at
// send and matches it on receive, e.g. instance.go:1148/1834/1849), so a
// `vrrp-group 256` wraps to VRID 0 (peer discards → the VIP never masters, an
// HA cold-boot blackhole) and `vrrp-group 257` aliases VRID 1 onto an unrelated
// group (cross-talk / dual-master).
const (
	MinVRRPGroupID = 1
	MaxVRRPGroupID = 255
)

// validateVRRPGroupIDStrict hard-rejects, at commit / commit-check, a
// `vrrp-group <id>` whose id falls outside the RFC 5798 VRID range 1..255
// (#4573, ps-037-A3 B-001).
//
// The config-mode schema documents the `vrrp-group <id>` instance slot as an
// unvalidated identity token (schema_interfaces.go vrrpGroupSchemaNode) — the
// deferral is safe for NON-numeric garbage (parseVRRPGroups drops an
// unparseable id, compiler_interfaces.go), but an OUT-OF-RANGE NUMERIC id is
// stored verbatim and later truncated onto the single VRID wire byte, producing
// a live wrong-VRID instance. This mirrors the chassis redundancy-group id gate
// (validateChassisClusterStrict, MaxHeartbeatRedundancyGroupID) that the schema
// comment cites as its model — that analog was hardened while VRRP was left
// unguarded, and this closes the asymmetry.
//
// On the tolerant load / peer-sync paths the compileExpanded call site
// downgrades this to a warning (opts.lenientVRRPGroupID) so an already-
// persisted or peer-synced config an older binary accepted still boots (#1960
// no-brick); a defensive runtime range check at instance creation
// (pkg/vrrp/manager.go UpdateInstances) refuses to advertise an out-of-range
// VRID for a value that slips through the lenient path.
func validateVRRPGroupIDStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Deterministic walk (interface name → unit number → group key) so the
	// first-error commit-check message is stable across map-ordered runs,
	// matching the compiler_validate_strict.go VRRP containment walk.
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			gkeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				gkeys = append(gkeys, k)
			}
			sort.Strings(gkeys)
			for _, gk := range gkeys {
				vg := unit.VRRPGroups[gk]
				if vg == nil {
					continue
				}
				if vg.ID < MinVRRPGroupID || vg.ID > MaxVRRPGroupID {
					return fmt.Errorf("vrrp-group id %d on %s unit %d is out of "+
						"range %d..%d (the VRRP VRID is one wire byte, RFC 5798 "+
						"§5.2.3; an id above %d truncates on the wire — 256 wraps "+
						"to the reserved VRID 0 and the VIP never masters, 257 "+
						"aliases VRID 1 onto another group) — renumber the "+
						"vrrp-group", vg.ID, ifName, un, MinVRRPGroupID,
						MaxVRRPGroupID, MaxVRRPGroupID)
				}
			}
		}
	}
	return nil
}
