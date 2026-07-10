package config

import (
	"fmt"
	"sort"
)

// MinVRRPPriority / MaxVRRPPriority bound the VRRP priority that a
// `vrrp-group <id> priority <n>` may carry. RFC 5798 §5.2.4 defines the
// Priority as an 8-bit field: 0 is reserved to signal that the current master
// has stopped participating (a resignation that forces backups to take over
// immediately) and 255 is the address owner; the usable configured range is
// 1..255. The native VRRP engine truncates the configured priority straight
// onto that byte (pkg/vrrp/instance.go writes `uint8(priority)` into the
// advertisement's Priority field in sendAdvert), so a `priority 256` wraps to 0
// — the group advertises RESIGNATION on every beacon and never holds the VIP,
// an HA blackhole — and `priority 300` aliases to 44, silently demoting the
// group below its intended weight.
const (
	MinVRRPPriority = 1
	MaxVRRPPriority = 255
)

// validateVRRPGroupPriorityStrict hard-rejects, at commit / commit-check, a
// `vrrp-group <id> priority <n>` whose priority falls outside the RFC 5798
// range 1..255 (#5184).
//
// The structured spellings — flat-set `set ... vrrp-group 1 priority 256` and
// the braced block — ARE gated at the schema layer by the `priority` leaf's
// ValidateInteger(1,255) (schema_interfaces.go vrrpGroupSchemaNode). But the
// PACKED hierarchical one-liner `vrrp-group 1 priority 256;` packs the property
// onto the instance node's Keys, which the schema walker consumes as unvalidated
// identity tokens (walkInstanceChildren, schema_walk.go) — so the out-of-range
// priority slips past SchemaValidate, parseVRRPGroups stores it verbatim into
// the wide `int` VRRPGroup.Priority field (compiler_interfaces.go), and only the
// later `uint8(priority)` narrowing in sendAdvert corrupts it. This compiled-
// *Config gate catches BOTH spellings (it runs on the typed Priority before any
// wire narrowing, where 256 is still visible as 256), exactly as
// validateVRRPGroupIDStrict backstops the equally-unvalidated `vrrp-group <id>`
// instance slot (#4573).
//
// On the tolerant load / peer-sync paths the compileExpanded call site
// downgrades this to a warning (opts.lenientVRRPGroupPriority) so an already-
// persisted or peer-synced config an older binary accepted still boots (#1960
// no-brick).
func validateVRRPGroupPriorityStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Deterministic walk (interface name → unit number → group key) so the
	// first-error commit-check message is stable across map-ordered runs,
	// matching validateVRRPGroupIDStrict.
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
				if vg.Priority < MinVRRPPriority || vg.Priority > MaxVRRPPriority {
					return fmt.Errorf("vrrp-group %d priority %d on %s unit %d is "+
						"out of range %d..%d (the VRRP priority is one wire byte, "+
						"RFC 5798 §5.2.4; a priority above %d truncates on the wire "+
						"— 256 wraps to the reserved priority 0 and the group "+
						"advertises resignation and never masters the VIP, 300 "+
						"aliases to 44) — set a priority in %d..%d", vg.ID,
						vg.Priority, ifName, un, MinVRRPPriority, MaxVRRPPriority,
						MaxVRRPPriority, MinVRRPPriority, MaxVRRPPriority)
				}
			}
		}
	}
	return nil
}
