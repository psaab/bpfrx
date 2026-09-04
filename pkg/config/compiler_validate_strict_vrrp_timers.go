package config

import (
	"fmt"
	"sort"
)

// The two VRRP timer bounds that a `vrrp-group <id>` may carry, and the reason
// each one is a bound rather than a preference.
//
// advertise-interval is SECONDS at the config layer. pkg/vrrp converts it
// seconds→milliseconds (vrrp.go) and then milliseconds→centiseconds
// (instance_send.go, `uint16(cfg.AdvertiseInterval / 10)`), and
// pkg/vrrp/packet.go writes the result into the VRRPv3 Max Advert Int field
// under a 12-bit mask:
//
//	binary.BigEndian.PutUint16(buf[4:6], p.MaxAdvertInt&0x0FFF)
//
// 4095 centiseconds is therefore the largest interval that survives the wire,
// so 40 s (4000 cs) is the last whole-second value that encodes and 41 s
// (4100 cs) aliases to 4 cs. The aliasing is silent and asymmetric: the local
// timers use the un-narrowed value while the peer's master-down calculation
// uses the narrowed one, so the two nodes disagree about how long silence must
// last before a takeover — spurious master-down on one side, or a group that
// never notices a dead peer.
//
// preempt hold-time is SECONDS and reaches the runtime un-narrowed
// (`time.Duration(cfg.PreemptHoldTime) * time.Second`, instance_preempt.go), so
// an out-of-range value corrupts nothing on the wire. Its bound exists so that
// the packed spelling agrees with the schema's ValidateInteger(1, 3600) rather
// than accepting a hold a structured spelling of the same config would refuse.
// It is a consistency gate, not a wire-safety one — stated here because the two
// checks in this file have genuinely different severities and a later reader
// should not have to re-derive that.
const (
	MinVRRPAdvertiseInterval = 1
	MaxVRRPAdvertiseInterval = 40
	MinVRRPPreemptHoldTime   = 1
	MaxVRRPPreemptHoldTime   = 3600
)

// validateVRRPGroupTimersStrict hard-rejects, at commit / commit-check, a
// `vrrp-group <id>` whose advertise-interval or preempt hold-time falls outside
// the range its schema leaf already declares (#8483).
//
// It exists for the same reason validateVRRPGroupPriorityStrict does, and the
// mechanism is documented in that file: the structured spellings — flat-set
// `set ... vrrp-group 1 advertise-interval 256` and the braced block — ARE
// gated at the schema layer, but the PACKED hierarchical one-liner
// `vrrp-group 1 virtual-address 10.0.1.100/24 advertise-interval 256;` packs
// the property onto the instance node's Keys, which the schema walker consumes
// as unvalidated identity tokens (walkInstanceChildren, schema_walk.go). This
// compiled-*Config gate catches both spellings because it runs on the typed
// field before any wire narrowing, where 256 is still visible as 256.
//
// The packed spelling is not reachable through `set` — SetPath normalizes
// packed tokens into schema-structured children, so every flat-set spelling is
// already gated. It is reachable through a hierarchical config file
// (`load merge` / `load override`) and through HA peer config sync, which is
// what makes it more than a typo: a packed one-liner authored once propagates
// to the peer.
//
// Zero is NOT an out-of-range value for either field. It is the compiler's
// "unset" sentinel: pkg/vrrp substitutes the 1 s default when
// AdvertiseInterval is 0 (vrrp.go), and treats PreemptHoldTime <= 0 as
// "preempt immediately" (instance_preempt.go). A gate that rejected 0 would
// refuse every vrrp-group that simply does not configure the timer.
//
// On the tolerant load / peer-sync paths the compileExpanded call site
// downgrades this to a warning (opts.lenientVRRPGroupTimers) so an
// already-persisted or peer-synced config an older binary accepted still boots
// (#1960 no-brick).
func validateVRRPGroupTimersStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Deterministic walk (interface name → unit number → group key) so the
	// first-error commit-check message is stable across map-ordered runs,
	// matching validateVRRPGroupPriorityStrict.
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
				if vg.AdvertiseInterval != 0 &&
					(vg.AdvertiseInterval < MinVRRPAdvertiseInterval ||
						vg.AdvertiseInterval > MaxVRRPAdvertiseInterval) {
					return fmt.Errorf("vrrp-group %d advertise-interval %d on %s "+
						"unit %d is out of range %d..%d (the VRRPv3 Max Advert Int "+
						"is a 12-bit centisecond field, RFC 5798 §5.2.7; %d s is "+
						"the last whole-second value that encodes, and a larger "+
						"interval aliases silently — 256 s advertises as 10.24 s, "+
						"so the two nodes disagree about the master-down window) "+
						"— set an advertise-interval in %d..%d, or omit it for the "+
						"1 s default", vg.ID, vg.AdvertiseInterval, ifName, un,
						MinVRRPAdvertiseInterval, MaxVRRPAdvertiseInterval,
						MaxVRRPAdvertiseInterval, MinVRRPAdvertiseInterval,
						MaxVRRPAdvertiseInterval)
				}
				if vg.PreemptHoldTime != 0 &&
					(vg.PreemptHoldTime < MinVRRPPreemptHoldTime ||
						vg.PreemptHoldTime > MaxVRRPPreemptHoldTime) {
					return fmt.Errorf("vrrp-group %d preempt hold-time %d on %s "+
						"unit %d is out of range %d..%d — set a hold-time in "+
						"%d..%d, or omit it to preempt immediately", vg.ID,
						vg.PreemptHoldTime, ifName, un, MinVRRPPreemptHoldTime,
						MaxVRRPPreemptHoldTime, MinVRRPPreemptHoldTime,
						MaxVRRPPreemptHoldTime)
				}
			}
		}
	}
	return nil
}
