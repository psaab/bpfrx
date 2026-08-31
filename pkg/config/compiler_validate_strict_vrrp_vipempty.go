package config

import (
	"fmt"
	"sort"
)

// vrrpVIPEmptyErr builds the operator-facing rejection for an explicit
// `vrrp-group` carrying no ADVERTISABLE virtual address, or nil when at least
// one address of either family parses.
//
// The predicate is `countVRRPVIPFamilies` — the SAME function the cardinality
// gate uses and the same split pkg/vrrp's send path performs
// (splitVIPsByFamily). That is deliberate rather than convenient: the defect
// being prevented is precisely that sendAdvert emits an IPv4 advert only when
// the IPv4 slice is non-empty and an IPv6 advert only when the IPv6 slice is
// non-empty, so "advertisable" must mean exactly what the send path means by
// it. A private re-implementation here could disagree with the sender and
// admit a group that still advertises nothing (#6539 shared authority).
//
// The two causes are reported SEPARATELY. `virtual-address` absent entirely and
// `virtual-address` present but unparseable produce the same silent
// non-advertising group, but the operator's remedy differs — add the statement,
// versus fix the literal they already wrote — and a single message would send
// half of them looking for the wrong thing.
func vrrpVIPEmptyErr(where string, vips []string) error {
	nV4, nV6 := countVRRPVIPFamilies(vips)
	if nV4 > 0 || nV6 > 0 {
		return nil
	}
	const consequence = " — pkg/vrrp sendAdvert emits an advert for a family " +
		"only when that family's address slice is non-empty, so this group " +
		"would send NOTHING while becomeMaster still published MASTER and " +
		"seated it in the election: a silent non-advertising owner that an " +
		"operator reading `show vrrp` sees as a healthy master"
	if len(vips) == 0 {
		return fmt.Errorf("%s has no virtual-address%s — add a "+
			"`virtual-address` statement, or delete the group",
			where, consequence)
	}
	return fmt.Errorf("%s has %d virtual-address entries and none of them "+
		"parses as an IPv4 or IPv6 address%s — correct the address literals "+
		"(a bare address or CIDR is accepted), or delete the group",
		where, len(vips), consequence)
}

// validateVRRPVIPEmptyStrict hard-rejects, at commit / commit-check, an
// explicit `vrrp-group` whose virtual-address set is empty or entirely
// unparseable (#7577).
//
// This is the LOWER-bound sibling of validateVRRPVIPCountStrict (#6779), split
// out because the two failures differ in kind. An OVERSIZED set claims VIPs and
// advertises nothing, so the peer promotes and both nodes answer for the same
// addresses — a duplicate-address hazard. An EMPTY set claims NO addresses, so
// there is nothing for a second master to collide over; it is a silent no-op
// group. Less harmful, and still wrong: the instance publishes MASTER, occupies
// the election, and emits no adverts, which is indistinguishable from a healthy
// master on every operator surface.
//
// SCOPE: explicit `vrrp-group` blocks ONLY. RETH-derived instances are
// deliberately not checked, because CollectRethInstances already SKIPS a RETH
// with no VIPs — no instance is synthesized, so there is nothing to claim a
// group or occupy an election. Extending this gate to RETH units would reject
// configurations that are correct today and produce no VRRP instance at all.
// That makes the explicit group the only reachable production shape.
//
// REJECT-ONLY, deliberately. The issue offers a second option — extend
// pkg/vrrp's checkAdvertCapacity with a lower bound so UpdateInstances and
// becomeMaster refuse the instance at runtime. That is NOT done here, for two
// reasons. It would change the behaviour of 22 existing pkg/vrrp tests that
// construct VIP-less instances as a convenient state-machine fixture, which is
// a behaviour change riding along with a bug fix. And the two options have very
// different worst cases: a commit-time rejection fails loudly and visibly on a
// config the operator is actively editing, while a runtime refusal removes a
// group from the election on a node that is already running. The bounded
// failure is the right one to ship first.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientVRRPVIPEmpty) so an already-persisted or peer-synced
// config an older binary accepted still BOOTS (#1960 no-brick). Unlike the
// #6779 case there is no runtime guard behind that downgrade — pkg/vrrp will
// seat the VIP-less instance — so the leniently-loaded config keeps exactly
// today's behaviour, which is the point: the tolerant path must not brick a
// node over a group that is merely inert.
func validateVRRPVIPEmptyStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	// Deterministic walk so the first-error commit-check message is stable
	// across map-ordered runs, matching the sibling strict validators.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, ifName := range names {
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
				where := fmt.Sprintf("interfaces %s unit %d vrrp-group %d",
					ifName, un, vg.ID)
				if err := vrrpVIPEmptyErr(where, vg.VirtualAddresses); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
