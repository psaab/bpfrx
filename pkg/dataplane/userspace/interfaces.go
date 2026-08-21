package userspace

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// Keep logical-only synthetic ifindexes in a high private range so they do
// not collide with kernel-assigned ifindexes in practical deployments, while
// remaining positive int32 values for protocol compatibility.
//
// These bounds are package vars (not consts) ONLY so a test can temporarily
// shrink the window to drive the range-exhaustion path through the real
// buildInterfaceSnapshots caller (#5557); production never mutates them and the
// initial values are identical to the pre-#5557 constants.
var (
	syntheticInterfaceIfindexMin = 1 << 30
	syntheticInterfaceIfindexMax = (1 << 30) + (1 << 20) - 1
)

// syntheticIfindexExhausted is the sentinel syntheticLogicalIfindex returns
// when the whole synthetic range is already claimed. It is a negative value so
// it can never be mistaken for a real (positive) ifindex; the caller skips the
// affected unit and logs rather than crashing the daemon (#5557).
const syntheticIfindexExhausted = -1

// syntheticLogicalIfindex assigns a unique logical-only ifindex from the
// private synthetic range. It returns syntheticIfindexExhausted (a
// negative sentinel) when every slot in the range is already used — an
// exhaustion that is unreachable in practice (it needs >1<<20 logical-only
// VLAN units on one box) but must degrade gracefully instead of panicking
// and crash-looping the daemon (#5557).
func syntheticLogicalIfindex(name string, vlanID int, used map[int]struct{}) int {
	if used == nil {
		used = make(map[int]struct{})
	}
	const fnvOffset = uint32(2166136261)
	const fnvPrime = uint32(16777619)
	hash := fnvOffset
	for _, b := range []byte(fmt.Sprintf("%s/%d", name, vlanID)) {
		hash ^= uint32(b)
		hash *= fnvPrime
	}
	span := syntheticInterfaceIfindexMax - syntheticInterfaceIfindexMin + 1
	start := syntheticInterfaceIfindexMin + int(hash%uint32(span))
	for offset := 0; offset < span; offset++ {
		candidate := syntheticInterfaceIfindexMin + ((start - syntheticInterfaceIfindexMin + offset) % span)
		if _, exists := used[candidate]; exists {
			continue
		}
		used[candidate] = struct{}{}
		return candidate
	}
	slog.Error("userspace snapshot: exhausted synthetic ifindex range; skipping logical-only unit",
		"name", name,
		"vlan", vlanID,
		"hash", hash,
		"tried", span,
		"range_min", syntheticInterfaceIfindexMin,
		"range_max", syntheticInterfaceIfindexMax,
	)
	return syntheticIfindexExhausted
}

func shouldUseLogicalOnlyParentBoundRethVLAN(cfg *config.Config, ifName string, unit *config.InterfaceUnit, childIfindex int, parentIfindex int) bool {
	if cfg == nil || unit == nil || childIfindex > 0 || parentIfindex <= 0 || unit.VlanID <= 0 {
		return false
	}
	if !strings.HasPrefix(ifName, "reth") {
		return false
	}
	return config.LinuxIfName(cfg.ResolveReth(ifName)) != config.LinuxIfName(ifName)
}

// userspaceBindTargetNetdev returns the Linux netdev that the userspace
// dataplane's AF_XDP socket actually binds to for a snapshot interface.
// This is the SINGLE SOURCE OF TRUTH on the Go control plane for the
// VLAN-unit binding contract (#2917).
//
// A VLAN sub-interface (e.g. reth0.80 → Linux netdev `ge-0-0-2.80`) is a
// SOFTWARE netdev with no hardware RX queues of its own: its VLAN-tagged
// frames are delivered on the PHYSICAL PARENT's hardware queues
// (`ge-0-0-2`) and the kernel demuxes the tag. Zero-copy AF_XDP therefore
// MUST bind the parent physical netdev, never the `.80` unit netdev (which
// would fail or fall back to copy/generic and, in the queue planner,
// collapse the per-interface queue_count to its lone software queue — the
// #3091 single-worker regression).
//
// This rule mirrors the Rust planner's `vlan_child_parent_netdev`
// (`userspace-dp/src/server/helpers.rs`) EXACTLY: redirect to the parent
// only when the row is a distinct VLAN child (VLANID != 0, a non-empty
// ParentLinuxName, and a parent netdev that differs from the row's own
// netdev). For a physical interface or a non-VLAN unit the parent and own
// netdev are the same netdev, so the bind target is the row's own
// LinuxName — identical to what `replan_queues` pushes as a candidate. The
// two planes MUST stay in lock-step; the cross-plane parity test in
// snapshot_allowlist_test.go and the Rust SSOT test in main_tests.rs guard
// against re-divergence.
func userspaceBindTargetNetdev(iface InterfaceSnapshot) string {
	if iface.VLANID != 0 && iface.ParentLinuxName != "" && iface.ParentLinuxName != iface.LinuxName {
		return iface.ParentLinuxName
	}
	return iface.LinuxName
}

// UserspaceBoundLinuxInterfaces returns the deduplicated, sorted set of
// Linux interface names that the userspace dataplane will bind AF_XDP
// sockets to for the given compiled config. This is the authoritative
// allowlist used by the D3 RSS indirection path (#797) so that we only
// reshape RSS on interfaces we actually steer into AF_XDP workers —
// siblings like a spare mlx5 PF or a management netdev must not be
// touched.
//
// Scope mirrors buildUserspaceIngressIfindexes() and
// userspaceSkipsIngressInterface(): include zoned non-tunnel interfaces
// excluding fxp*, em*, fab*, lo0, mgmt/control zones, and RETH member
// children; plus every fabric's parent member (fab0/fab1 themselves are
// IPVLAN overlays and are excluded above, but their physical parent is
// where AF_XDP binds). For zoned VLAN units whose parent is the physical
// interface, we emit the parent Linux name — that is the netdev the
// AF_XDP socket actually binds to.
//
// Returns nil on nil config. Never returns an error: this is a
// best-effort derivation used to scope a best-effort optimization.
func UserspaceBoundLinuxInterfaces(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	ucfg := deriveUserspaceConfig(cfg)
	// Build a snapshot without depending on ifindex resolution — the
	// allowlist is by Linux name (what `ethtool` consumes), so ifindex
	// lookups are unnecessary here. We reuse the shared filter via the
	// real builder to stay in lock-step with binding logic.
	// #2514: buildSnapshot can return an error (e.g. an unresolvable
	// address-book content-ID collision). This is a best-effort allowlist
	// derivation, so on error we degrade to nil rather than propagating —
	// the real apply path (ApplyConfig) surfaces the same error to the
	// operator and rejects the commit.
	snap, err := buildSnapshot(cfg, ucfg, 0, 0)
	if err != nil || snap == nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for _, iface := range snap.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		// #2917: resolve the AF_XDP bind target through the single
		// VLAN-unit binding contract (userspaceBindTargetNetdev), which
		// mirrors the Rust planner's vlan_child_parent_netdev rule
		// exactly. A VLAN sub-interface binds its physical PARENT netdev;
		// everything else binds its own netdev.
		add(userspaceBindTargetNetdev(iface))
	}
	for _, fab := range snap.Fabrics {
		add(fab.ParentLinuxName)
	}
	sort.Strings(out)
	return out
}

func buildInterfaceSnapshots(cfg *config.Config) []InterfaceSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	zoneByInterface := buildInterfaceZoneMap(cfg)
	ifaceRoutingInstance := buildInterfaceRoutingInstances(cfg)
	usedSyntheticIfindexes := make(map[int]struct{})
	// Build RETH RG lookup: physical member → RETH's RedundancyGroup.
	// Physical members have RedundantParent set but RedundancyGroup=0;
	// the RG is on the RETH. Without this, flow cache HA checks on
	// RETH member egress interfaces return owner_rg=0 and bypass
	// HA active/inactive validation, causing stale forwarding after failover.
	rethRG := make(map[string]int)
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" {
			if reth := cfg.Interfaces.Interfaces[ifc.RedundantParent]; reth != nil && reth.RedundancyGroup > 0 {
				rethRG[ifc.Name] = reth.RedundancyGroup
			}
		}
	}
	// #6722: the operator's LITERAL zone bindings — fanned DOWN onto a bare
	// reference's units, which is what that reference means, but never fanned UP
	// from a unit to its base, which is the derivation that manufactures a claim
	// about a sibling identity. stampEgressZones (run after this loop) needs the
	// provenance; see authoredZoneRefs in zones.go.
	//
	// Bindings to a zone the StableZoneID quarantine will DROP are removed here
	// rather than scrubbed afterwards. quarantineCollidingZones runs after this
	// builder and unzones the colliding zone's interfaces so they fail closed;
	// scrubbing the egress answer at that point would be wrong, because losing
	// one of two colliding bindings on an ifindex turns it from CONTESTED into
	// unanimous and the survivor's zone is then the right answer. The zone-name
	// set is the same one the quarantine uses — buildZoneSnapshots publishes
	// exactly cfg.Security.Zones — so the two cannot disagree.
	authored := authoredZoneRefs(cfg)
	if dropped := quarantinedZoneNames(cfg); len(dropped) > 0 {
		for ref, zone := range authored {
			if _, drop := dropped[zone]; drop {
				delete(authored, ref)
			}
		}
	}
	// Parallel to `out`: the egress-zone identity of each emitted row. Collected
	// here rather than re-derived afterwards because the loop is where the
	// aliasing is actually performed — `linuxUnit` vs `parentLinux` is the fact
	// that decides whether a unit collapses onto its base netdev.
	idents := make([]egressRowIdentity, 0, len(cfg.Interfaces.Interfaces))
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]InterfaceSnapshot, 0, len(names))
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxName := snapshotLinuxName(cfg, name, iface, nil)
		ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(linuxName)
		// Use the interface's own RG, or inherit from RETH parent.
		rg := iface.RedundancyGroup
		if rg <= 0 {
			rg = rethRG[name]
		}
		out = append(out, InterfaceSnapshot{
			Name:            name,
			Zone:            zoneByInterface[name],
			RoutingInstance: ifaceRoutingInstance[name],
			LinuxName:       linuxName,
			ParentLinuxName: "",
			Ifindex:         ifindex,
			ParentIfindex:   0,
			RXQueues:        userspaceRXQueueCount(linuxName),
			VLANID:          0,
			LocalFabric:     iface.LocalFabricMember,
			RedundancyGroup: rg,
			UnitCount:       len(iface.Units),
			Tunnel:          iface.Tunnel != nil,
			MTU:             mtu,
			HardwareAddr:    hardwareAddr,
			Addresses:       addresses,
		})
		idents = append(idents, egressRowIdentity{owner: name, identity: name})
		if len(iface.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil {
				continue
			}
			var cosUnit *config.CoSInterfaceUnit
			if cfg.ClassOfService != nil {
				if cosIface := cfg.ClassOfService.Interfaces[name]; cosIface != nil {
					cosUnit = cosIface.Units[unitNum]
				}
			}
			unitName := fmt.Sprintf("%s.%d", name, unitNum)
			parentLinux := snapshotLinuxName(cfg, name, iface, nil)
			parentIfindex, parentMTU, parentHardwareAddr, _ := buildLinkSnapshot(parentLinux)
			parentRXQueues := userspaceRXQueueCount(parentLinux)
			linuxUnit := snapshotLinuxName(cfg, name, iface, unit)
			ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(linuxUnit)
			rxQueues := userspaceRXQueueCount(linuxUnit)
			logicalOnly := false
			// Bondless RETH VLAN units can transmit through the parent
			// AF_XDP netdev without a Linux VLAN child. Keep a unique
			// logical ifindex for Rust FIB/filter/CoS state, while the
			// existing ParentIfindex path remains the socket bind target.
			if shouldUseLogicalOnlyParentBoundRethVLAN(cfg, name, unit, ifindex, parentIfindex) {
				ifindex = syntheticLogicalIfindex(unitName, unit.VlanID, usedSyntheticIfindexes)
				if ifindex == syntheticIfindexExhausted {
					// Range exhausted (unreachable in practice; already
					// logged in syntheticLogicalIfindex). Skip this unit
					// rather than emit a snapshot with a bogus/negative
					// ifindex — degrade gracefully instead of crashing the
					// daemon (#5557).
					continue
				}
				logicalOnly = true
				if mtu == 0 {
					mtu = parentMTU
				}
				if hardwareAddr == "" {
					hardwareAddr = parentHardwareAddr
				}
				if rxQueues == 0 {
					rxQueues = parentRXQueues
				}
			}
			addresses = mergeInterfaceAddressSnapshots(addresses, buildConfiguredAddressSnapshots(unit.Addresses))
			out = append(out, InterfaceSnapshot{
				Name:                      unitName,
				Zone:                      zoneByInterface[unitName],
				RoutingInstance:           ifaceRoutingInstance[unitName],
				LinuxName:                 linuxUnit,
				ParentLinuxName:           parentLinux,
				Ifindex:                   ifindex,
				ParentIfindex:             parentIfindex,
				LogicalOnly:               logicalOnly,
				RXQueues:                  rxQueues,
				VLANID:                    unit.VlanID,
				LocalFabric:               iface.LocalFabricMember,
				RedundancyGroup:           rg, // inherit resolved RG (RETH parent or own)
				UnitCount:                 0,
				Tunnel:                    iface.Tunnel != nil || unit.Tunnel != nil,
				MTU:                       mtu,
				HardwareAddr:              hardwareAddr,
				Addresses:                 addresses,
				FilterInputV4:             unit.FilterInputV4,
				FilterOutputV4:            unit.FilterOutputV4,
				FilterInputV6:             unit.FilterInputV6,
				FilterOutputV6:            unit.FilterOutputV6,
				CoSShapingRateBytesPerSec: coSUnitShapingRate(cosUnit),
				CoSBurstSize:              coSUnitBurstSize(cosUnit),
				CoSSchedulerMap:           coSUnitSchedulerMap(cosUnit),
				CoSDSCPClassifier:         coSUnitDSCPClassifier(cosUnit),
				CoSIEEE8021Classifier:     coSUnitIEEE8021Classifier(cosUnit),
				CoSDSCPRewriteRule:        coSUnitDSCPRewriteRule(cosUnit),
				// #1614 A1/A2: per-interface oversubscription policy
				// + priority-low min-share. All default-zero/empty
				// preserves current scheduler bit-for-bit.
				CoSOversubscriptionPolicy:            coSUnitOversubscriptionPolicy(cosUnit),
				CoSOversubscriptionGuaranteeFraction: coSUnitOversubscriptionFraction(cosUnit),
				CoSPriorityLowMinShareBytes:          coSUnitPriorityLowMinShare(cosUnit),
			})
			// UNIT 0 that lands on its base's netdev is not a separate egress
			// identity: it IS the interface. Junos treats unit 0 of an untagged
			// interface as the interface, and `snapshotLinuxName` collapses it
			// onto the base device to match.
			//
			// The two halves are NOT equally load-bearing, and the difference is
			// measured rather than asserted:
			//
			//	drop `unitNum == 0`         -> RED. TestContestedNetdevOwnership-
			//	  FailsClosed_6722/two-tunnel-units-on-one-device. `TunnelNameMap`
			//	  maps EVERY unit of an interface-level WireGuard tunnel onto the
			//	  tunnel netdev, so `wg0.0` and `wg0.1` are one device but two
			//	  logical interfaces; folding `wg0.1` onto `wg0` collapses the two
			//	  identities into one, the ifindex coheres, and the zone authored
			//	  on `wg0.1` decides for the deliberately unzoned `wg0.0`.
			//	drop `linuxUnit == parentLinux` -> SURVIVOR, and inert for a
			//	  reason that does not depend on enumerating shapes. The clause
			//	  can only CHANGE an identity string for a unit whose netdev is
			//	  not its base's; such a unit is on a different IFINDEX from the
			//	  base row, so it lands in a different bucket in stampEgressZones
			//	  and its identity never meets the base row's. And the only reader
			//	  of the identity strings, egressIdentitiesCohere, decides from
			//	  the OWNERS in a bucket, which this clause never alters. So the
			//	  fold can matter only by merging two identity KEYS inside ONE
			//	  bucket, and a differing netdev name is precisely what puts them
			//	  in two. More than one config produces such a unit — a VLAN
			//	  unit 0 on `<dev>.<vlan>`, and a RETH whose unit 0 carries a
			//	  per-unit tunnel — which is why the argument is stated as the
			//	  bucket property rather than as a list: a list is what #6722's
			//	  four earlier spellings were, and each was holed by the next
			//	  shape. Measured rather than argued: a differential dump of
			//	  per-ifindex EgressZone over 18 config shapes — every shape this
			//	  file's cells use, plus a VLAN unit 0 on its own netdev, which is
			//	  the only kind of unit the clause can reach — is byte-identical
			//	  with and without it, 36 ifindex rows unchanged, and the whole Go
			//	  suite stays green.
			//
			// It is kept as an explicit statement of the rule ("unit 0 that lands
			// on its base's netdev IS the interface"), not as a guard that
			// currently discriminates. If `snapshotLinuxName` ever puts a VLAN
			// unit back on the base ifindex, this is the clause that keeps the
			// fold correct; until then, removing it would be behaviour-preserving
			// and the comment must not claim otherwise.
			unitIdentity := unitName
			if unitNum == 0 && linuxUnit == parentLinux {
				unitIdentity = name
			}
			idents = append(idents, egressRowIdentity{owner: name, identity: unitIdentity, isUnit: true})
		}
	}
	// #6722: decide each ifindex's EGRESS zone here, from the operator's authored
	// bindings and this loop's own aliasing, and stamp the answer on every row.
	stampEgressZones(cfg, out, idents, authored)
	// #3362: stamp the per-interface host-inbound OVERRIDE onto each snapshot so
	// the Rust dataplane can key the host-inbound admission check by ingress
	// interface. Carried only for an interface that declared an interface-level
	// stanza and is NOT a management/cluster-control lifeline (matching the nft
	// primary path, which excludes lifeline addresses from host-inbound deny
	// scoping). The carried set is the EFFECTIVE union of the zone-level set and
	// the override, so the Rust side enforces it as-is without re-deriving the
	// union. HostInboundConfigured marks a present override (even an empty one →
	// fail-closed) so an old Go binary that omits the field is distinguishable.
	if overrideByIface := buildInterfaceHostInboundMap(cfg); len(overrideByIface) > 0 {
		lifelines := hostInboundLifelineSet(cfg)
		for i := range out {
			ovr := overrideByIface[out[i].Name]
			zone := cfg.Security.Zones[out[i].Zone]
			if ovr == nil || zone == nil ||
				hostInboundLifelineInterface(out[i].Name, lifelines) {
				continue
			}
			svc, proto := unionHostInboundTokens(zone.HostInboundTraffic, ovr)
			out[i].HostInboundConfigured = true
			out[i].HostInboundSystemServices = svc
			out[i].HostInboundProtocols = proto
		}
	}
	return out
}

func coSUnitShapingRate(unit *config.CoSInterfaceUnit) uint64 {
	if unit == nil {
		return 0
	}
	return unit.ShapingRateBytes
}

func coSUnitBurstSize(unit *config.CoSInterfaceUnit) uint64 {
	if unit == nil {
		return 0
	}
	return unit.BurstSizeBytes
}

func coSUnitSchedulerMap(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.SchedulerMap
}

// #1614 A1: oversubscription-policy snapshot helpers. Empty string
// maps to Proportional (default) on the Rust side.
func coSUnitOversubscriptionPolicy(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.OversubscriptionPolicy
}

func coSUnitOversubscriptionFraction(unit *config.CoSInterfaceUnit) float64 {
	if unit == nil {
		return 0
	}
	return unit.OversubscriptionGuaranteeFraction
}

// #1614 A2: priority-low min-share snapshot helper.
func coSUnitPriorityLowMinShare(unit *config.CoSInterfaceUnit) uint64 {
	if unit == nil {
		return 0
	}
	return unit.PriorityLowMinShareBytes
}

func coSUnitDSCPClassifier(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.DSCPClassifier
}

func coSUnitIEEE8021Classifier(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.IEEE8021Classifier
}

func coSUnitDSCPRewriteRule(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.DSCPRewriteRule
}

// NOTE: Keep in sync with (*Config).ResolveKernelIfName in
// pkg/config/types.go. The two implementations have intentional
// scope deltas (snapshotLinuxName does not implement IRB), but the
// shared cases must match. See drift-guard test in this package.
func snapshotLinuxName(cfg *config.Config, ifName string, iface *config.InterfaceConfig, unit *config.InterfaceUnit) string {
	if iface == nil {
		return config.LinuxIfName(ifName)
	}
	if unit != nil {
		if tunnelNames := cfg.TunnelNameMap(); len(tunnelNames) > 0 {
			ref := fmt.Sprintf("%s.%d", ifName, unit.Number)
			if linuxName, ok := tunnelNames[ref]; ok && linuxName != "" {
				return linuxName
			}
		}
		if unit.VlanID > 0 {
			return fmt.Sprintf("%s.%d", config.LinuxIfName(cfg.ResolveReth(ifName)), unit.VlanID)
		}
		if strings.HasPrefix(ifName, "reth") {
			if unit.Number == 0 {
				return config.LinuxIfName(cfg.ResolveReth(ifName))
			}
			return config.LinuxIfName(cfg.ResolveReth(fmt.Sprintf("%s.%d", ifName, unit.Number)))
		}
		if unit.Number == 0 {
			return config.LinuxIfName(ifName)
		}
		return config.LinuxIfName(fmt.Sprintf("%s.%d", ifName, unit.Number))
	}
	if strings.HasPrefix(ifName, "reth") {
		return config.LinuxIfName(cfg.ResolveReth(ifName))
	}
	return config.LinuxIfName(ifName)
}

// egressRowIdentity is the egress-zone identity of one emitted snapshot row,
// recorded by buildInterfaceSnapshots as it emits (#6722).
//
//   - owner    — the CONFIGURED interface this row belongs to. For a unit row
//     that is the base interface name, not a string split of the row name: an
//     interface may legally be NAMED with a dot (`ge-0/0/1.100`), and splitting
//     would silently reattribute it to a different owner.
//   - identity — the EGRESS identity this row speaks for. A unit whose netdev is
//     its base's netdev speaks for the base; one on its own netdev speaks for
//     itself. This is taken from the aliasing the builder just performed
//     (`linuxUnit == parentLinux`), never re-derived from names.
//   - isUnit   — whether the row is a logical unit row.
type egressRowIdentity struct {
	owner    string
	identity string
	isUnit   bool
}

// stampEgressZones decides the EGRESS security zone of every ifindex in the
// snapshot and writes it onto each row's EgressZone (#6722).
//
// WHY THIS IS DECIDED HERE. `ForwardingState::egress_zone_id`
// (userspace-dp/src/afxdp/types/forwarding.rs) must answer "which single zone
// does this ifindex identify" — a nonzero to-zone is what makes an operator
// `permit` match, so guessing one adjudicates transit under a policy that was
// never written for that device. Answering it from the snapshot ROWS is not
// possible, because a row's Zone is the OUTCOME of two derivations whose inputs
// the rows no longer carry:
//
//   - buildInterfaceZoneMap (zones.go) fans one authored reference UP to a base
//     as well as down onto units, so a row's Zone may be a restatement of a
//     sentence the operator wrote about a DIFFERENT identity. Measured: for
//     `ge-0/0/1` with unit 0 in `lan` and unit 1 in `dmz`, the BASE row carries
//     "dmz" — a zone nothing on that netdev was ever put in, chosen because
//     "dmz" sorts before "lan". (The fan-DOWN is not such a restatement, and
//     authoredZoneRefs keeps it: a bare interface reference is a sentence about
//     every unit of that interface.)
//   - snapshotLinuxName collapses several configured identities onto one netdev
//     (a non-VLAN unit 0 onto its base; a RETH and its member, via ResolveReth;
//     every unit of an interface-level tunnel onto the tunnel device).
//
// #6722 tried FOUR times to reconstruct that provenance downstream by
// classifying rows — from the raw `redundant-parent` string, from co-resident
// row names, from the set of netdevs a parent's rows occupy, and finally by
// asking snapshotLinuxName about the parent's BASE row. Each spelling was holed
// by a config shape it had not enumerated, because provenance is not recoverable
// from the outcome: by the time a row exists, "the operator zoned this device"
// and "something else was zoned and this row inherited the words" look identical.
// The enumeration was the defect, not any particular missing case. So the answer
// is computed once, here, where both inputs are in hand, and shipped.
//
// THE RULES, in order. For each ifindex > 0:
//
//  1. CONTESTED OWNERSHIP → no zone. An ifindex carrying two or more distinct
//     egress identities describes one kernel device that the config claims
//     twice. That is legitimate for exactly one relation — a redundant-ethernet
//     interface and the member port it resolves onto — and a fiction otherwise.
//     See egressIdentitiesCohere.
//  2. AUTHORED → that zone. Every `security-zone <z> interfaces <ref>` the
//     operator literally wrote, resolved to an ifindex by the row that ref
//     names. Exactly one distinct zone on the ifindex wins; two or more is a
//     real conflict about a real device and resolves to no zone.
//  3. TRUNK CARRIER → the units' unanimous zone. An ifindex with no authored
//     reference and NO logical unit row on it is a bare tagged-parent netdev:
//     its children all live on `<dev>.<vlan>` devices of their own. Attributing
//     the zone its units unanimously carry matches both origin/master and the
//     #921/#3618 ingress rule, and it is what keeps a `vlan-tagging` RETH's base
//     ifindex zoned (the reference cluster's `reth0`/ifindex 25). If ANY unit
//     row is on the ifindex, this rule does not fire: that unit is an identity
//     on the device in its own right and rule 2 already had its say.
//  4. Otherwise no zone. Rendered as "" and read by the helper as the 0
//     sentinel, against which evaluate_policy_result_l3_aware matches no rule
//     and the default policy decides.
//
// WHAT THIS MAKES UNREPRESENTABLE. There is no longer any per-row
// classification predicate on the dataplane side — no "is this row a
// projection", no exemption list, nothing for a new config shape to disagree
// with. A row's Zone is never consulted to adjudicate; it is used only as
// corroboration at the helper boundary (see populate_interfaces).
//
// WHAT IT DOES NOT. "A reth member is a bare L2 port" (egressMemberIsBarePort)
// is a MODEL rule imported from Junos, not something derivable from the config,
// and it stays a definition. It is now stated positively in one place and read
// by both the commit gate (validateRethMemberStrict) and this builder, rather
// than existing as a growing list of rejected shapes.
func stampEgressZones(cfg *config.Config, out []InterfaceSnapshot, idents []egressRowIdentity, authored map[string]string) {
	if cfg == nil || len(out) == 0 || len(out) != len(idents) {
		return
	}
	type ifxState struct {
		identities  map[string]string // identity -> owner
		authored    map[string]bool
		unitRefs    map[string]bool // authored zone of each UNIT row ("" = none)
		hasUnitRow  bool
		rowsByIndex []int
	}
	states := make(map[int]*ifxState)
	order := make([]int, 0, len(out))
	for i := range out {
		ifx := out[i].Ifindex
		if ifx <= 0 {
			continue
		}
		st := states[ifx]
		if st == nil {
			st = &ifxState{
				identities: map[string]string{},
				authored:   map[string]bool{},
				unitRefs:   map[string]bool{},
			}
			states[ifx] = st
			order = append(order, ifx)
		}
		st.identities[idents[i].identity] = idents[i].owner
		if idents[i].isUnit {
			st.hasUnitRow = true
			// Rule 1's escape hatch (see egressOneOwnerUnitsAgree): the
			// authored zone of THIS unit row, "" when the operator authored
			// none. "" is recorded on purpose — a unit left out of every zone
			// is a statement, and it must break unanimity.
			st.unitRefs[authored[out[i].Name]] = true
		}
		st.rowsByIndex = append(st.rowsByIndex, i)
		// Rule 2's input: an authored reference NAMING THIS ROW. Keyed by the
		// row's own name, so the ref lands on whatever ifindex the builder
		// resolved that name to — the same aliasing, not a second opinion.
		if z := authored[out[i].Name]; z != "" {
			st.authored[z] = true
		}
	}
	sort.Ints(order)
	for _, ifx := range order {
		st := states[ifx]
		zone := ""
		switch {
		case !egressIdentitiesCohere(cfg, st.identities) &&
			!egressOneOwnerUnitsAgree(st.identities, st.unitRefs):
			zone = ""
		case len(st.authored) == 1:
			for z := range st.authored {
				zone = z
			}
		case len(st.authored) > 1:
			zone = ""
		case !st.hasUnitRow:
			zone = unanimousUnitZone(cfg, st.identities, authored)
		}
		for _, i := range st.rowsByIndex {
			out[i].EgressZone = zone
		}
	}
}

// egressOneOwnerUnitsAgree is the one narrow case in which several egress
// identities on ONE ifindex still identify a single zone (#6722).
//
// egressIdentitiesCohere refuses every multi-identity ifindex whose identities
// belong to a single configured interface, on the ground that the operator
// described two logical interfaces and the kernel gave them one device. That is
// the right answer when the two disagree — a MEASURED fail-open otherwise, see
// TestContestedNetdevOwnershipFailsClosed_6722/two-tunnel-units-on-one-device,
// where `wg0.1` is zoned and `wg0.0` deliberately is not. It is the WRONG answer
// when they agree: an interface-level tunnel maps EVERY unit onto the tunnel
// netdev (`TunnelNameMap`), so `gr-0/0/0.0` and `gr-0/0/0.1` both in `sfmix` is
// one device on which every claimant names the same zone. origin/master
// resolved `sfmix` there; refusing it drops every transit flow out of the tunnel
// to the default policy for no safety gained.
//
// So the refusal is narrowed to what it is actually about — DISAGREEMENT — and
// only for a device no foreign interface claims:
//
//   - every identity on the ifindex must belong to the SAME configured
//     interface. One owner means there is no independent claimant to defer to
//     or to be misattributed; the reth/member relation and every cross-interface
//     collision keep going through egressIdentitiesCohere unchanged.
//   - every LOGICAL UNIT row on the ifindex must carry the SAME authored zone.
//     An unauthored unit contributes "" and breaks unanimity, which is what
//     preserves the fail-closed above.
//
// Base rows are not required to be authored: a bare `security-zone <z>
// interfaces <ifc>` reference does author them (authoredZoneRefs fans it down),
// but a per-unit reference legitimately leaves the base row unauthored, and rule
// 2 then reads the units' agreed zone off their own rows.
//
// MEASURED SURVIVOR: the `z != ""` test on the single agreed value. Removing it
// leaves the whole Go suite green, and the reason is structural rather than a
// missing fixture. It fires only when EVERY unit row on the ifindex is
// unauthored, i.e. `unitRefs == {""}`; the caller then reaches rule 2 with an
// `authored` set that can only have been filled by a BASE row, and a bare
// reference — the only spelling that authors a base row — is fanned down onto
// every configured unit, so it would have authored those unit rows too. The set
// is therefore empty, rule 2 does not fire, rule 3 is skipped because a unit row
// IS on the ifindex, and the answer is "" either way. It is kept because it
// states the rule the function is about ("the units agree on a ZONE", not "the
// units agree"), and because the fan-down is what makes it unreachable — a
// future change that narrows the fan-down would make this the difference between
// honouring a base-only zone on units the operator declined to zone and refusing
// it.
func egressOneOwnerUnitsAgree(identities map[string]string, unitRefs map[string]bool) bool {
	if len(identities) < 2 || len(unitRefs) != 1 {
		return false
	}
	owner := ""
	for _, o := range identities {
		if owner == "" {
			owner = o
			continue
		}
		if o != owner {
			return false
		}
	}
	for z := range unitRefs {
		return z != ""
	}
	return false
}

// egressIdentitiesCohere reports whether the egress identities sharing one
// ifindex describe a device the config claims coherently (#6722).
//
// One identity always coheres. Exactly two cohere only when one is a
// redundant-ethernet interface and the other is a bare member port that names it
// — the single relation under which two configured identities are DESIGNED to be
// one netdev (`ResolveReth`, pkg/config/types.go). Three or more never cohere:
// a reth resolves onto exactly one member, so a third claimant is always a
// second, unrelated claim on the same device.
//
// Everything the ledger used to enumerate falls out of this:
//
//   - The reference bondless cluster — `{ge-0/0/1, reth1}` on ifindex 24 —
//     coheres, which is the whole point of #6722: the member's rows must not
//     make the RETH's own zone ambiguous.
//   - An `interfaces ge-0-0-1` / `interfaces ge-0/0/1` canonicalization
//     collision (#5832) does NOT cohere — neither side is a reth, so the
//     deference premise ("the member is a port, the reth owns the L3") is
//     absent. It fails closed, retiring the fail-OPEN delta the previous
//     spelling admitted for that shape on the tolerant path.
//   - A reth that names a redundant parent of its own does NOT cohere: a reth is
//     never a member port. validateRethMemberStrict rejects it at commit; on the
//     tolerant load / peer-sync path, where that gate is a warning (#1960
//     no-brick), this is what holds the line.
//   - A WireGuard or other tunnel interface named as a member does NOT cohere.
//     A tunnel is an independently routed L3 endpoint, not a port, and the one
//     that reaches the builder anyway carries its own routes onto the shared
//     ifindex.
//   - A member carrying its OWN logical units does NOT cohere. Its units are
//     independently addressed L3 interfaces on the shared device, and their lack
//     of a zone is a real operator statement.
func egressIdentitiesCohere(cfg *config.Config, identities map[string]string) bool {
	if len(identities) <= 1 {
		return true
	}
	if len(identities) > 2 {
		return false
	}
	owners := make([]string, 0, 2)
	for _, owner := range identities {
		owners = append(owners, owner)
	}
	if owners[0] == owners[1] {
		// Two identities of ONE interface on one netdev — two units of an
		// interface-level tunnel, say. The operator described two logical
		// interfaces; the kernel gives them one device. Nothing designates
		// either as the other's port, so the device identifies no single zone.
		//
		// MEASURED SURVIVOR (#6722 round 11), and dead for a stronger reason
		// than that round recorded. A same-owner pair puts the SAME name in both
		// argument positions, and `egressRethMemberOf(X, X)` is a contradiction
		// on the name alone: the `reth` position demands
		// `strings.HasPrefix(X, "reth")` and the `member` position is handed to
		// `egressMemberIsBarePort`, which refuses exactly that prefix. No config
		// satisfies both, so the fall-through cannot admit a same-owner pair
		// whatever the `redundant-parent` says — the round-11 note read the
		// refusal as contingent on the parent match, and it is not.
		//
		// Kept because it states the rule at the level the rule is about
		// (identity vs. interface) rather than as a name-shape accident, and
		// because that accident is exactly the kind of thing a later change
		// unpicks: relaxing either prefix test would silently re-admit this
		// shape through a branch nobody was watching. Recorded as a survivor
		// rather than deleted or claimed to be load-bearing.
		return false
	}
	return egressRethMemberOf(cfg, owners[0], owners[1]) ||
		egressRethMemberOf(cfg, owners[1], owners[0])
}

// egressRethMemberOf reports whether `member` is a valid redundant-ethernet
// member port of `reth` (#6722): `reth` is a reth interface, `member` names it
// as its `gigether-options redundant-parent`, and `member` is a bare L2 port.
func egressRethMemberOf(cfg *config.Config, member, reth string) bool {
	if !strings.HasPrefix(reth, "reth") {
		return false
	}
	if cfg.Interfaces.Interfaces[reth] == nil {
		return false
	}
	ifc := cfg.Interfaces.Interfaces[member]
	if ifc == nil || ifc.RedundantParent != reth {
		return false
	}
	return egressMemberIsBarePort(member, ifc)
}

// egressMemberIsBarePort states POSITIVELY what a redundant-ethernet member is
// allowed to be: a port that contributes a netdev and nothing else (#6722).
//
// Junos models a reth as ONE interface described by several nodes — the `rethN`
// node owns the logical units, addresses, security zone and CoS, and each member
// node contributes only a physical port. That model is why a member's row may
// share the reth's ifindex without making it ambiguous, so the model's
// conditions are exactly the conditions of the deference. An interface that
// carries its own logical units, its own tunnel, or that is itself a reth has an
// L3 identity of its own and is not a port.
//
// validateRethMemberStrict (pkg/config/compiler_validate_strict_reth_member.go)
// rejects each of these at commit and quotes this rule; this is the runtime half
// that must hold on the tolerant load / peer-sync path, where those rejections
// are downgraded to warnings (#1960 no-brick).
func egressMemberIsBarePort(name string, ifc *config.InterfaceConfig) bool {
	if ifc == nil || strings.HasPrefix(name, "reth") {
		return false
	}
	if ifc.Tunnel != nil {
		return false
	}
	_, hasUnit := firstConfiguredUnit(ifc)
	return !hasUnit
}

// firstConfiguredUnit reports the lowest configured (non-nil) logical unit of
// ifc. A present-but-nil unit slot (tolerant load / HA config-sync, #3494/#5068)
// is not a configured unit.
func firstConfiguredUnit(ifc *config.InterfaceConfig) (int, bool) {
	lowest, found := 0, false
	for num, unit := range ifc.Units {
		if unit == nil {
			continue
		}
		if !found || num < lowest {
			lowest, found = num, true
		}
	}
	return lowest, found
}

// unanimousUnitZone implements rule 3 of stampEgressZones: the zone that every
// AUTHORED unit reference of the interfaces claiming this ifindex agrees on, or
// "" if they disagree or none exists (#6722).
//
// Only reached for an ifindex with no authored reference of its own AND no unit
// row on it — a bare tagged-parent netdev whose children all live on their own
// `<dev>.<vlan>` devices. Unzoned units are skipped rather than counted as
// dissent: they are not on this netdev and say nothing about it.
func unanimousUnitZone(cfg *config.Config, identities map[string]string, authored map[string]string) string {
	seen := ""
	for _, owner := range identities {
		ifc := cfg.Interfaces.Interfaces[owner]
		if ifc == nil {
			continue
		}
		for num, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			z := authored[fmt.Sprintf("%s.%d", owner, num)]
			if z == "" {
				continue
			}
			if seen != "" && seen != z {
				return ""
			}
			seen = z
		}
	}
	return seen
}

// buildLinkSnapshot resolves a kernel interface's live ifindex/MTU/MAC/addresses.
// It is a package var so the host-inbound view builder (which resolves the base
// netdev's LIVE addresses through it) is unit-testable without a real kernel
// interface — the #5699 base-vs-unit-0 double-emission only manifests when the
// base netdev actually carries the (unit-0-collapsed) live address.
var buildLinkSnapshot = func(linuxName string) (ifindex int, mtu int, hardwareAddr string, addresses []InterfaceAddressSnapshot) {
	if linuxName == "" {
		return 0, 0, "", nil
	}
	if link, err := net.InterfaceByName(linuxName); err == nil {
		ifindex = link.Index
	}
	if link, err := netlink.LinkByName(linuxName); err == nil && link != nil {
		mtu = link.Attrs().MTU
		if hw := link.Attrs().HardwareAddr; len(hw) > 0 {
			hardwareAddr = hw.String()
		}
		addresses = buildInterfaceAddressSnapshots(link)
	}
	return ifindex, mtu, hardwareAddr, addresses
}

func buildConfiguredAddressSnapshots(addrs []string) []InterfaceAddressSnapshot {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]InterfaceAddressSnapshot, 0, len(addrs))
	for _, cidr := range addrs {
		ip, netw, err := net.ParseCIDR(cidr)
		if err != nil || netw == nil {
			continue
		}
		netw.IP = ip
		family := "inet"
		if ip.To4() == nil {
			family = "inet6"
		}
		out = append(out, InterfaceAddressSnapshot{
			Family:  family,
			Address: netw.String(),
			Scope:   int(netlink.SCOPE_UNIVERSE),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func mergeInterfaceAddressSnapshots(live []InterfaceAddressSnapshot, configured []InterfaceAddressSnapshot) []InterfaceAddressSnapshot {
	if len(live) == 0 {
		return configured
	}
	if len(configured) == 0 {
		return live
	}
	seen := make(map[string]bool, len(live)+len(configured))
	out := make([]InterfaceAddressSnapshot, 0, len(live)+len(configured))
	for _, addr := range live {
		key := addr.Family + "/" + addr.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	for _, addr := range configured {
		key := addr.Family + "/" + addr.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func buildInterfaceAddressSnapshots(link netlink.Link) []InterfaceAddressSnapshot {
	if link == nil {
		return nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	out := make([]InterfaceAddressSnapshot, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		family := "inet"
		if addr.IPNet.IP.To4() == nil {
			family = "inet6"
		}
		out = append(out, InterfaceAddressSnapshot{
			Family:  family,
			Address: addr.IPNet.String(),
			Scope:   addr.Scope,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func userspaceRXQueueCount(linuxName string) int {
	if linuxName == "" {
		return 0
	}
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", linuxName, "queues"))
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if name := entry.Name(); len(name) > 3 && name[:3] == "rx-" {
			count++
		}
	}
	return count
}
