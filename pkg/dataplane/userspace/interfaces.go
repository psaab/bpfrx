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
	// #6722: which interfaces are a PROJECTION of the RETH they belong to —
	// the ones a RETH's own rows were resolved onto, so member and RETH
	// describe one netdev rather than two independent observers of it.
	rethProjection := rethProjectionMembers(cfg)
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
			RethProjection:  rethProjection[name],
			UnitCount:       len(iface.Units),
			Tunnel:          iface.Tunnel != nil,
			MTU:             mtu,
			HardwareAddr:    hardwareAddr,
			Addresses:       addresses,
		})
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
				RedundancyGroup:           rg,    // inherit resolved RG (RETH parent or own)
				RethProjection:            false, // #6722: never on a unit row — see rethProjectionMembers
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
		}
	}
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

// rethProjectionMembers reports which interfaces are a PROJECTION of the
// redundant-ethernet interface they name as their `gigether-options
// redundant-parent` — that is, which ones the RETH's own rows have been
// resolved ONTO, so that the member's row and the RETH's row describe one
// kernel netdev rather than two independent observers of it.
//
// #6722. `snapshotLinuxName` resolves a RETH through `ResolveReth`
// (pkg/config/types.go) onto its LOCAL member's netdev, so on a bondless
// cluster `reth1`, `reth1.0` and `ge-0/0/1` are three rows on ONE device.
// Junos zones the RETH rather than the member, so the member's row arrives
// unzoned. Counting that "no zone" as a dissenting vote in the Rust agreement
// ledger (userspace-dp/src/afxdp/forwarding_build/interfaces.rs) holds the
// ifindex ambiguous, collapses the egress zone to the 0 sentinel, and
// blackholes every WAN->LAN transit flow on a bondless-RETH cluster.
//
// The predicate is the ALIAS ITSELF, asked of the function that creates it:
// does the parent's base row resolve to the same netdev as this interface's?
// Four earlier spellings re-derived that answer downstream — from the shape of
// the `redundant-parent` string, then from co-resident row names, then from the
// set of netdevs the parent's rows occupy — and each re-derivation was holed by
// a config that made it disagree with `ResolveReth`. There is no second opinion
// to disagree now: `snapshotLinuxName` is the aliasing, and the only question
// left is which of a RETH's declared members it picked (`RethToPhysical`'s
// node-affinity scoring), which is exactly what this comparison asks.
//
// THE CASE SPLIT IS FOUR-WAY, not two. `snapshotLinuxName` is
// `LinuxIfName(ResolveReth(x))` for a `reth*`-prefixed name and
// `LinuxIfName(x)` otherwise, and it is applied to BOTH sides of the
// comparison, so `parent` and `name` each take either arm independently:
//
//	| parent   | name     | equality actually tested |
//	|----------|----------|--------------------------|
//	| reth     | non-reth | L(R(parent)) = L(name)   |
//	| non-reth | non-reth | L(parent)    = L(name)   |
//	| reth     | reth     | L(R(parent)) = L(R(name))|
//	| non-reth | reth     | L(parent)    = L(R(name))|
//
// Rounds 4-6 of #6722 argued only the first two and called them exhaustive.
// They are not, and rows 3 and 4 were both measured REACHABLE under strict
// `CompileConfig` before round 7 — each one marking a `reth*` interface, the
// L3 owner, as a projection. What empties them is a property of
// `validateRethMemberStrict`, not a failed search: its reth clause rejects any
// `reth*` name that declares a `redundant-parent`, and this loop only ever
// considers a `name` that declares one, so `name` is never a `reth*` name and
// `snapshotLinuxName(name)` is unconditionally `LinuxIfName(name)`. Rows 3 and
// 4 are then structurally unreachable rather than merely unwitnessed.
//
// DEPENDENCY, stated because it is not local to this file. Row 2 — no RETH
// involved at all, the two names merely CANONICALIZING together, e.g.
// `redundant-parent ge-0-0-1` on `ge-0/0/1` where `/`->`-` makes both
// `ge-0-0-1` — is closed by `validateInterfaceNameCollisionStrict` (#5832), a
// DIFFERENT gate from `validateRethMemberStrict`, rejecting two distinct names
// that canonicalize to one device. The deference premise ("a member is an L2
// port, the reth owns the L3") does not hold there, because neither side is a
// reth. This predicate's soundness rests on #5832, so relaxing it reopens row
// 2. #5832 is likewise a warning on the tolerant load / peer-sync path, where
// the shape is therefore admissible: measured, the marked row's empty vote is
// withheld and the ledger resolves the zone the operator wrote on the OTHER
// name for that same device — a fail-OPEN delta against master, bounded to a
// zone the operator did write on that device, on a config that has already
// emitted the #5832 hijack warning. Pinned by
// TestCanonicalNameCollisionMarksWithoutAReth_6722.
//
// Rows 3 and 4 have the same tolerant-path status as row 2: the reth clause is
// a warning there too, so a grandfathered config can still present a `reth*`
// candidate and the mark still lands. What bounds it is NOT any property of
// what the marked interface carries — measured, a marked reth on the tolerant
// path can carry BOTH its own logical units and its own zone, because the
// gate's unit clause is downgraded on that path exactly like the reth clause.
// Two structural facts bound it instead, and both are bound by tests:
//
//  1. A marked row's vote is only ever WITHHELD when it is EMPTY. The Rust gate
//     is `reth_projection && zone.is_empty()`, so a marked row that names a
//     zone still votes. Withholding therefore cannot discard a zone the
//     operator wrote; it can only let the ifindex resolve a zone another row on
//     it named, or leave it with no contributing row and answer the 0 sentinel.
//  2. UNIT rows are never marked — `buildInterfaceSnapshots` stamps
//     `RethProjection: false` on every unit row unconditionally, so the mark can
//     never silence an independently addressed L3 interface.
//
// It does NOT follow that a marked base row's units hold its ifindex ambiguous.
// An earlier version of this comment said so; that is true only for a non-VLAN
// unit 0, which collapses onto the base netdev. `snapshotLinuxName` sends a VLAN
// unit to `L(R(name)).<vlan>` — a DIFFERENT netdev — so it votes on its own
// ifindex and says nothing about the base's. Measured on `reth1 unit 100 vlan-id
// 100` beside a zoned `reth0`: ifindex 31 carries only the zoned reth0 rows and
// the unzoned MARKED reth1 row, so it resolves `lan` — where the same config
// with `unit 0` puts `reth1.0` on ifindex 31 as well and resolves the 0
// sentinel.
//
// A STRONGER bound holds for row 3 specifically: the mark is RUNTIME-INERT.
// A row-3 mark requires `S(parent) == S(name)` with both `reth*`. `S(name)` is
// `L(R(name))`, which is the marked reth's OWN name unless some interface
// declares it as a redundant parent; if one does, `R(parent)` is a member of
// `parent` and `R(name)` a member of `name`, two different interfaces, so the
// equality needs a canonicalization collision — which is #5832's shape, not this
// one. So absent a #5832 collision a row-3 mark always lands on the netdev name
// `rethN`, and on the bondless-RETH model this whole mechanism exists for, a
// reth is not a kernel device: `buildLinkSnapshot` resolves by name and answers
// ifindex 0, and both `populate_interfaces` and `populate_egress` skip
// `ifindex <= 0`. The row never reaches the ledger. Row 4 is NOT inert — its
// netdev is a real physical member's — and is bounded by (1) instead.
//
// Pinned by TestRethNamingARedundantParentMarksTheRethOnTheLenientPath_6722.
//
// The remaining `parent != name` test is the definition of a parent relation,
// not a clause excluding a case: nothing is its own redundant parent, and a
// self-reference makes `ResolveReth` a no-op so the comparison would otherwise
// be trivially true and report an interface as a projection of ITSELF.
// `validateRethMemberStrict` (pkg/config/compiler_validate_strict_reth_member.go)
// rejects that config at commit; on the tolerant load / peer-sync path, where
// that gate is downgraded to a warning (#1960 no-brick), this test is what keeps
// that false fact off the wire. It is NOT what holds the zone line there:
// measured on the self-parent shape (`st0` self-parenting, zone on `st0.1`),
// dropping the test marks `st0`, but `buildInterfaceZoneMap`'s `out[base]` write
// has already stamped the base row `vpnb`, so the Rust gate
// `reth_projection && zone.is_empty()` is false and the row still votes. The
// zone line is held by that base-row-only stamp plus the `out[base]` write —
// see cell J in reth_member_projection_6722_test.go.
//
// Keyed by interface name because after `validateRethMemberStrict` a member has
// exactly ONE row: the gate rejects a member carrying its own logical units, so
// there are no member unit rows to classify. `buildInterfaceSnapshots` stamps
// this on the BASE row only — a member unit that reaches the builder anyway,
// through the lenient path, is an independently addressed L3 interface and must
// keep voting, which leaves its ifindex ambiguous and fail-CLOSED.
func rethProjectionMembers(cfg *config.Config) map[string]bool {
	out := make(map[string]bool)
	for name, iface := range cfg.Interfaces.Interfaces {
		if iface == nil || iface.RedundantParent == "" || iface.RedundantParent == name {
			continue
		}
		parent := cfg.Interfaces.Interfaces[iface.RedundantParent]
		if parent == nil {
			continue
		}
		parentNetdev := snapshotLinuxName(cfg, iface.RedundantParent, parent, nil)
		if parentNetdev != "" && parentNetdev == snapshotLinuxName(cfg, name, iface, nil) {
			out[name] = true
		}
	}
	return out
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
