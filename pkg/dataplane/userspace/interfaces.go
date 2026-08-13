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
	// #6722: every row of a RETH physical member is stamped with its
	// RedundantParent below (base row AND unit rows) so the Rust agreement
	// ledger can tell a PROJECTION of another row's netdev from an independent
	// observer of it. ResolveReth collapses reth1/reth1.0 onto the member's
	// netdev, and a member's own units alias the matching reth unit the same
	// way — a VLAN unit resolves to LinuxIfName(ResolveReth(base)).<vlan>, so
	// `ge-0/0/1.100` lands on `reth1.100`'s netdev. Measured: a member carrying
	// `unit 0` + `unit 100 vlan-id 100` puts {ge-0/0/1, ge-0/0/1.0, reth1} on
	// one ifindex and {ge-0/0/1.100, reth1.100} on another, so stamping only
	// the base row would leave the second pair ambiguous. Junos zones the RETH
	// and never the member, so those rows arrive unzoned; counting that "no
	// zone" as a dissenting vote holds the ifindex ambiguous, collapses the
	// egress zone to the 0 sentinel, and blackholes every WAN->LAN transit flow
	// on a bondless-RETH cluster. See InterfaceSnapshot.RedundantParent.
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
			RedundantParent: iface.RedundantParent,
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
				RedundancyGroup:           rg, // inherit resolved RG (RETH parent or own)
				RedundantParent:           iface.RedundantParent,
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
