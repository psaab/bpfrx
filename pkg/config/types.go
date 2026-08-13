package config

import (
	"fmt"
	"strconv"
	"strings"
)

// LinuxIfName translates a Junos-style interface name (e.g. "ge-0/0/0")
// to a valid Linux interface name (e.g. "ge-0-0-0"). Linux IFNAMSIZ
// forbids "/" so we replace with "-".
func LinuxIfName(name string) string {
	return strings.ReplaceAll(name, "/", "-")
}

// DHCPLeaseIfName returns the Linux interface name under which the
// DHCP manager keys the lease for the given configured interface unit:
// LinuxIfName(ifName), plus a ".<vlan-id>" suffix when the unit is
// 802.1Q tagged. Note the suffix is the unit's VLAN ID, NOT its unit
// number — the two coincide by convention but are distinct concepts,
// bridged only here. Shared by the daemon's buildDHCPClientSpecs and
// the ip-monitoring interface-typed next-hop compiler (#1844) so the
// two derivations can never drift.
func DHCPLeaseIfName(ifName string, unit *InterfaceUnit) string {
	base := LinuxIfName(ifName)
	if unit != nil && unit.VlanID > 0 {
		return fmt.Sprintf("%s.%d", base, unit.VlanID)
	}
	return base
}

// InterfaceSlot extracts the FPC slot number from a Junos interface name.
// "ge-0/0/7" → 0, "ge-7/0/7" → 7, "xe-3/1/2" → 3.
// Returns -1 if the name doesn't match the <type>-N/N/N pattern.
func InterfaceSlot(name string) int {
	// Find the first "-" separator, then parse the FPC number before the first "/".
	dashIdx := strings.Index(name, "-")
	if dashIdx < 0 || dashIdx+1 >= len(name) {
		return -1
	}
	rest := name[dashIdx+1:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return -1
	}
	slot, err := strconv.Atoi(rest[:slashIdx])
	if err != nil {
		return -1
	}
	return slot
}

// SlotToNodeID maps a vSRX FPC slot to a cluster node-id.
// Convention: slot 0 → node0, slot 7 → node1.
func SlotToNodeID(slot int) int {
	if slot == 7 {
		return 1
	}
	return 0
}

// RethToPhysical returns a map of reth name → local physical member name.
// Built from interfaces that have RedundantParent set.
func (c *Config) RethToPhysical() map[string]string {
	m := make(map[string]string)
	bestScore := make(map[string]int)
	localNodeID := -1
	if c.Chassis.Cluster != nil {
		localNodeID = c.Chassis.Cluster.NodeID
	}
	for _, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.RedundantParent != "" {
			score := 1
			if localNodeID >= 0 {
				slot := InterfaceSlot(ifc.Name)
				if slot >= 0 {
					if SlotToNodeID(slot) == localNodeID {
						score = 2
					} else {
						score = 0
					}
				}
			}
			prev, ok := m[ifc.RedundantParent]
			if !ok || score > bestScore[ifc.RedundantParent] ||
				(score == bestScore[ifc.RedundantParent] && ifc.Name < prev) {
				m[ifc.RedundantParent] = ifc.Name
				bestScore[ifc.RedundantParent] = score
			}
		}
	}
	return m
}

// ResolveReth resolves "reth0" or "reth0.50" to the physical member equivalent.
// Returns input unchanged if not a RETH name.
func (c *Config) ResolveReth(ref string) string {
	rethMap := c.RethToPhysical()
	parts := strings.SplitN(ref, ".", 2)
	if phys, ok := rethMap[parts[0]]; ok {
		if len(parts) == 2 {
			return phys + "." + parts[1]
		}
		return phys
	}
	return ref
}

// ResolveFab resolves "fab0" or "fab0.0" to the backing physical member
// interface using LocalFabricMember. Returns input unchanged if not a fab name
// or the interface has no LocalFabricMember set.
func (c *Config) ResolveFab(ref string) string {
	parts := strings.SplitN(ref, ".", 2)
	base := parts[0]
	if c.Interfaces.Interfaces == nil {
		return ref
	}
	ifc, ok := c.Interfaces.Interfaces[base]
	if !ok || ifc == nil || ifc.LocalFabricMember == "" {
		return ref
	}
	resolved := ifc.LocalFabricMember
	if len(parts) == 2 {
		return resolved + "." + parts[1]
	}
	return resolved
}

// ResolveKernelIfName converts a Junos-style interface reference
// (as found in zone declarations and the keys of
// cfg.Interfaces.Interfaces) to the Linux kernel ifname it should
// resolve to on the LOCAL node.
//
// This is a DISPLAY-name resolver for API readers — it is NOT the
// same as ResolveFab (which returns the fabric overlay's parent
// physical member for BPF attachment). fab0 itself is a real kernel
// IPVLAN device, so API queries on fab0 must look up "fab0", not
// its parent. st0.x resolves to the xfrmi device derived from the
// AUTHORED bind-interface, which is not always the ref itself.
//
// Resolution semantics, in order:
//  1. Bare refs (no "." suffix):
//     - reth* → ResolveReth → physical member, LinuxIfName.
//     - all others (fxp0, em0, fab0, lo, ge-0/0/0, gr-0/0/0, st0):
//     LinuxIfName(ref). Matches snapshotLinuxName for the no-unit
//     case.
//  2. Dotted refs (e.g. "ge-0/0/0.80", "reth0.50", "gr-0/0/0.0",
//     "irb.0", "st0.0"):
//     a. st<N>.<M>: resolve the xfrmi device from the AUTHORED
//     bind-interface via SecureTunnelUnitNetdev (#5619). A bare
//     `bind-interface st0` and an explicit `bind-interface st0.0`
//     derive the same if_id under DIFFERENT device names, while
//     the unit ref is `st0.0` either way — so it is read from the
//     config, NOT reconstructed from the ref. Falls back to the
//     verbatim ref only when no VPN binds the unit, since no xfrmi
//     device exists for it then. That whole rule lives in
//     SecureTunnelUnitNetdev, which snapshotLinuxName and
//     junosHostLinuxName also call — one resolver, not three
//     copies asserted to agree (#6691).
//     b. IRB: look up via IRBToBridge(cfg.BridgeDomains) and return
//     the bridge device name (no suffix).
//     c. Tunnel: if TunnelNameMap[ref] is set, return that name
//     verbatim (covers gr-0/0/0.0 → gr-0-0-0 and
//     gr-0/0/0.1 → gr-0-0-0u1).
//     d. Otherwise look up cfg.Interfaces.Interfaces[base].Units[unit]:
//     - If unit has tunnel.Name set, return that.
//     - If unit.VlanID > 0, return
//     LinuxIfName(ResolveReth(base)) + "." + VlanID.
//     - If unit.Number == 0, return
//     LinuxIfName(ResolveReth(base)) (unit-0 collapse).
//     - Else return LinuxIfName(ResolveReth(base)) + "." + unit.Number.
//     e. Fallback: LinuxIfName(ResolveReth(ref)) — preserves suffix.
//
// NOTE: Keep in sync with snapshotLinuxName in
// pkg/dataplane/userspace/interfaces.go and resolveJunosIfName in
// pkg/daemon/daemon_dhcp.go. Migration to centralize all callers is
// tracked as a follow-up to #1565.
// resolveBareKernelIfName is the BARE-ref arm of ResolveKernelIfName, split out
// so callers that already know structurally that they hold an interface name —
// not a unit ref — can reach it without round-tripping through the dotted
// parse (#6861 F1/F3).
//
// The distinction is load-bearing, not cosmetic. ResolveKernelIfName decides
// which arm to take by splitting the string on ".", so an interface whose
// AUTHORED name contains a dot (`ip-0/0/0.0` is a legal interface name in the
// config tree even though Junos would read it as a unit ref) takes the dotted
// arm and can consume an unrelated unit's TunnelNameMap entry. The dataplane's
// snapshotLinuxName has no such ambiguity because it branches on `unit != nil`
// — a structural fact. A caller holding the structure must be able to say so.
func (c *Config) resolveBareKernelIfName(name string) string {
	if strings.HasPrefix(name, "reth") {
		return LinuxIfName(c.ResolveReth(name))
	}
	return LinuxIfName(name)
}

func (c *Config) ResolveKernelIfName(ref string) string {
	parts := strings.SplitN(ref, ".", 2)
	base := parts[0]

	// Bare refs.
	if len(parts) == 1 {
		return c.resolveBareKernelIfName(base)
	}

	// XFRM (st<N>): the kernel device is the AUTHORED bind-interface, which
	// is not always the ref. A bare `bind-interface st0` and an explicit
	// `bind-interface st0.0` derive the same if_id under DIFFERENT device
	// names ("st0" vs "st0.0", pkg/routing/xfrm.go), and the unit ref is
	// `st0.0` either way — so resolve it from the config rather than
	// reconstructing it from the ref (#5619). Falls back to the verbatim ref
	// when no VPN binds this unit: no xfrmi device exists for it then, and
	// the verbatim ref is what this returned before.
	//
	// The whole rule lives in SecureTunnelUnitNetdev (xfrmi.go) so
	// snapshotLinuxName and junosHostLinuxName apply the IDENTICAL one
	// instead of hand-copied instances of it (#6691).
	if dev, ok := c.SecureTunnelUnitNetdev(ref); ok {
		return dev
	}

	// IRB.
	if base == "irb" {
		if bridges := IRBToBridge(c.BridgeDomains); bridges != nil {
			if bridge, ok := bridges[ref]; ok && bridge != "" {
				return bridge
			}
		}
		// Fall through if no bridge mapping; fallback handles it.
	}

	// Per-unit tunnel by ref.
	if tunMap := c.TunnelNameMap(); tunMap != nil {
		if linuxName, ok := tunMap[ref]; ok && linuxName != "" {
			return linuxName
		}
	}

	// Bail to fallback if the suffix isn't numeric (malformed ref
	// like "ge-0/0/0.foo" must not silently map to unit 0).
	unitNum, err := strconv.Atoi(parts[1])
	if err != nil {
		return LinuxIfName(c.ResolveReth(ref))
	}
	if c.Interfaces.Interfaces == nil {
		return LinuxIfName(c.ResolveReth(ref))
	}
	if ifc, ok := c.Interfaces.Interfaces[base]; ok && ifc != nil {
		if unit, ok := ifc.Units[unitNum]; ok && unit != nil {
			if unit.Tunnel != nil && unit.Tunnel.Name != "" {
				return unit.Tunnel.Name
			}
			kernelBase := LinuxIfName(c.ResolveReth(base))
			if unit.VlanID > 0 {
				return fmt.Sprintf("%s.%d", kernelBase, unit.VlanID)
			}
			if unit.Number == 0 {
				return kernelBase
			}
			return fmt.Sprintf("%s.%d", kernelBase, unit.Number)
		}
	}

	// Fallback for refs not modeled in cfg.Interfaces.Interfaces:
	// preserve the suffix and translate slashes only.
	return LinuxIfName(c.ResolveReth(ref))
}

// DHCPLeaseKey returns the lease-lookup key that pkg/dhcp.Manager
// keys leases by for the given config-level interface ref and unit
// number. Mirrors the construction in
// pkg/daemon/daemon_dhcp.go:56-95:
//
//	key = LinuxIfName(configRef) + ("." + strconv(unit.VlanID)) when > 0
//
// configRef is the CONFIG-LEVEL name (e.g. "reth0"), not the resolved
// physical member — the daemon's DHCP Start() is invoked with the
// config-level name.
//
// Returns ("", false) when the unit doesn't exist in cfg.
func (c *Config) DHCPLeaseKey(configRef string, unitNum int) (string, bool) {
	configRef = strings.SplitN(configRef, ".", 2)[0]
	if c.Interfaces.Interfaces == nil {
		return "", false
	}
	ifc, ok := c.Interfaces.Interfaces[configRef]
	if !ok || ifc == nil {
		return "", false
	}
	unit, ok := ifc.Units[unitNum]
	if !ok || unit == nil {
		return "", false
	}
	key := LinuxIfName(configRef)
	if unit.VlanID > 0 {
		key = key + "." + strconv.Itoa(unit.VlanID)
	}
	return key, true
}

// Config is the top-level typed configuration, compiled from the AST.
type Config struct {
	Security          SecurityConfig
	Interfaces        InterfacesConfig
	Applications      ApplicationsConfig
	RoutingOptions    RoutingOptionsConfig
	Protocols         ProtocolsConfig
	RoutingInstances  []*RoutingInstanceConfig
	Firewall          FirewallConfig
	ClassOfService    *ClassOfServiceConfig
	Services          ServicesConfig
	ForwardingOptions ForwardingOptionsConfig
	System            SystemConfig
	PolicyOptions     PolicyOptionsConfig
	Schedulers        map[string]*SchedulerConfig
	Chassis           ChassisConfig
	EventOptions      []*EventPolicy
	BridgeDomains     []*BridgeDomainConfig
	Warnings          []string // non-fatal validation warnings
}

// IRBToBridge returns a mapping of IRB interface reference (e.g. "irb.0") to
// bridge device name (e.g. "br-bd0") for all bridge domains with a routing-interface.
func IRBToBridge(bds []*BridgeDomainConfig) map[string]string {
	m := make(map[string]string)
	for _, bd := range bds {
		if bd.RoutingInterface != "" {
			m[bd.RoutingInterface] = "br-" + bd.Name
		}
	}
	return m
}

// TunnelNameMap returns a mapping from Junos interface reference (e.g. "gr-0/0/0.0")
// to the Linux tunnel interface name. A unit WITH its own per-unit
// tunnel stanza always maps to its compiler-assigned TunnelConfig.Name
// (unit 0 = base Linux name, unit N>0 = "uN" suffix,
// compiler_interfaces.go) — even when an interface-level tunnel
// coexists, because the compiler creates BOTH devices and mapping the
// unit ref to the base name would shadow the real uN device (#1910 r1
// Codex/AGY convergent High). Units WITHOUT their own tunnel stanza
// under an interface-level tunnel share the interface device; the
// interface-level gate admits WireGuard despite its empty GRE-style
// `source` (the #1736 collectAppliedTunnels twin — the persistent wgN
// TUN is one shared device, so wg0.1 must resolve to wg0, not fall
// through to a literal ".1" name).
func (c *Config) TunnelNameMap() map[string]string {
	m := make(map[string]string)
	for ifName, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		ifaceTunnel := ifc.Tunnel != nil &&
			(ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard")
		baseName := LinuxIfName(ifName)
		for unitNum, unit := range ifc.Units {
			ref := ifName + "." + strconv.Itoa(unitNum)
			if unit != nil && unit.Tunnel != nil && unit.Tunnel.Name != "" {
				// Per-unit tunnel: its own Linux device, always.
				m[ref] = unit.Tunnel.Name
				continue
			}
			if ifaceTunnel {
				// Interface-level tunnel: unit shares the device.
				m[ref] = baseName
			}
		}
	}
	return m
}
