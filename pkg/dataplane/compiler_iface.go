package dataplane

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/vishvananda/netlink"
)

// resolveInterfaceRef parses an interface reference like "enp6s0" or "enp6s0.100"
// and returns the physical Linux name, config name, unit number, and VLAN ID.
// For RETH interfaces, configName stays as "reth0" (for config lookups) while
// physName resolves to the local physical member's Linux name.
func resolveInterfaceRef(ref string, cfg *config.Config) (physName string, configName string, unitNum int, vlanID int) {
	parts := strings.SplitN(ref, ".", 2)
	configName = parts[0]

	// Resolve IRB interfaces to their bridge device name.
	// "irb.0" → bridge device "br-bd0" (looked up via bridge-domains config).
	if configName == "irb" {
		irbMap := config.IRBToBridge(cfg.BridgeDomains)
		if bridge, ok := irbMap[ref]; ok {
			physName = bridge
			if len(parts) == 2 {
				unitNum, _ = strconv.Atoi(parts[1])
			}
			return
		}
	}

	// Resolve RETH to local physical member
	rethToPhys := cfg.RethToPhysical()
	physBase := configName
	if phys, ok := rethToPhys[configName]; ok {
		physBase = phys
	}

	if strings.HasPrefix(configName, "st") && len(parts) == 2 {
		physName = config.LinuxIfName(ref)
		unitNum, _ = strconv.Atoi(parts[1])
		return
	}

	// Resolve fabric interface to local physical member for BPF attachment.
	// fab0 is an IPVLAN on ge-0-0-0; XDP/TC must attach to the parent.
	if ifCfg, ok := cfg.Interfaces.Interfaces[configName]; ok && ifCfg.LocalFabricMember != "" {
		physBase = ifCfg.LocalFabricMember
	}

	physName = config.LinuxIfName(physBase)

	if len(parts) == 2 {
		unitNum, _ = strconv.Atoi(parts[1])
	}

	// Per-unit tunnel interfaces have their own Linux interface name
	// (e.g. gr-0/0/0 unit 1 → "gr-0-0-0u1")
	if ifCfg, ok := cfg.Interfaces.Interfaces[configName]; ok {
		if unit, ok := ifCfg.Units[unitNum]; ok {
			vlanID = unit.VlanID
			if unit.Tunnel != nil {
				physName = unit.Tunnel.Name
			}
		}
	}
	return
}

// ensureVLANSubInterface creates a Linux VLAN sub-interface if it doesn't exist.
// Returns the sub-interface's ifindex.
func ensureVLANSubInterface(parentName string, vlanID int) (int, error) {
	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		return 0, fmt.Errorf("parent interface %s: %w", parentName, err)
	}

	subName := fmt.Sprintf("%s.%d", parentName, vlanID)

	// Check if sub-interface already exists
	existing, err := netlink.LinkByName(subName)
	if err == nil {
		// Already exists, ensure it's up
		if existing.Attrs().OperState != netlink.OperUp {
			netlink.LinkSetUp(existing)
		}
		return existing.Attrs().Index, nil
	}

	// Create VLAN sub-interface
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        subName,
			ParentIndex: parent.Attrs().Index,
		},
		VlanId: vlanID,
	}
	if err := netlink.LinkAdd(vlan); err != nil {
		return 0, fmt.Errorf("create VLAN sub-interface %s: %w", subName, err)
	}

	// Bring it up
	link, err := netlink.LinkByName(subName)
	if err != nil {
		return 0, fmt.Errorf("find created VLAN sub-interface %s: %w", subName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, fmt.Errorf("set VLAN sub-interface %s up: %w", subName, err)
	}

	// Disable RA acceptance — firewall uses its own configured routes.
	raPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", subName)
	if err := os.WriteFile(raPath, []byte("0"), 0644); err != nil {
		slog.Warn("failed to disable accept_ra on VLAN sub-interface", "name", subName, "err", err)
	}

	slog.Info("created VLAN sub-interface",
		"name", subName, "parent", parentName, "vlan_id", vlanID,
		"ifindex", link.Attrs().Index)

	return link.Attrs().Index, nil
}

func isConfiguredVLANSubInterface(name string, cfg *config.Config) bool {
	idx := strings.IndexByte(name, '.')
	if idx < 0 {
		return false
	}
	base := name[:idx]
	suffix := name[idx+1:]
	vid, err := strconv.Atoi(suffix)
	if err != nil {
		return false
	}
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if !ifCfg.VlanTagging || config.LinuxIfName(ifName) != base {
			continue
		}
		for _, unit := range ifCfg.Units {
			if unit.VlanID == vid {
				return true
			}
		}
	}
	return false
}

// reconcileInterfaceAddresses ensures the interface has exactly the configured
// addresses. Stale addresses are removed and missing ones are added.
// Link-local (fe80::/10) addresses are left untouched since the kernel manages them.
func reconcileInterfaceAddresses(ifaceName string, desired []string) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		slog.Warn("cannot find interface for address reconciliation",
			"name", ifaceName, "err", err)
		return
	}

	// Build desired set keyed by "ip/mask"
	want := make(map[string]*netlink.Addr, len(desired))
	for _, addrStr := range desired {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("invalid address for interface",
				"addr", addrStr, "name", ifaceName, "err", err)
			continue
		}
		want[addr.IPNet.String()] = addr
	}

	// List current kernel addresses (both v4 and v6)
	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		slog.Warn("failed to list addresses on interface",
			"name", ifaceName, "err", err)
		// Fall through to add-only mode
		existing = nil
	}

	// Remove stale addresses (skip link-local)
	for i := range existing {
		addr := &existing[i]
		if addr.IP.IsLinkLocalUnicast() || addr.IP.IsLinkLocalMulticast() {
			continue
		}
		key := addr.IPNet.String()
		if _, ok := want[key]; ok {
			// Already present, no need to add
			delete(want, key)
		} else {
			// Stale — remove it
			if err := netlink.AddrDel(link, addr); err != nil {
				slog.Warn("failed to remove stale address from interface",
					"addr", key, "name", ifaceName, "err", err)
			} else {
				slog.Info("removed stale address from interface",
					"addr", key, "name", ifaceName)
			}
		}
	}

	// Add missing addresses
	for key, addr := range want {
		if err := netlink.AddrAdd(link, addr); err != nil {
			if !strings.Contains(err.Error(), "exists") {
				slog.Warn("failed to add address to interface",
					"addr", key, "name", ifaceName, "err", err)
			}
		}
	}
}

func compileZones(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear: write new entries first,
	// then delete stale ones that are no longer in the config.
	writtenIfaceZone := make(map[IfaceZoneKey]bool)
	writtenVlanIface := make(map[uint32]bool)

	// Build interface -> routing table ID map from routing instances.
	// Forwarding instances use the default table (0), so skip them.
	ifaceTableID := make(map[string]uint32)
	for _, ri := range cfg.RoutingInstances {
		if ri.InstanceType == "forwarding" {
			continue
		}
		for _, ifaceName := range ri.Interfaces {
			ifaceTableID[ifaceName] = uint32(ri.TableID)
		}
	}

	// Track which physical interfaces have already had one-time parent setup.
	attached := make(map[int]bool)
	// Track which interfaces already have a deferred XDP attachment queued.
	attachedXDP := make(map[int]bool)
	// Collect ifindexes for deferred XDP attachment.
	var xdpIfindexes []int
	// Tunnel interfaces need XDP for ingress but must NOT be in
	// redirect_capable or tx_ports — bpf_redirect_map sends the full
	// Ethernet frame, but POINTOPOINT tunnels expect raw IP.
	tunnelIfindexes := make(map[int]bool)

	for name, zone := range cfg.Security.Zones {
		zid := result.ZoneIDs[name]

		// Write zone_config
		zc := ZoneConfig{
			ZoneID: zid,
		}

		// Look up screen profile ID for this zone
		if zone.ScreenProfile != "" {
			if sid, ok := result.ScreenIDs[zone.ScreenProfile]; ok {
				zc.ScreenProfileID = sid
				slog.Info("zone screen profile assigned",
					"zone", name, "screen", zone.ScreenProfile, "id", sid)
			} else {
				return fmt.Errorf("screen profile %q not found for zone %q",
					zone.ScreenProfile, name)
			}
		}

		// Compile host-inbound-traffic flags
		if zone.HostInboundTraffic != nil {
			var flags uint32
			for _, svc := range zone.HostInboundTraffic.SystemServices {
				if f, ok := HostInboundServiceFlags[svc]; ok {
					flags |= f
				} else {
					slog.Warn("unknown host-inbound system-service",
						"service", svc, "zone", name)
				}
			}
			for _, proto := range zone.HostInboundTraffic.Protocols {
				if f, ok := HostInboundProtocolFlags[proto]; ok {
					flags |= f
				} else {
					slog.Warn("unknown host-inbound protocol",
						"protocol", proto, "zone", name)
				}
			}
			zc.HostInbound = flags
			slog.Info("host-inbound-traffic compiled",
				"zone", name, "flags", fmt.Sprintf("0x%x", flags))
		}

		if zone.TCPRst {
			zc.TCPRst = 1
		}

		if err := dp.SetZoneConfig(zid, zc); err != nil {
			return fmt.Errorf("set zone config %s: %w", name, err)
		}

		// Map interfaces to zone
		for _, ifaceRef := range zone.Interfaces {
			physName, cfgName, unitNum, vlanID := resolveInterfaceRef(ifaceRef, cfg)

			// Get the physical interface (cached to avoid redundant syscalls)
			physIface, err := result.cachedInterfaceByName(physName)
			if err != nil {
				slog.Warn("interface not found, skipping",
					"interface", physName, "zone", name, "err", err)
				continue
			}

			if vlanID > 0 {
				// VLAN sub-interface: create it, populate vlan_iface_map
				subIfindex, err := ensureVLANSubInterface(physName, vlanID)
				if err != nil {
					slog.Warn("VLAN sub-interface failed, skipping",
						"parent", physName, "vlan_id", vlanID, "zone", name, "err", err)
					continue
				}

				if err := dp.SetVlanIfaceInfo(subIfindex, physIface.Index, uint16(vlanID)); err != nil {
					return fmt.Errorf("set vlan_iface_info %s.%d: %w",
						physName, vlanID, err)
				}
				writtenVlanIface[uint32(subIfindex)] = true

				// Reconcile addresses on sub-interface (removes stale, adds missing).
				// DHCP-managed and RETH sub-interfaces are skipped — DHCP client
				// manages DHCP addresses, VRRP manages RETH VIP addresses.
				subName := fmt.Sprintf("%s.%d", physName, vlanID)
				var addrs []string
				isDHCPSub := false
				isReth := false
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
					if unit, ok := ifCfg.Units[unitNum]; ok {
						addrs = unit.Addresses
						isDHCPSub = unit.DHCP || unit.DHCPv6
					}
					if ifCfg.RedundancyGroup > 0 {
						isReth = true
					}
				}
				if !isDHCPSub && !isReth {
					reconcileInterfaceAddresses(subName, addrs)
				}

				// Apply unit-level MTU to VLAN sub-interface
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
					if unit, ok := ifCfg.Units[unitNum]; ok && unit.MTU > 0 {
						if nl, err := result.cachedLinkByName(subName); err == nil {
							if nl.Attrs().MTU != unit.MTU {
								if err := netlink.LinkSetMTU(nl, unit.MTU); err != nil {
									slog.Warn("failed to set VLAN sub-interface MTU",
										"name", subName, "mtu", unit.MTU, "err", err)
								} else {
									slog.Info("set VLAN sub-interface MTU", "name", subName, "mtu", unit.MTU)
								}
							}
						}
					}
				}

				slog.Info("VLAN sub-interface configured",
					"parent", physName, "vlan_id", vlanID,
					"sub_ifindex", subIfindex, "zone", name)

				// Native GRE on VLAN transport needs XDP on the child interface
				// itself; packets can ingress via ge-*.VID without ever running
				// the parent's driver XDP hook. VLAN children do not support the
				// fast path reliably here, so keep them on generic XDP only.
				if !attachedXDP[subIfindex] {
					xdpIfindexes = append(xdpIfindexes, subIfindex)
					result.genericXDPIfindexes[subIfindex] = true
					attachedXDP[subIfindex] = true
				}
			}

			// Set zone mapping using composite key {physIfindex, vlanID}
			tableID := ifaceTableID[ifaceRef] // 0 if not in any routing instance
			var izFlags uint8
			var rgID uint8
			var screenFlags uint32
			if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
				if ifCfg.Tunnel != nil {
					izFlags |= IfaceFlagTunnel
				}
				// Check per-unit tunnel
				if unit, ok := ifCfg.Units[unitNum]; ok && unit.Tunnel != nil {
					izFlags |= IfaceFlagTunnel
				}
				if ifCfg.RedundancyGroup > 0 {
					rgID = uint8(ifCfg.RedundancyGroup)
				} else if ifCfg.RedundantParent != "" {
					// Physical RETH member: inherit RG from the RETH parent.
					// Without this, check_egress_rg_active() in BPF returns
					// rg_id=0 for RETH member VLAN sub-interfaces, bypassing
					// the HA active/inactive check and preventing fabric
					// redirect after RG failover.
					if reth, ok := cfg.Interfaces.Interfaces[ifCfg.RedundantParent]; ok && reth.RedundancyGroup > 0 {
						rgID = uint8(reth.RedundancyGroup)
					}
				}
			}
			if zone.ScreenProfile != "" {
				profile, ok := cfg.Security.Screen[zone.ScreenProfile]
				if !ok {
					return fmt.Errorf("screen profile %q not found for zone %q",
						zone.ScreenProfile, name)
				}
				screenFlags = buildScreenConfig(
					profile,
					cfg.Security.Flow.SynFloodProtectionMode == "syn-cookie",
				).Flags
			}
			if izFlags&IfaceFlagTunnel != 0 {
				tunnelIfindexes[physIface.Index] = true
			} else {
				// Optimistically set native XDP flag for non-tunnel
				// interfaces.  Cleared in needGeneric fallback below.
				izFlags |= IfaceFlagNativeXDP
			}
			if err := dp.SetZone(physIface.Index, uint16(vlanID), zid, tableID, izFlags, rgID, screenFlags); err != nil {
				return fmt.Errorf("set zone for %s vlan %d (ifindex %d): %w",
					physName, vlanID, physIface.Index, err)
			}
			writtenIfaceZone[IfaceZoneKey{Ifindex: uint32(physIface.Index), VlanID: uint16(vlanID)}] = true

			// Add physical interface to tx_ports and attach TC (once per phys iface).
			// XDP attachment is deferred to after the loop so we can ensure
			// all interfaces use the same XDP mode (native vs generic).
			if !attached[physIface.Index] {
				// Skip tx_ports for tunnel interfaces — bpf_redirect_map
				// sends Ethernet frames but tunnels expect raw IP.
				if tunnelIfindexes[physIface.Index] {
					slog.Info("skipping tx_port for tunnel interface",
						"name", physName, "ifindex", physIface.Index)
				} else if err := dp.AddTxPort(physIface.Index); err != nil {
					return fmt.Errorf("add tx port %s: %w", physName, err)
				}

				// Disable VLAN RX offload so XDP sees VLAN tags in packet data
				// (otherwise NIC strips them into skb->vlan_tci which XDP can't read).
				// Check current state first — toggling rxvlan on iavf VFs causes a
				// driver reset that drops in-flight packets (kills active TCP sessions).
				result.ensureRxVlanOff(physName)

				// Single cached netlink lookup for MTU, speed/duplex, and UP/DOWN.
				nl, nlErr := result.cachedLinkByIndex(physIface.Index)

				// Apply interface-level MTU from config
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok && ifCfg.MTU > 0 && nlErr == nil {
					if nl.Attrs().MTU != ifCfg.MTU {
						if err := netlink.LinkSetMTU(nl, ifCfg.MTU); err != nil {
							slog.Warn("failed to set MTU",
								"name", physName, "mtu", ifCfg.MTU, "err", err)
						} else {
							slog.Info("set interface MTU", "name", physName, "mtu", ifCfg.MTU)
						}
					}
				}

				// Apply interface speed/duplex via ethtool if configured
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
					result.applyEthtool(physName, ifCfg)
				}

				// Tune ring buffers and txqueuelen BEFORE XDP attachment
				// (ethtool -G can reset the NIC, disrupting attached programs).
				if nlErr == nil {
					result.tuneInterfaceBuffers(nl)
				}

				// Bring the interface UP so XDP can process traffic,
				// unless the interface is administratively disabled.
				// Note: For DPDK-bound ports, LinkSetDown has no effect because
				// DPDK takes over the NIC via VFIO/UIO, bypassing the kernel
				// driver. DPDK ports are disabled by not including them in the
				// worker's poll set (the zone map lookup will miss, causing drop).
				isDisabled := false
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok && ifCfg.Disable {
					isDisabled = true
					if nlErr == nil {
						if err := netlink.LinkSetDown(nl); err != nil {
							slog.Warn("failed to bring disabled interface down",
								"name", physName, "err", err)
						} else {
							slog.Info("interface administratively disabled", "name", physName)
						}
					}
				} else if nlErr == nil {
					if err := netlink.LinkSetUp(nl); err != nil {
						slog.Warn("failed to bring interface up",
							"name", physName, "err", err)
					}
				}

				// Skip XDP/TC attachment for disabled interfaces — they are
				// administratively down and should not process traffic.
				if isDisabled {
					slog.Info("skipping XDP/TC attachment for disabled interface",
						"name", physName, "ifindex", physIface.Index)
				} else {
					// Defer actual XDP/TC attachment to after all compile phases
					// so link.Update() switches to programs with fully-populated maps.
					if !attachedXDP[physIface.Index] {
						xdpIfindexes = append(xdpIfindexes, physIface.Index)
						attachedXDP[physIface.Index] = true
					}
					// Skip TC egress for tunnel interfaces — kernel forwards
					// the inner packet to the tunnel device, and TC egress
					// would see it with ingress_ifindex != 0 and drop it.
					// Tunnels need XDP for ingress (decapsulated traffic)
					// but not TC for egress (encapsulation is kernel work).
					if !tunnelIfindexes[physIface.Index] {
						result.pendingTC = append(result.pendingTC, physIface.Index)
					} else {
						slog.Info("skipping TC for tunnel interface",
							"name", physName, "ifindex", physIface.Index)
					}
				}
				attached[physIface.Index] = true
			}

			// Reconcile addresses for non-VLAN, non-DHCP, non-RETH, non-fabric-parent interfaces.
			// DHCP-managed interfaces are skipped — the DHCP client manages their addresses.
			// RETH interfaces are skipped — VRRP manages their VIP addresses.
			// Fabric parents are skipped — addresses go on the IPVLAN overlay (fab0/fab1).
			if vlanID == 0 {
				var addrs []string
				isDHCP := false
				isReth := false
				isFabricParent := false
				var unitMTU int
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
					if unit, ok := ifCfg.Units[unitNum]; ok {
						addrs = unit.Addresses
						isDHCP = unit.DHCP || unit.DHCPv6
						unitMTU = unit.MTU
					}
					if ifCfg.RedundancyGroup > 0 {
						isReth = true
					}
					if ifCfg.LocalFabricMember != "" {
						isFabricParent = true
					}
				}
				if !isDHCP && !isReth && !isFabricParent {
					reconcileInterfaceAddresses(physName, addrs)
				}
				// Apply unit-level MTU (overrides interface-level MTU)
				if unitMTU > 0 {
					if nl, err := result.cachedLinkByName(physName); err == nil {
						if nl.Attrs().MTU != unitMTU {
							if err := netlink.LinkSetMTU(nl, unitMTU); err != nil {
								slog.Warn("failed to set unit MTU",
									"name", physName, "mtu", unitMTU, "err", err)
							} else {
								slog.Info("set unit MTU", "name", physName, "unit", unitNum, "mtu", unitMTU)
							}
						}
					}
				}
			}

			slog.Info("zone interface configured",
				"zone", name, "interface", ifaceRef,
				"phys_ifindex", physIface.Index, "vlan_id", vlanID,
				"zone_id", zid)
		}
	}

	// Auto-add HOST_INBOUND_GRE to zones carrying GRE tunnel transport.
	// When a GRE tunnel is configured, the outer encapsulated packets must
	// reach the kernel for decapsulation.  Without this, the zone's
	// host-inbound policy blocks outer GRE (protocol 47) because it's not
	// explicitly listed as a system-service.
	autoFlags := make(map[string]uint32) // zone name → extra flags
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		tunnels := []*config.TunnelConfig{}
		if ifCfg.Tunnel != nil {
			tunnels = append(tunnels, ifCfg.Tunnel)
		}
		for _, unit := range ifCfg.Units {
			if unit.Tunnel != nil {
				tunnels = append(tunnels, unit.Tunnel)
			}
		}
		for _, tun := range tunnels {
			if tun.Source == "" {
				continue
			}
			srcIP := net.ParseIP(tun.Source)
			if srcIP == nil {
				continue
			}
			var flag uint32
			if tun.Mode == "gre" || tun.Mode == "" {
				flag = HostInboundGRE
			}
			if flag == 0 {
				continue
			}
			// Find which zone's interface carries this tunnel source IP.
			for zoneName, zone := range cfg.Security.Zones {
				for _, ifRef := range zone.Interfaces {
					_, cn, un, _ := resolveInterfaceRef(ifRef, cfg)
					ic, ok := cfg.Interfaces.Interfaces[cn]
					if !ok {
						continue
					}
					u, ok := ic.Units[un]
					if !ok {
						continue
					}
					for _, addr := range u.Addresses {
						ip, _, err := net.ParseCIDR(addr)
						if err != nil {
							continue
						}
						if ip.Equal(srcIP) {
							autoFlags[zoneName] |= flag
						}
					}
				}
			}
		}
	}
	for zoneName, flags := range autoFlags {
		zid, ok := result.ZoneIDs[zoneName]
		if !ok {
			continue
		}
		zone := cfg.Security.Zones[zoneName]
		var existing uint32
		if zone.HostInboundTraffic != nil {
			for _, svc := range zone.HostInboundTraffic.SystemServices {
				if f, ok := HostInboundServiceFlags[svc]; ok {
					existing |= f
				}
			}
			for _, proto := range zone.HostInboundTraffic.Protocols {
				if f, ok := HostInboundProtocolFlags[proto]; ok {
					existing |= f
				}
			}
		}
		if existing&flags != flags {
			merged := existing | flags
			zc := ZoneConfig{HostInbound: merged}
			if zone.TCPRst {
				zc.TCPRst = 1
			}
			dp.SetZoneConfig(zid, zc)
			slog.Info("auto-added host-inbound for tunnel transport",
				"zone", zoneName, "flags", fmt.Sprintf("0x%x", flags))
		}
	}

	// Store pending XDP ifindexes for deferred attachment after all compile phases.
	result.pendingXDP = xdpIfindexes
	result.tunnelIfindexes = tunnelIfindexes

	// Collect managed interface info for networkd config generation.
	// Iterate over configured interfaces (not zones) to get a clean
	// per-interface view including VLAN parent and sub-interface entries.
	//
	// RETH interfaces (reth0, reth1) are config-only — no bond devices are
	// created. Physical member interfaces (with RedundantParent) inherit the
	// reth's addresses, VLANs, and redundancy group settings.
	//
	// For VRRP-backed RETH, VIP addresses are managed by native VRRP. The
	// networkd .network file gets a link-local base address (169.254.RG.NODE/32)
	// instead — VRRP requires at least one IPv4 for advertisements.
	clusterNodeID := -1
	if cfg.Chassis.Cluster != nil {
		clusterNodeID = cfg.Chassis.Cluster.NodeID
	}
	rethToPhys := cfg.RethToPhysical()
	seen := make(map[string]bool)
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if strings.HasPrefix(ifName, "st") {
			mtu := ifCfg.MTU
			for unitNum, unit := range ifCfg.Units {
				unitName, _ := config.XFRMIfNameAndID(fmt.Sprintf("%s.%d", ifName, unitNum))
				if unitName == "" {
					continue
				}
				if _, err := result.cachedInterfaceByName(unitName); err != nil {
					continue
				}
				if seen[unitName] {
					continue
				}
				seen[unitName] = true
				unitMTU := mtu
				if unit.MTU > 0 && (unitMTU == 0 || unit.MTU < unitMTU) {
					unitMTU = unit.MTU
				}
				desc := ifCfg.Description
				if unit.Description != "" {
					desc = unit.Description
				}
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:             unitName,
					Addresses:        unit.Addresses,
					PrimaryAddress:   unit.PrimaryAddress,
					PreferredAddress: unit.PreferredAddress,
					DHCPv4:           unit.DHCP,
					DHCPv6:           unit.DHCPv6,
					DADDisable:       unit.DADDisable,
					MTU:              unitMTU,
					Description:      desc,
				})
			}
			continue
		}

		// Skip reth interfaces — no physical device exists; the physical
		// member interface inherits the reth's config below.
		if _, isReth := rethToPhys[ifName]; isReth {
			continue
		}

		// For physical members with a RedundantParent, merge the parent
		// reth's config (addresses, VLANs, redundancy group).
		effectiveCfg := ifCfg
		isVRRPReth := false
		if ifCfg.RedundantParent != "" {
			if rethCfg, ok := cfg.Interfaces.Interfaces[ifCfg.RedundantParent]; ok {
				effectiveCfg = rethCfg
				isVRRPReth = rethCfg.RedundancyGroup > 0 && clusterNodeID >= 0
			}
		} else {
			isVRRPReth = ifCfg.RedundancyGroup > 0 && clusterNodeID >= 0
		}

		linuxName := config.LinuxIfName(ifName)
		originalName := "" // kernel name before .link rename (for RETH recovery)
		physIface, err := result.cachedInterfaceByName(linuxName)
		if err != nil && isVRRPReth && cfg.Chassis.Cluster != nil {
			// Interface not found under its config name — it may exist
			// under its kernel name if the .link rename was lost. Search
			// by the expected RETH virtual MAC.
			rgID := effectiveCfg.RedundancyGroup
			expectedMAC := net.HardwareAddr{0x02, 0xbf, 0x72,
				byte(cfg.Chassis.Cluster.ClusterID), byte(rgID), byte(clusterNodeID)}
			physIface = findInterfaceByMAC(expectedMAC)
			if physIface != nil {
				slog.Info("found RETH member under kernel name",
					"config", linuxName, "actual", physIface.Name,
					"mac", expectedMAC)
				// Mark kernel name as seen so unmanaged detection skips it.
				seen[physIface.Name] = true
				// Use OriginalName= in .link for stable matching across
				// reboots (PCI name is stable, MAC alternates between
				// physical and virtual).
				originalName = physIface.Name
			}
		}
		// vSRX fabric member resolution: when a fabric interface (fab0, fab1)
		// has a LocalFabricMember set (vSRX fabric-options mode), look up the
		// member's Linux name to find the physical interface and rename it.
		if physIface == nil && strings.HasPrefix(ifName, "fab") && ifCfg.LocalFabricMember != "" {
			memberLinux := config.LinuxIfName(ifCfg.LocalFabricMember)
			physIface, _ = result.cachedInterfaceByName(memberLinux)
			if physIface != nil {
				slog.Info("found vSRX fabric member interface",
					"fab", linuxName, "member", ifCfg.LocalFabricMember,
					"kernel", physIface.Name)
				seen[physIface.Name] = true
				originalName = physIface.Name
			}
		}
		// Fabric interface recovery: when a fabric interface (fab0, fab1)
		// isn't found by name, read the bootstrap .link file for its
		// OriginalName= (PCI kernel name) and look up the kernel interface
		// under that name. This handles the case where the .link rename
		// hasn't taken effect yet (e.g. no reboot since bootstrap).
		if physIface == nil && strings.HasPrefix(ifName, "fab") {
			origName := readOriginalNameFromLink(linuxName)
			if origName != "" {
				physIface, err = result.cachedInterfaceByName(origName)
				if physIface != nil {
					slog.Info("found fabric interface under kernel name",
						"config", linuxName, "actual", physIface.Name,
						"originalName", origName)
					seen[physIface.Name] = true
					originalName = origName
				}
			}
		}
		if physIface == nil {
			continue
		}
		// IPVLAN fabric: mark the parent interface as seen so unmanaged
		// detection doesn't bring it DOWN (IPVLAN needs parent UP for carrier).
		// Also add a ManagedInterfaces entry (no addresses, no .link) so the
		// parent gets a .network file that keeps it UP.
		if ifCfg.LocalFabricMember != "" {
			parentLinux := config.LinuxIfName(ifCfg.LocalFabricMember)
			if !seen[parentLinux] {
				seen[parentLinux] = true
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:        parentLinux,
					Description: "fabric parent (IPVLAN host)",
				})
			}
		}
		mac := physIface.HardwareAddr.String()
		if mac == "" {
			continue
		}
		// If this is a RETH member with a virtual MAC already programmed
		// (02:bf:72:...), use the permanent (factory) MAC for the .link
		// file so it matches on reboot before the daemon sets the virtual MAC.
		if isVRRPReth && isVirtualRethMAC(physIface.HardwareAddr) {
			// Recover original kernel name for stable .link OriginalName=
			// matching. More reliable than MACAddress= because the MAC
			// alternates between physical (boot) and virtual (daemon sets it).
			if originalName == "" {
				originalName = getOriginalKernelName(physIface.Name, result)
				if originalName == "" {
					originalName = readOriginalNameFromLink(linuxName)
				}
				if originalName != "" {
					slog.Info("recovered RETH original kernel name",
						"iface", linuxName, "originalName", originalName)
				}
			}
			// Use permanent MAC when available to avoid writing the virtual
			// MAC to the .link MACAddress field. If OriginalName is set,
			// generateLink uses it instead of MACAddress anyway.
			if permMAC := getPermAddr(physIface.Name, result); permMAC != "" {
				mac = permMAC
			}
		}

		// vSRX fabric members (LocalFabricMember set): the parent physical
		// interface (ge-0-0-0) keeps its name; fab0 is an IPVLAN overlay.
		// Don't write a .link file for the fab* name — linksetup already
		// handles ge-X-0-Y naming. Clear addresses since they go on the IPVLAN.
		if ifCfg.LocalFabricMember != "" {
			mac = ""
			originalName = ""
		}

		if effectiveCfg.VlanTagging {
			// VLAN parent: no addresses, just rename
			if !seen[linuxName] {
				seen[linuxName] = true
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:         linuxName,
					MACAddress:   mac,
					OriginalName: originalName,
					IsVLANParent: true,
					Disable:      ifCfg.Disable,
					Speed:        ifCfg.Speed,
					Duplex:       ifCfg.Duplex,
					MTU:          ifCfg.MTU,
					Description:  ifCfg.Description,
				})
			}
			// VLAN sub-interfaces get their own .network file
			for _, unit := range effectiveCfg.Units {
				if unit.VlanID > 0 {
					subName := fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					if !seen[subName] {
						seen[subName] = true
						addrs := unit.Addresses
						if isVRRPReth {
							// Replace VIP addresses with a link-local base for VRRP.
							addrs = []string{fmt.Sprintf("169.254.%d.%d/32", effectiveCfg.RedundancyGroup, clusterNodeID+1)}
						}
						result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
							Name:             subName,
							Addresses:        addrs,
							PrimaryAddress:   unit.PrimaryAddress,
							PreferredAddress: unit.PreferredAddress,
							DHCPv4:           unit.DHCP,
							DHCPv6:           unit.DHCPv6,
							DADDisable:       unit.DADDisable,
							MTU:              unit.MTU,
							Description:      unit.Description,
							KeepAddresses:    isVRRPReth,
						})
					}
				}
			}
		} else {
			// Regular interface (non-VLAN)
			if !seen[linuxName] {
				seen[linuxName] = true
				// Collect addresses from all units (using effective config for RETH members)
				var addrs []string
				var dhcpv4, dhcpv6, dadDisable bool
				var primaryAddr, preferredAddr string
				unitMTU := 0
				for _, unit := range effectiveCfg.Units {
					addrs = append(addrs, unit.Addresses...)
					if unit.DHCP {
						dhcpv4 = true
					}
					if unit.DHCPv6 {
						dhcpv6 = true
					}
					if unit.DADDisable {
						dadDisable = true
					}
					if unit.MTU > 0 && (unitMTU == 0 || unit.MTU < unitMTU) {
						unitMTU = unit.MTU
					}
					if unit.PrimaryAddress != "" && primaryAddr == "" {
						primaryAddr = unit.PrimaryAddress
					}
					if unit.PreferredAddress != "" && preferredAddr == "" {
						preferredAddr = unit.PreferredAddress
					}
				}
				// Unit-level MTU (family inet/inet6) overrides interface-level MTU
				mtu := ifCfg.MTU
				if unitMTU > 0 && (mtu == 0 || unitMTU < mtu) {
					mtu = unitMTU
				}
				// VRRP-backed RETH: replace VIP addresses with a
				// link-local base; native VRRP manages the actual VIPs.
				if isVRRPReth {
					addrs = []string{fmt.Sprintf("169.254.%d.%d/32", effectiveCfg.RedundancyGroup, clusterNodeID+1)}
					primaryAddr = ""
					preferredAddr = ""
				}
				// Management interfaces (fxp*, fab*) are bound to vrf-mgmt.
				// Include VRF= in .network so networkctl reconfigure preserves binding.
				vrfName := ""
				if strings.HasPrefix(ifName, "fxp") || strings.HasPrefix(ifName, "fab") || strings.HasPrefix(ifName, "em") {
					vrfName = "vrf-mgmt"
				}
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:             linuxName,
					MACAddress:       mac,
					OriginalName:     originalName,
					Addresses:        addrs,
					PrimaryAddress:   primaryAddr,
					PreferredAddress: preferredAddr,
					DHCPv4:           dhcpv4,
					DHCPv6:           dhcpv6,
					Disable:          ifCfg.Disable,
					DADDisable:       dadDisable,
					Speed:            ifCfg.Speed,
					Duplex:           ifCfg.Duplex,
					MTU:              mtu,
					Description:      ifCfg.Description,
					KeepAddresses:    isVRRPReth,
					VRFName:          vrfName,
				})
			}
		}
	}

	// Generate networkd .netdev + .network files for fabric bonds with multiple
	// members. This makes the bond persistent across reboots via systemd-networkd
	// (the routing package also creates the bond via netlink at runtime).
	// Skip vSRX-style fabric (LocalFabricMember set) — the daemon creates an
	// IPVLAN on the single local member; no bond needed.
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if len(ifCfg.FabricMembers) <= 1 || ifCfg.LocalFabricMember != "" {
			continue
		}
		bondName := ifName
		if !seen[bondName] {
			seen[bondName] = true
			// Collect addresses from fabric interface units
			var addrs []string
			for _, unit := range ifCfg.Units {
				addrs = append(addrs, unit.Addresses...)
			}
			result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
				Name:        bondName,
				IsBond:      true,
				BondMode:    "active-backup",
				Addresses:   addrs,
				Description: ifCfg.Description,
				MTU:         ifCfg.MTU,
				VRFName:     "vrf-mgmt",
			})
		}
		// Member interfaces: .network with Bond= referencing the bond
		for _, member := range ifCfg.FabricMembers {
			memberName := config.LinuxIfName(member)
			if seen[memberName] {
				continue
			}
			seen[memberName] = true
			var mac string
			if iface, err := result.cachedInterfaceByName(memberName); err == nil {
				mac = iface.HardwareAddr.String()
			}
			result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
				Name:       memberName,
				MACAddress: mac,
				BondMaster: bondName,
			})
		}
	}

	// Bridge domains: generate bridge .netdev + .network entries and set
	// BridgeMaster on VLAN sub-interfaces that belong to a bridge domain.
	// Build vlanID → bridge device name map for bridge member assignment.
	vlanToBridge := make(map[int]string)
	for _, bd := range cfg.BridgeDomains {
		bridgeName := "br-" + bd.Name
		for _, vid := range bd.VlanIDs {
			vlanToBridge[vid] = bridgeName
		}
	}

	for _, bd := range cfg.BridgeDomains {
		bridgeName := "br-" + bd.Name
		if seen[bridgeName] {
			continue
		}
		seen[bridgeName] = true

		// Collect IRB addresses from the referenced interface unit
		var addrs []string
		if bd.RoutingInterface != "" {
			// Parse "irb.N" to get unit number
			parts := strings.SplitN(bd.RoutingInterface, ".", 2)
			if len(parts) == 2 {
				irbName := parts[0] // "irb"
				unitNum, _ := strconv.Atoi(parts[1])
				if irbCfg, ok := cfg.Interfaces.Interfaces[irbName]; ok {
					if unit, ok := irbCfg.Units[unitNum]; ok {
						addrs = unit.Addresses
					}
				}
			}
		}

		result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
			Name:      bridgeName,
			IsBridge:  true,
			Addresses: addrs,
		})
	}

	// Set BridgeMaster on VLAN sub-interfaces that are bridge domain members.
	for i, mi := range result.ManagedInterfaces {
		if !isConfiguredVLANSubInterface(mi.Name, cfg) {
			continue
		}
		if idx := strings.IndexByte(mi.Name, '.'); idx >= 0 {
			suffix := mi.Name[idx+1:]
			if vid, err := strconv.Atoi(suffix); err == nil {
				if bridge, ok := vlanToBridge[vid]; ok {
					result.ManagedInterfaces[i].BridgeMaster = bridge
				}
			}
		}
	}

	// Discover all system interfaces and mark unconfigured ones as unmanaged.
	// Unmanaged interfaces are brought down and have addresses removed to
	// prevent traffic leaking through unconfigured paths.
	//
	// Skip interfaces created by the daemon itself (VRFs, tunnels, bridges).
	daemonOwned := make(map[string]bool)
	daemonOwned["vrf-mgmt"] = true // implicit management VRF for fxp*/fab*
	for _, ri := range cfg.RoutingInstances {
		if ri.InstanceType != "forwarding" {
			daemonOwned["vrf-"+ri.Name] = true
		}
	}
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.Tunnel != nil {
			daemonOwned[ifc.Tunnel.Name] = true
		}
		// Per-unit tunnel interfaces
		for _, unit := range ifc.Units {
			if unit.Tunnel != nil {
				daemonOwned[unit.Tunnel.Name] = true
			}
		}
		if len(ifc.FabricMembers) > 0 {
			daemonOwned[name] = true
		}
		// IPVLAN fabric overlays (fab0, fab1) are daemon-created.
		if ifc.LocalFabricMember != "" {
			daemonOwned[config.LinuxIfName(name)] = true
		}
	}
	for _, bd := range cfg.BridgeDomains {
		daemonOwned["br-"+bd.Name] = true
	}

	allIfaces, _ := net.Interfaces()
	for _, iface := range allIfaces {
		name := iface.Name
		// Skip loopback, already-managed, and daemon-created interfaces
		if name == "lo" || seen[name] || daemonOwned[name] {
			continue
		}
		// Skip VLAN sub-interfaces of managed parents
		if idx := strings.IndexByte(name, '.'); idx >= 0 {
			if seen[name[:idx]] {
				continue
			}
		}
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}

		// If this is a daemon-created bond/RETH that's no longer in config,
		// delete the device entirely rather than marking it unmanaged.
		nl, err := result.cachedLinkByIndex(iface.Index)
		if err != nil {
			continue
		}
		if _, isBond := nl.(*netlink.Bond); isBond {
			if err := netlink.LinkDel(nl); err == nil {
				slog.Info("deleted stale bond device", "name", name)
			} else {
				slog.Warn("failed to delete stale bond", "name", name, "err", err)
			}
			continue
		}

		seen[name] = true
		result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
			Name:       name,
			MACAddress: mac,
			Unmanaged:  true,
		})

		// Bring down and remove all non-link-local addresses immediately.
		// The networkd .network file with ActivationPolicy=always-down
		// ensures it stays down across reboots.
		addrs, _ := netlink.AddrList(nl, netlink.FAMILY_ALL)
		for i := range addrs {
			if addrs[i].IP.IsLinkLocalUnicast() || addrs[i].IP.IsLinkLocalMulticast() {
				continue
			}
			if err := netlink.AddrDel(nl, &addrs[i]); err == nil {
				slog.Info("removed address from unmanaged interface",
					"addr", addrs[i].IPNet, "name", name)
			}
		}
		if err := netlink.LinkSetDown(nl); err == nil {
			slog.Info("brought down unmanaged interface", "name", name)
		}
	}

	// Delete stale zone/VLAN map entries no longer in the config.
	dp.DeleteStaleIfaceZone(writtenIfaceZone)
	dp.DeleteStaleVlanIface(writtenVlanIface)

	return nil
}

func compileScreenProfiles(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	var maxScreenID uint32
	for name, profile := range cfg.Security.Screen {
		sid, ok := result.ScreenIDs[name]
		if !ok {
			continue
		}

		sc := buildScreenConfig(
			profile,
			cfg.Security.Flow.SynFloodProtectionMode == "syn-cookie",
		)

		if err := dp.SetScreenConfig(uint32(sid), sc); err != nil {
			return fmt.Errorf("set screen config %s (id=%d): %w", name, sid, err)
		}
		if uint32(sid) > maxScreenID {
			maxScreenID = uint32(sid)
		}

		slog.Info("screen profile compiled",
			"name", name, "id", sid,
			"flags", fmt.Sprintf("0x%x", sc.Flags),
			"syn_thresh", sc.SynFloodThresh,
			"icmp_thresh", sc.ICMPFloodThresh,
			"udp_thresh", sc.UDPFloodThresh)
	}

	// Zero screen config entries above the highest used ID.
	dp.ZeroStaleScreenConfigs(maxScreenID)

	return nil
}

func buildScreenConfig(profile *config.ScreenProfile, synCookie bool) ScreenConfig {
	var sc ScreenConfig

	if profile == nil {
		return sc
	}

	if profile.TCP.Land {
		sc.Flags |= ScreenLandAttack
	}
	if profile.TCP.SynFin {
		sc.Flags |= ScreenTCPSynFin
	}
	if profile.TCP.NoFlag {
		sc.Flags |= ScreenTCPNoFlag
	}
	if profile.TCP.FinNoAck {
		sc.Flags |= ScreenTCPFinNoAck
	}
	if profile.TCP.WinNuke {
		sc.Flags |= ScreenWinNuke
	}
	if profile.TCP.SynFrag {
		sc.Flags |= ScreenSynFrag
	}
	if profile.IP.TearDrop {
		sc.Flags |= ScreenTearDrop
	}
	if profile.TCP.SynFlood != nil && profile.TCP.SynFlood.AttackThreshold > 0 {
		sc.Flags |= ScreenSynFlood
		sc.SynFloodThresh = uint32(profile.TCP.SynFlood.AttackThreshold)
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			sc.SynFloodSrcThresh = uint32(profile.TCP.SynFlood.SourceThreshold)
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			sc.SynFloodDstThresh = uint32(profile.TCP.SynFlood.DestinationThreshold)
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			sc.SynFloodTimeout = uint32(profile.TCP.SynFlood.Timeout)
		}
		if synCookie {
			sc.Flags |= ScreenSynCookie
		}
	}
	if profile.ICMP.PingDeath {
		sc.Flags |= ScreenPingOfDeath
	}
	if profile.ICMP.FloodThreshold > 0 {
		sc.Flags |= ScreenICMPFlood
		sc.ICMPFloodThresh = uint32(profile.ICMP.FloodThreshold)
	}
	if profile.IP.SourceRouteOption {
		sc.Flags |= ScreenIPSourceRoute
	}
	if profile.UDP.FloodThreshold > 0 {
		sc.Flags |= ScreenUDPFlood
		sc.UDPFloodThresh = uint32(profile.UDP.FloodThreshold)
	}
	if profile.TCP.PortScanThreshold > 0 {
		sc.Flags |= ScreenPortScan
		sc.PortScanThresh = uint32(profile.TCP.PortScanThreshold)
	}
	if profile.IP.IPSweepThreshold > 0 {
		sc.Flags |= ScreenIPSweep
		sc.IPSweepThresh = uint32(profile.IP.IPSweepThreshold)
	}
	if profile.LimitSession.SourceIPBased > 0 {
		sc.Flags |= ScreenSessionLimitSrc
		sc.SessionLimitSrc = uint32(profile.LimitSession.SourceIPBased)
	}
	if profile.LimitSession.DestinationIPBased > 0 {
		sc.Flags |= ScreenSessionLimitDst
		sc.SessionLimitDst = uint32(profile.LimitSession.DestinationIPBased)
	}

	return sc
}
