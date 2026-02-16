package dataplane

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/networkd"
	"github.com/vishvananda/netlink"
)

// CompileResult holds the result of a config compilation for reference.
type CompileResult struct {
	ZoneIDs     map[string]uint16  // zone name -> zone ID
	ScreenIDs   map[string]uint16  // screen profile name -> profile ID (1-based)
	AddrIDs     map[string]uint32  // address name -> address ID
	AppIDs      map[string]uint32  // application name -> app ID
	PoolIDs     map[string]uint8   // NAT pool name -> pool ID (0-based)
	PolicyNames map[uint32]string  // rule_id -> "from-zone/to-zone/policy-name" (or "global/policy-name")
	PolicySets  int                // number of policy sets created
	FilterIDs  map[string]uint32 // "inet:name" or "inet6:name" -> filter_id

	Lo0FilterV4 uint32 // lo0 inet filter ID (0=none), set by compileFirewallFilters
	Lo0FilterV6 uint32 // lo0 inet6 filter ID (0=none), set by compileFirewallFilters

	nextAddrID       uint32            // next available address ID (after address book)
	implicitSets     map[string]uint32 // cache of implicit set key -> set ID
	nextNATCounterID uint16            // next available NAT rule counter ID (1-based, 0 = no counter)
	NATCounterIDs    map[string]uint16 // "rulesetName/ruleName" -> counter ID

	// pendingXDP/TC collect interface indexes for deferred program attachment.
	// Attachment happens AFTER all compilation phases so that link.Update()
	// atomically switches to programs with fully-populated maps.
	pendingXDP []int
	pendingTC  []int

	// ManagedInterfaces describes all interfaces managed by the firewall,
	// used by the networkd manager to generate .link and .network files.
	ManagedInterfaces []networkd.InterfaceConfig
}

// CompileConfig translates a typed Config into dataplane table entries.
// It works with any DataPlane backend (eBPF or DPDK) via the interface.
// The isRecompile flag triggers FIB generation bump for hitless restarts.
func CompileConfig(dp DataPlane, cfg *config.Config, isRecompile bool) (*CompileResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if !dp.IsLoaded() {
		return nil, fmt.Errorf("dataplane not loaded")
	}

	result := &CompileResult{
		ZoneIDs:          make(map[string]uint16),
		ScreenIDs:        make(map[string]uint16),
		AddrIDs:          make(map[string]uint32),
		AppIDs:           make(map[string]uint32),
		PoolIDs:          make(map[string]uint8),
		implicitSets:     make(map[string]uint32),
		nextNATCounterID: 1, // 0 = no counter
		NATCounterIDs:    make(map[string]uint16),
		Lo0FilterV4:      0xFFFFFFFF, // sentinel: no lo0 filter
		Lo0FilterV6:      0xFFFFFFFF,
	}

	// Phase 1: Assign zone IDs (1-based; 0 = unassigned).
	// Sort names for deterministic IDs across restarts — existing sessions
	// store zone IDs, so changing them breaks session→policy lookups.
	zoneID := uint16(1)
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, name := range zoneNames {
		result.ZoneIDs[name] = zoneID
		zoneID++
	}

	// Phase 1.5: Assign screen profile IDs (1-based; 0 = no profile).
	// Sorted for deterministic IDs.
	screenID := uint16(1)
	screenNames := make([]string, 0, len(cfg.Security.Screen))
	for name := range cfg.Security.Screen {
		screenNames = append(screenNames, name)
	}
	sort.Strings(screenNames)
	for _, name := range screenNames {
		result.ScreenIDs[name] = screenID
		screenID++
	}

	// Phase 2: Compile zones
	if err := compileZones(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile zones: %w", err)
	}

	// Phase 3: Compile address book
	if err := compileAddressBook(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile address book: %w", err)
	}

	// Phase 4: Compile applications
	if err := compileApplications(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile applications: %w", err)
	}

	// Phase 5: Compile policies
	if err := compilePolicies(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile policies: %w", err)
	}

	// Phase 6: Compile NAT
	if err := compileNAT(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile nat: %w", err)
	}

	// Phase 6.5: Compile static NAT
	if err := compileStaticNAT(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile static nat: %w", err)
	}

	// Phase 6.6: Compile NAT64 prefixes
	if err := compileNAT64(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile nat64: %w", err)
	}

	// Phase 7: Compile screen profiles
	if err := compileScreenProfiles(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile screen profiles: %w", err)
	}

	// Phase 8: Compile default policy
	if err := compileDefaultPolicy(dp, cfg); err != nil {
		return nil, fmt.Errorf("compile default policy: %w", err)
	}

	// Phase 9: Compile flow timeouts
	if err := compileFlowTimeouts(dp, cfg); err != nil {
		return nil, fmt.Errorf("compile flow timeouts: %w", err)
	}

	// Phase 10: Compile firewall filters (before flow config so lo0 IDs are available)
	if err := compileFirewallFilters(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile firewall filters: %w", err)
	}

	// Phase 10b: Compile flow config (TCP MSS clamp, lo0 filter IDs, etc.)
	if err := compileFlowConfig(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile flow config: %w", err)
	}

	// Phase 11: Compile port mirroring
	if err := compilePortMirroring(dp, cfg); err != nil {
		return nil, fmt.Errorf("compile port mirroring: %w", err)
	}

	// Bump FIB generation counter on recompile so sessions re-run
	// bpf_fib_lookup with potentially changed interface indices or MAC
	// addresses. BPF checks session.fib_gen != fib_gen_map[0] and
	// treats cached entries as stale — no session write-back needed.
	if isRecompile {
		dp.BumpFIBGeneration()
	}

	slog.Info("config compiled to dataplane",
		"zones", len(result.ZoneIDs),
		"addresses", len(result.AddrIDs),
		"applications", len(result.AppIDs),
		"policy_sets", result.PolicySets)

	return result, nil
}

// Compile translates a typed Config into eBPF map entries and attaches programs.
func (m *Manager) Compile(cfg *config.Config) (*CompileResult, error) {
	result, err := CompileConfig(m, cfg, m.lastCompile != nil)
	if err != nil {
		return nil, err
	}

	// eBPF-specific: attach XDP/TC programs AFTER all maps are populated.
	// link.Update() atomically switches to programs with complete config.
	for _, ifidx := range result.pendingTC {
		if err := m.AttachTC(ifidx); err != nil {
			if !strings.Contains(err.Error(), "already attached") {
				return nil, fmt.Errorf("attach TC to ifindex %d: %w", ifidx, err)
			}
		}
	}

	if len(result.pendingXDP) > 0 {
		rcMap := m.maps["redirect_capable"]

		// Populate redirect_capable BEFORE link.Update() swaps programs.
		if rcMap != nil {
			for _, ifidx := range result.pendingXDP {
				rcMap.Update(uint32(ifidx), uint8(1), ebpf.UpdateAny)
			}
		}

		// Try native XDP first. If any interface lacks native support,
		// ALL must use generic mode for bpf_redirect_map compatibility.
		needGeneric := false
		for _, ifidx := range result.pendingXDP {
			if err := m.AttachXDP(ifidx, false); err != nil {
				if strings.Contains(err.Error(), "already attached") {
					continue
				}
				slog.Info("native XDP not supported, falling back ALL to generic",
					"ifindex", ifidx, "err", err)
				needGeneric = true
				break
			}
		}

		if needGeneric {
			for _, ifidx := range result.pendingXDP {
				m.DetachXDP(ifidx)
			}
			for _, ifidx := range result.pendingXDP {
				if err := m.AttachXDP(ifidx, true); err != nil {
					if !strings.Contains(err.Error(), "already attached") {
						return nil, fmt.Errorf("attach XDP generic to ifindex %d: %w", ifidx, err)
					}
				}
			}
		}
	}

	m.lastCompile = result
	return result, nil
}

// resolveInterfaceRef parses an interface reference like "enp6s0" or "enp6s0.100"
// and returns the physical interface name, unit number, and VLAN ID from config.
func resolveInterfaceRef(ref string, cfg *config.Config) (physName string, configName string, unitNum int, vlanID int) {
	parts := strings.SplitN(ref, ".", 2)
	configName = parts[0]
	physName = config.LinuxIfName(configName)
	if len(parts) == 2 {
		unitNum, _ = strconv.Atoi(parts[1])
	}

	// Look up VLAN ID from interface config (keyed by Junos name)
	if ifCfg, ok := cfg.Interfaces.Interfaces[configName]; ok {
		if unit, ok := ifCfg.Units[unitNum]; ok {
			vlanID = unit.VlanID
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

func compileZones(dp DataPlane,cfg *config.Config, result *CompileResult) error {
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

	// Track which physical interfaces we've already attached to
	attached := make(map[int]bool)
	// Collect physical ifindexes for deferred XDP attachment
	var xdpIfindexes []int

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

			// Get the physical interface
			physIface, err := net.InterfaceByName(physName)
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
				// DHCP-managed sub-interfaces are skipped.
				subName := fmt.Sprintf("%s.%d", physName, vlanID)
				var addrs []string
				isDHCPSub := false
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
					if unit, ok := ifCfg.Units[unitNum]; ok {
						addrs = unit.Addresses
						isDHCPSub = unit.DHCP || unit.DHCPv6
					}
				}
				if !isDHCPSub {
					reconcileInterfaceAddresses(subName, addrs)
				}

				// Apply unit-level MTU to VLAN sub-interface
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
					if unit, ok := ifCfg.Units[unitNum]; ok && unit.MTU > 0 {
						if nl, err := netlink.LinkByName(subName); err == nil {
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
			}

			// Set zone mapping using composite key {physIfindex, vlanID}
			tableID := ifaceTableID[ifaceRef] // 0 if not in any routing instance
			if err := dp.SetZone(physIface.Index, uint16(vlanID), zid, tableID); err != nil {
				return fmt.Errorf("set zone for %s vlan %d (ifindex %d): %w",
					physName, vlanID, physIface.Index, err)
			}
			writtenIfaceZone[IfaceZoneKey{Ifindex: uint32(physIface.Index), VlanID: uint16(vlanID)}] = true

			// Add physical interface to tx_ports and attach TC (once per phys iface).
			// XDP attachment is deferred to after the loop so we can ensure
			// all interfaces use the same XDP mode (native vs generic).
			if !attached[physIface.Index] {
				if err := dp.AddTxPort(physIface.Index); err != nil {
					return fmt.Errorf("add tx port %s: %w", physName, err)
				}

				// Disable VLAN RX offload so XDP sees VLAN tags in packet data
				// (otherwise NIC strips them into skb->vlan_tci which XDP can't read)
				if out, err := exec.Command("ethtool", "-K", physName, "rxvlan", "off").CombinedOutput(); err != nil {
					slog.Warn("failed to disable rxvlan offload (VLAN parsing may fail)",
						"interface", physName, "err", err, "output", strings.TrimSpace(string(out)))
				} else {
					slog.Info("disabled VLAN RX offload for XDP", "interface", physName)
				}

				// Apply interface-level MTU from config
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok && ifCfg.MTU > 0 {
					if nl, err := netlink.LinkByIndex(physIface.Index); err == nil {
						if nl.Attrs().MTU != ifCfg.MTU {
							if err := netlink.LinkSetMTU(nl, ifCfg.MTU); err != nil {
								slog.Warn("failed to set MTU",
									"name", physName, "mtu", ifCfg.MTU, "err", err)
							} else {
								slog.Info("set interface MTU", "name", physName, "mtu", ifCfg.MTU)
							}
						}
					}
				}

				// Apply interface speed/duplex via ethtool if configured
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
					applyEthtool(physName, ifCfg)
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
					if nl, err := netlink.LinkByIndex(physIface.Index); err == nil {
						if err := netlink.LinkSetDown(nl); err != nil {
							slog.Warn("failed to bring disabled interface down",
								"name", physName, "err", err)
						} else {
							slog.Info("interface administratively disabled", "name", physName)
						}
					}
				} else if nl, err := netlink.LinkByIndex(physIface.Index); err == nil {
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
					xdpIfindexes = append(xdpIfindexes, physIface.Index)
					result.pendingTC = append(result.pendingTC, physIface.Index)
				}
				attached[physIface.Index] = true
			}

			// Reconcile addresses for non-VLAN, non-DHCP interfaces (removes stale, adds missing).
			// DHCP-managed interfaces are skipped — the DHCP client manages their addresses.
			if vlanID == 0 {
				var addrs []string
				isDHCP := false
				var unitMTU int
				if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok {
					if unit, ok := ifCfg.Units[unitNum]; ok {
						addrs = unit.Addresses
						isDHCP = unit.DHCP || unit.DHCPv6
						unitMTU = unit.MTU
					}
				}
				if !isDHCP {
					reconcileInterfaceAddresses(physName, addrs)
				}
				// Apply unit-level MTU (overrides interface-level MTU)
				if unitMTU > 0 {
					if nl, err := netlink.LinkByName(physName); err == nil {
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

	// Store pending XDP ifindexes for deferred attachment after all compile phases.
	result.pendingXDP = xdpIfindexes

	// Collect managed interface info for networkd config generation.
	// Iterate over configured interfaces (not zones) to get a clean
	// per-interface view including VLAN parent and sub-interface entries.
	//
	// For RETH interfaces with a redundancy group, VIP addresses are managed
	// by keepalived (VRRP). The networkd .network file gets a link-local base
	// address (169.254.RG.NODE/32) instead — keepalived requires at least one
	// IPv4 on the interface for VRRP advertisements. Putting the VIP in both
	// networkd AND keepalived causes conflicts: keepalived removes the address
	// when entering FAULT/BACKUP state.
	clusterNodeID := -1
	if cfg.Chassis.Cluster != nil {
		clusterNodeID = cfg.Chassis.Cluster.NodeID
	}
	seen := make(map[string]bool)
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		linuxName := config.LinuxIfName(ifName)
		physIface, err := net.InterfaceByName(linuxName)
		if err != nil {
			continue
		}
		mac := physIface.HardwareAddr.String()
		if mac == "" {
			continue
		}

		// isVRRPReth: true when keepalived manages this interface's VIPs.
		isVRRPReth := ifCfg.RedundancyGroup > 0 && clusterNodeID >= 0

		if ifCfg.VlanTagging {
			// VLAN parent: no addresses, just rename
			if !seen[linuxName] {
				seen[linuxName] = true
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:         linuxName,
					MACAddress:   mac,
					IsVLANParent: true,
					Disable:      ifCfg.Disable,
					Speed:        ifCfg.Speed,
					Duplex:       ifCfg.Duplex,
					MTU:          ifCfg.MTU,
					Description:  ifCfg.Description,
				})
			}
			// VLAN sub-interfaces get their own .network file
			for _, unit := range ifCfg.Units {
				if unit.VlanID > 0 {
					subName := fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					if !seen[subName] {
						seen[subName] = true
						addrs := unit.Addresses
						if isVRRPReth {
							// Replace VIP addresses with a link-local base for VRRP.
							addrs = []string{fmt.Sprintf("169.254.%d.%d/32", ifCfg.RedundancyGroup, clusterNodeID+1)}
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
						})
					}
				}
			}
		} else {
			// Regular interface (non-VLAN)
			if !seen[linuxName] {
				seen[linuxName] = true
				// Collect addresses from all units
				var addrs []string
				var dhcpv4, dhcpv6, dadDisable bool
				var primaryAddr, preferredAddr string
				unitMTU := 0
				for _, unit := range ifCfg.Units {
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
				// RETH with redundancy group: replace VIP addresses with a
				// link-local base; keepalived manages the actual VIPs.
				if isVRRPReth {
					addrs = []string{fmt.Sprintf("169.254.%d.%d/32", ifCfg.RedundancyGroup, clusterNodeID+1)}
					primaryAddr = ""
					preferredAddr = ""
				}
				// RETH members: set BondMaster so networkd keeps them enslaved
				// after reload/reconfigure.
				var bondMaster string
				if ifCfg.RedundantParent != "" {
					bondMaster = config.LinuxIfName(ifCfg.RedundantParent)
				}
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:             linuxName,
					MACAddress:       mac,
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
					BondMaster:       bondMaster,
				})
			}
		}
	}

	// Discover all system interfaces and mark unconfigured ones as unmanaged.
	// Unmanaged interfaces are brought down and have addresses removed to
	// prevent traffic leaking through unconfigured paths.
	//
	// Skip interfaces created by the daemon itself (VRFs, tunnels).
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
		if len(ifc.FabricMembers) > 0 {
			daemonOwned[name] = true
		}
		// RETH bond devices are created by the daemon
		if strings.HasPrefix(name, "reth") {
			daemonOwned[name] = true
		}
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
		nl, err := netlink.LinkByIndex(iface.Index)
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

func compileAddressBook(dp DataPlane,cfg *config.Config, result *CompileResult) error {
	// Clear stale address book entries before repopulating.
	if err := dp.ClearAddressBookV4(); err != nil {
		return fmt.Errorf("clear address_book_v4: %w", err)
	}
	if err := dp.ClearAddressBookV6(); err != nil {
		return fmt.Errorf("clear address_book_v6: %w", err)
	}
	if err := dp.ClearAddressMembership(); err != nil {
		return fmt.Errorf("clear address_membership: %w", err)
	}

	ab := cfg.Security.AddressBook
	if ab == nil {
		result.nextAddrID = 1 // start from 1 for implicit entries
		return nil
	}

	// Assign address IDs (1-based; 0 = "any")
	addrID := uint32(1)

	// Process individual addresses (sorted for deterministic IDs across restarts)
	addrNames := make([]string, 0, len(ab.Addresses))
	for name := range ab.Addresses {
		addrNames = append(addrNames, name)
	}
	sort.Strings(addrNames)
	for _, name := range addrNames {
		addr := ab.Addresses[name]
		result.AddrIDs[name] = addrID

		cidr := addr.Value
		// Ensure CIDR notation
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr = cidr + "/128" // IPv6
			} else {
				cidr = cidr + "/32" // IPv4
			}
		}

		if err := dp.SetAddressBookEntry(cidr, addrID); err != nil {
			return fmt.Errorf("set address %s (%s): %w", name, cidr, err)
		}

		// Write self-membership: (addrID, addrID) -> 1
		if err := dp.SetAddressMembership(addrID, addrID); err != nil {
			return fmt.Errorf("set self-membership for %s: %w", name, err)
		}

		slog.Debug("address compiled", "name", name, "cidr", cidr, "id", addrID)
		addrID++
	}

	// Process address sets (sorted for deterministic IDs)
	setNames := make([]string, 0, len(ab.AddressSets))
	for name := range ab.AddressSets {
		setNames = append(setNames, name)
	}
	sort.Strings(setNames)
	for _, setName := range setNames {
		setID := addrID
		result.AddrIDs[setName] = setID
		addrID++

		// Recursively expand nested sets to flat address list
		allAddresses, err := config.ExpandAddressSet(setName, ab)
		if err != nil {
			return fmt.Errorf("address set %q: %w", setName, err)
		}

		// Write membership entries for each resolved address
		for _, memberName := range allAddresses {
			memberID, ok := result.AddrIDs[memberName]
			if !ok {
				return fmt.Errorf("address set %q: member %q not found",
					setName, memberName)
			}
			if err := dp.SetAddressMembership(memberID, setID); err != nil {
				return fmt.Errorf("set membership %s in %s: %w",
					memberName, setName, err)
			}
		}

		slog.Debug("address set compiled", "name", setName, "id", setID,
			"members", len(allAddresses))
	}

	result.nextAddrID = addrID
	return nil
}

func compileApplications(dp DataPlane,cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenApps := make(map[AppKey]bool)

	appID := uint32(1)
	userApps := cfg.Applications.Applications

	// Collect all referenced application names from policies,
	// expanding application-sets to individual apps.
	referenced := make(map[string]bool)
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			for _, appName := range pol.Match.Applications {
				if appName == "any" {
					continue
				}
				// Check if it's an application-set
				if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
					expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
					if err != nil {
						return fmt.Errorf("expand application-set %q: %w", appName, err)
					}
					for _, a := range expanded {
						referenced[a] = true
					}
				} else {
					referenced[appName] = true
				}
			}
		}
	}

	// Sort for deterministic app IDs across restarts.
	refNames := make([]string, 0, len(referenced))
	for name := range referenced {
		refNames = append(refNames, name)
	}
	sort.Strings(refNames)
	for _, appName := range refNames {
		app, found := config.ResolveApplication(appName, userApps)
		if !found {
			return fmt.Errorf("application %q not found", appName)
		}

		proto := protocolNumber(app.Protocol)

		result.AppIDs[appName] = appID

		// Parse destination port (may be a range like "8080-8090")
		ports, err := parsePorts(app.DestinationPort)
		if err != nil {
			slog.Warn("bad port for application",
				"name", appName, "port", app.DestinationPort, "err", err)
			continue
		}

		// Parse source port range (stored in BPF app_value, not expanded)
		var srcLow, srcHigh uint16
		if app.SourcePort != "" {
			srcLow, srcHigh, err = parsePortRange(app.SourcePort)
			if err != nil {
				slog.Warn("bad source-port for application",
					"name", appName, "port", app.SourcePort, "err", err)
			}
		}

		var appTimeout uint32
		if app.InactivityTimeout > 0 {
			appTimeout = uint32(app.InactivityTimeout)
		}

		algType := algTypeFromString(app.ALG)

		// When no protocol is specified, install entries for both TCP and UDP
		// (matching Junos behavior where omitted protocol means any L4).
		protos := []uint8{proto}
		if proto == 0 && app.Protocol != "icmp" {
			protos = []uint8{6, 17} // TCP + UDP
		}

		for _, p := range protos {
			for _, port := range ports {
				if err := dp.SetApplication(p, port, appID, appTimeout, algType, srcLow, srcHigh); err != nil {
					return fmt.Errorf("set application %s port %d: %w",
						appName, port, err)
				}
				writtenApps[AppKey{Protocol: p, DstPort: htons(port)}] = true
			}
		}

		slog.Debug("application compiled", "name", appName, "id", appID,
			"proto", proto, "ports", ports, "srcPort", app.SourcePort, "timeout", appTimeout)
		appID++
	}

	// Delete stale application entries no longer referenced.
	dp.DeleteStaleApplications(writtenApps)

	return nil
}

// resolveAddrList resolves a list of address names to a single address ID.
// If the list has one entry, returns that entry's ID directly.
// If the list has multiple entries, creates an implicit address-set containing
// all referenced addresses and returns the set's ID.
func resolveAddrList(dp DataPlane,names []string, result *CompileResult) (uint32, error) {
	if len(names) == 0 {
		return 0, nil
	}

	// Filter out "any" entries
	var filtered []string
	for _, n := range names {
		if n != "any" {
			filtered = append(filtered, n)
		}
	}
	if len(filtered) == 0 {
		return 0, nil // all "any"
	}

	// Single address: return its ID directly
	if len(filtered) == 1 {
		id, ok := result.AddrIDs[filtered[0]]
		if !ok {
			return 0, fmt.Errorf("address %q not found", filtered[0])
		}
		return id, nil
	}

	// Multiple addresses: build implicit address-set
	sorted := make([]string, len(filtered))
	copy(sorted, filtered)
	sort.Strings(sorted)
	cacheKey := strings.Join(sorted, ",")

	if setID, ok := result.implicitSets[cacheKey]; ok {
		return setID, nil
	}

	setID := result.nextAddrID
	result.nextAddrID++

	for _, name := range sorted {
		memberID, ok := result.AddrIDs[name]
		if !ok {
			return 0, fmt.Errorf("address %q not found", name)
		}
		if err := dp.SetAddressMembership(memberID, setID); err != nil {
			return 0, fmt.Errorf("set implicit membership %s in set %d: %w", name, setID, err)
		}
	}

	result.implicitSets[cacheKey] = setID
	slog.Debug("implicit address-set created", "id", setID, "members", sorted)
	return setID, nil
}

// resolveSNATMatchAddr resolves a SNAT match CIDR to an address ID.
// If the CIDR already exists as an address-book entry, reuses that ID.
// Otherwise, creates an implicit address-book entry with a synthetic name.
// Returns 0 (any) if the CIDR is empty.
func resolveSNATMatchAddr(dp DataPlane,cidr string, result *CompileResult) (uint32, error) {
	if cidr == "" {
		return 0, nil
	}

	// Normalize CIDR
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}

	// Create implicit address-book entry (LPM trie handles deduplication)
	synthName := "_snat_match_" + cidr
	if id, ok := result.AddrIDs[synthName]; ok {
		return id, nil
	}

	addrID := result.nextAddrID
	result.nextAddrID++
	result.AddrIDs[synthName] = addrID

	if err := dp.SetAddressBookEntry(cidr, addrID); err != nil {
		return 0, fmt.Errorf("set implicit address %s: %w", cidr, err)
	}
	if err := dp.SetAddressMembership(addrID, addrID); err != nil {
		return 0, fmt.Errorf("set self-membership for implicit %s: %w", cidr, err)
	}

	slog.Debug("implicit SNAT match address created", "cidr", cidr, "id", addrID)
	return addrID, nil
}

func compilePolicies(dp DataPlane,cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenPolicySets := make(map[ZonePairKey]bool)
	result.PolicyNames = make(map[uint32]string)

	policySetID := uint32(0)

	for _, zpp := range cfg.Security.Policies {
		fromZone, ok := result.ZoneIDs[zpp.FromZone]
		if !ok {
			return fmt.Errorf("policy from-zone %q not found", zpp.FromZone)
		}
		toZone, ok := result.ZoneIDs[zpp.ToZone]
		if !ok {
			return fmt.Errorf("policy to-zone %q not found", zpp.ToZone)
		}

		// Expand rules: each config rule with N applications becomes N BPF rules.
		// Collect expanded rules first to know the total count.
		type expandedRule struct {
			pol    *config.Policy
			appID  uint32
		}
		var expanded []expandedRule

		for _, pol := range zpp.Policies {
			// Resolve application list, expanding application-sets
			var appIDs []uint32
			hasAny := false
			for _, appName := range pol.Match.Applications {
				if appName == "any" {
					hasAny = true
					break
				}
			}
			if hasAny || len(pol.Match.Applications) == 0 {
				appIDs = []uint32{0} // single rule with app_id=0 (any)
			} else {
				seen := make(map[uint32]bool)
				for _, appName := range pol.Match.Applications {
					// Expand application-sets
					if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
						expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
						if err != nil {
							return fmt.Errorf("policy %s expand app-set %q: %w", pol.Name, appName, err)
						}
						for _, a := range expanded {
							if id, ok := result.AppIDs[a]; ok && !seen[id] {
								seen[id] = true
								appIDs = append(appIDs, id)
							}
						}
					} else if id, ok := result.AppIDs[appName]; ok && !seen[id] {
						seen[id] = true
						appIDs = append(appIDs, id)
					}
				}
				if len(appIDs) == 0 {
					appIDs = []uint32{0}
				}
			}

			for _, aid := range appIDs {
				expanded = append(expanded, expandedRule{pol: pol, appID: aid})
			}
		}

		ps := PolicySet{
			PolicySetID:   policySetID,
			NumRules:      uint16(len(expanded)),
			DefaultAction: ActionDeny,
		}
		zpKey := ZonePairKey{FromZone: fromZone, ToZone: toZone}
		if err := dp.SetZonePairPolicy(fromZone, toZone, ps); err != nil {
			return fmt.Errorf("set zone pair policy %s->%s: %w",
				zpp.FromZone, zpp.ToZone, err)
		}
		writtenPolicySets[zpKey] = true

		for i, er := range expanded {
			pol := er.pol
			rule := PolicyRule{
				RuleID:      uint32(policySetID*MaxRulesPerPolicy + uint32(i)),
				PolicySetID: policySetID,
				Sequence:    uint16(i),
				AppID:       er.appID,
				Active:      1, // default active; scheduler may toggle to 0
			}

			// Map action
			switch pol.Action {
			case config.PolicyPermit:
				rule.Action = ActionPermit
			case config.PolicyDeny:
				rule.Action = ActionDeny
			case config.PolicyReject:
				rule.Action = ActionReject
			}

			// Logging
			if pol.Log != nil {
				if pol.Log.SessionInit {
					rule.Log |= LogFlagSessionInit
				}
				if pol.Log.SessionClose {
					rule.Log |= LogFlagSessionClose
				}
			}

			// Source address (supports multiple via implicit address-set)
			srcID, err := resolveAddrList(dp,pol.Match.SourceAddresses, result)
			if err != nil {
				return fmt.Errorf("policy %s source address: %w", pol.Name, err)
			}
			rule.SrcAddrID = srcID

			// Destination address (supports multiple via implicit address-set)
			dstID, err := resolveAddrList(dp,pol.Match.DestinationAddresses, result)
			if err != nil {
				return fmt.Errorf("policy %s destination address: %w", pol.Name, err)
			}
			rule.DstAddrID = dstID

			if err := dp.SetPolicyRule(policySetID, uint32(i), rule); err != nil {
				return fmt.Errorf("set policy rule %s[%d]: %w",
					pol.Name, i, err)
			}

			result.PolicyNames[rule.RuleID] = pol.Name

			slog.Debug("policy rule compiled",
				"from", zpp.FromZone, "to", zpp.ToZone,
				"policy", pol.Name, "action", rule.Action,
				"index", i, "app_id", er.appID)
		}

		result.PolicySets++
		policySetID++
	}

	// Global policies (apply to all zone pairs, evaluated as fallback).
	// Uses special key {0, 0} which BPF checks when no zone-pair-specific match.
	if len(cfg.Security.GlobalPolicies) > 0 {
		type expandedRule struct {
			pol   *config.Policy
			appID uint32
		}
		var expanded []expandedRule

		for _, pol := range cfg.Security.GlobalPolicies {
			var appIDs []uint32
			hasAny := false
			for _, appName := range pol.Match.Applications {
				if appName == "any" {
					hasAny = true
					break
				}
			}
			if hasAny || len(pol.Match.Applications) == 0 {
				appIDs = []uint32{0}
			} else {
				seen := make(map[uint32]bool)
				for _, appName := range pol.Match.Applications {
					if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
						exp, err := config.ExpandApplicationSet(appName, &cfg.Applications)
						if err != nil {
							return fmt.Errorf("global policy expand app-set %q: %w", appName, err)
						}
						for _, a := range exp {
							if id, ok := result.AppIDs[a]; ok && !seen[id] {
								seen[id] = true
								appIDs = append(appIDs, id)
							}
						}
					} else if id, ok := result.AppIDs[appName]; ok && !seen[id] {
						seen[id] = true
						appIDs = append(appIDs, id)
					}
				}
				if len(appIDs) == 0 {
					appIDs = []uint32{0}
				}
			}

			for _, aid := range appIDs {
				expanded = append(expanded, expandedRule{pol: pol, appID: aid})
			}
		}

		ps := PolicySet{
			PolicySetID:   policySetID,
			NumRules:      uint16(len(expanded)),
			DefaultAction: ActionDeny,
		}
		// Global policy key: from_zone=0, to_zone=0
		if err := dp.SetZonePairPolicy(0, 0, ps); err != nil {
			return fmt.Errorf("set global policy: %w", err)
		}
		writtenPolicySets[ZonePairKey{FromZone: 0, ToZone: 0}] = true

		for i, er := range expanded {
			pol := er.pol
			rule := PolicyRule{
				RuleID:      uint32(policySetID*MaxRulesPerPolicy + uint32(i)),
				PolicySetID: policySetID,
				Sequence:    uint16(i),
				AppID:       er.appID,
				Active:      1,
			}

			switch pol.Action {
			case config.PolicyPermit:
				rule.Action = ActionPermit
			case config.PolicyDeny:
				rule.Action = ActionDeny
			case config.PolicyReject:
				rule.Action = ActionReject
			}

			if pol.Log != nil {
				if pol.Log.SessionInit {
					rule.Log |= LogFlagSessionInit
				}
				if pol.Log.SessionClose {
					rule.Log |= LogFlagSessionClose
				}
			}

			srcID, err := resolveAddrList(dp,pol.Match.SourceAddresses, result)
			if err != nil {
				return fmt.Errorf("global policy %s source address: %w", pol.Name, err)
			}
			rule.SrcAddrID = srcID

			dstID, err := resolveAddrList(dp,pol.Match.DestinationAddresses, result)
			if err != nil {
				return fmt.Errorf("global policy %s destination address: %w", pol.Name, err)
			}
			rule.DstAddrID = dstID

			if err := dp.SetPolicyRule(policySetID, uint32(i), rule); err != nil {
				return fmt.Errorf("set global policy rule %s[%d]: %w", pol.Name, i, err)
			}

			result.PolicyNames[rule.RuleID] = pol.Name

			slog.Debug("global policy rule compiled",
				"policy", pol.Name, "action", rule.Action,
				"index", i, "app_id", er.appID)
		}

		result.PolicySets++
		policySetID++
	}

	// Delete stale zone-pair policy entries no longer in the config.
	dp.DeleteStaleZonePairPolicies(writtenPolicySets)

	return nil
}

func compileNAT(dp DataPlane,cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenSNAT := make(map[SNATKey]bool)
	writtenSNATv6 := make(map[SNATKey]bool)
	writtenDNAT := make(map[DNATKey]bool)
	writtenDNATv6 := make(map[DNATKeyV6]bool)

	// Clear stale persistent NAT pool configs before recompilation
	if pnat := dp.GetPersistentNAT(); pnat != nil {
		pnat.ClearPoolConfigs()
	}

	natCfg := &cfg.Security.NAT

	// Source NAT: allocate pool IDs and compile pools + rules
	poolID := uint8(0)

	// Track per-zone-pair v4/v6 rule indices for multiple SNAT rules
	type zonePairIdx struct{ from, to uint16 }
	v4RuleIdx := make(map[zonePairIdx]uint16)
	v6RuleIdx := make(map[zonePairIdx]uint16)

	for _, rs := range natCfg.Source {
		fromZone, ok := result.ZoneIDs[rs.FromZone]
		if !ok {
			return fmt.Errorf("source NAT from-zone %q not found", rs.FromZone)
		}
		toZone, ok := result.ZoneIDs[rs.ToZone]
		if !ok {
			return fmt.Errorf("source NAT to-zone %q not found", rs.ToZone)
		}

		for _, rule := range rs.Rules {
			if !rule.Then.Interface && rule.Then.PoolName == "" && !rule.Then.Off {
				slog.Warn("SNAT rule has no action",
					"rule", rule.Name, "rule-set", rs.Name)
				continue
			}

			// source-nat off: write exemption rule (no pool allocation)
			if rule.Then.Off {
				// Resolve source addresses (supports bracket lists)
				srcAddrs := rule.Match.SourceAddresses
				if len(srcAddrs) == 0 {
					srcAddrs = []string{rule.Match.SourceAddress}
				}

				// Resolve destination addresses (supports bracket lists)
				dstAddrs := rule.Match.DestinationAddresses
				if len(dstAddrs) == 0 {
					dstAddrs = []string{rule.Match.DestinationAddress}
				}

				zp := zonePairIdx{fromZone, toZone}
				ruleKey := rs.Name + "/" + rule.Name
				counterID := result.nextNATCounterID
				result.NATCounterIDs[ruleKey] = counterID
				result.nextNATCounterID++

				for _, srcAddr := range srcAddrs {
					srcAddrID, err := resolveSNATMatchAddr(dp, srcAddr, result)
					if err != nil {
						return fmt.Errorf("snat rule %s/%s source match %q: %w",
							rs.Name, rule.Name, srcAddr, err)
					}
					for _, dstAddr := range dstAddrs {
						dstAddrID, err := resolveSNATMatchAddr(dp, dstAddr, result)
						if err != nil {
							return fmt.Errorf("snat rule %s/%s dest match %q: %w",
								rs.Name, rule.Name, dstAddr, err)
						}

						// Write v4 rule
						val := SNATValue{
							Mode:      SNATModeOff,
							SrcAddrID: srcAddrID,
							DstAddrID: dstAddrID,
							CounterID: counterID,
						}
						ri := v4RuleIdx[zp]
						if err := dp.SetSNATRule(fromZone, toZone, ri, val); err != nil {
							return fmt.Errorf("set snat off rule %s/%s: %w",
								rs.Name, rule.Name, err)
						}
						writtenSNAT[SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ri}] = true
						v4RuleIdx[zp] = ri + 1

						// Write v6 rule
						val6 := SNATValueV6{
							Mode:      SNATModeOff,
							SrcAddrID: srcAddrID,
							DstAddrID: dstAddrID,
							CounterID: counterID,
						}
						ri6 := v6RuleIdx[zp]
						if err := dp.SetSNATRuleV6(fromZone, toZone, ri6, val6); err != nil {
							return fmt.Errorf("set snat_v6 off rule %s/%s: %w",
								rs.Name, rule.Name, err)
						}
						writtenSNATv6[SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ri6}] = true
						v6RuleIdx[zp] = ri6 + 1

						slog.Info("source NAT off rule compiled",
							"rule-set", rs.Name, "rule", rule.Name,
							"from", rs.FromZone, "to", rs.ToZone,
							"counter_id", counterID,
							"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
							"src_addr", srcAddr, "dst_addr", dstAddr)
					}
				}
				continue
			}

			var curPoolID uint8
			var poolCfg NATPoolConfig
			var v4IPs []net.IP
			var v6IPs []net.IP

			if rule.Then.Interface {
				// Interface mode: create implicit pool from egress interface IP(s)
				toZoneCfg, ok := cfg.Security.Zones[rs.ToZone]
				if !ok || len(toZoneCfg.Interfaces) == 0 {
					slog.Warn("to-zone has no interfaces",
						"zone", rs.ToZone, "rule-set", rs.Name)
					continue
				}
				ifaceName := toZoneCfg.Interfaces[0]

				// RETH interfaces backed by VRRP: read addresses from config
				// instead of live interface query (VIPs may not be on this node).
				if ifCfg, ok := cfg.Interfaces.Interfaces[ifaceName]; ok && ifCfg.RedundancyGroup > 0 {
					v4IPs, v6IPs = rethConfigAddrs(ifCfg)
				} else {
					snatIP, err := getInterfaceIP(ifaceName)
					if err != nil {
						slog.Warn("cannot get interface IPv4 for SNAT",
							"interface", ifaceName, "err", err)
					} else {
						v4IPs = append(v4IPs, snatIP)
					}

					snatIPv6, err := getInterfaceIPv6(ifaceName)
					if err != nil {
						slog.Debug("no IPv6 address for SNAT",
							"interface", ifaceName, "err", err)
					} else {
						v6IPs = append(v6IPs, snatIPv6)
					}
				}

				if len(v4IPs) == 0 && len(v6IPs) == 0 {
					slog.Warn("no IP addresses for interface SNAT",
						"interface", ifaceName)
					continue
				}

				poolCfg.PortLow = 1024
				poolCfg.PortHigh = 65535
				curPoolID = poolID
				poolID++
			} else {
				// Pool mode: look up named pool
				pool, ok := natCfg.SourcePools[rule.Then.PoolName]
				if !ok {
					return fmt.Errorf("source NAT pool %q not found (rule %q)",
						rule.Then.PoolName, rule.Name)
				}

				// Check if pool already has an ID assigned
				if existingID, exists := result.PoolIDs[pool.Name]; exists {
					curPoolID = existingID
				} else {
					curPoolID = poolID
					result.PoolIDs[pool.Name] = curPoolID
					poolID++
				}

				// Parse pool addresses
				for _, addr := range pool.Addresses {
					cidr := addr
					if !strings.Contains(cidr, "/") {
						if strings.Contains(cidr, ":") {
							cidr += "/128"
						} else {
							cidr += "/32"
						}
					}
					ip, _, err := net.ParseCIDR(cidr)
					if err != nil {
						slog.Warn("invalid pool address", "addr", addr, "err", err)
						continue
					}
					if ip.To4() != nil {
						v4IPs = append(v4IPs, ip.To4())
					} else {
						v6IPs = append(v6IPs, ip)
					}
				}

				poolCfg.PortLow = uint16(pool.PortLow)
				poolCfg.PortHigh = uint16(pool.PortHigh)
				if poolCfg.PortLow == 0 {
					poolCfg.PortLow = 1024
				}
				if poolCfg.PortHigh == 0 {
					poolCfg.PortHigh = 65535
				}
			}

			// Write pool IPs to maps
			poolCfg.NumIPs = uint16(len(v4IPs))
			poolCfg.NumIPsV6 = uint16(len(v6IPs))

			for i, ip := range v4IPs {
				if i >= int(MaxNATPoolIPsPerPool) {
					break
				}
				if err := dp.SetNATPoolIPV4(uint32(curPoolID), uint32(i), ipToUint32BE(ip)); err != nil {
					return fmt.Errorf("set pool ip v4 %d/%d: %w", curPoolID, i, err)
				}
			}
			for i, ip := range v6IPs {
				if i >= int(MaxNATPoolIPsPerPool) {
					break
				}
				if err := dp.SetNATPoolIPV6(uint32(curPoolID), uint32(i), ipTo16Bytes(ip)); err != nil {
					return fmt.Errorf("set pool ip v6 %d/%d: %w", curPoolID, i, err)
				}
			}

			if natCfg.AddressPersistent {
				poolCfg.AddrPersistent = 1
			}

			if err := dp.SetNATPoolConfig(uint32(curPoolID), poolCfg); err != nil {
				return fmt.Errorf("set pool config %d: %w", curPoolID, err)
			}

			// Register persistent NAT pool config and IPs on the persistent NAT table
			if !rule.Then.Interface {
				pool := natCfg.SourcePools[rule.Then.PoolName]
				if pool.PersistentNAT != nil {
					pnat := dp.GetPersistentNAT()
					if pnat != nil {
						timeout := time.Duration(pool.PersistentNAT.InactivityTimeout) * time.Second
						if timeout == 0 {
							timeout = 300 * time.Second
						}
						pnat.SetPoolConfig(pool.Name, PersistentNATPoolInfo{
							Timeout:             timeout,
							PermitAnyRemoteHost: pool.PersistentNAT.PermitAnyRemoteHost,
						})
						for _, ip := range v4IPs {
							addr, ok := netip.AddrFromSlice(ip.To4())
							if ok {
								pnat.RegisterNATIP(addr, pool.Name)
							}
						}
						for _, ip := range v6IPs {
							addr, ok := netip.AddrFromSlice(ip.To16())
							if ok {
								pnat.RegisterNATIP(addr, pool.Name)
							}
						}
						slog.Info("persistent NAT pool registered",
							"pool", pool.Name,
							"timeout", timeout,
							"permit_any_remote_host", pool.PersistentNAT.PermitAnyRemoteHost)
					}
				}
			}

			// Resolve SNAT match addresses (supports bracket lists).
			// Creates one BPF rule per (src, dst) address pair (Cartesian product).
			srcAddrs := rule.Match.SourceAddresses
			if len(srcAddrs) == 0 {
				srcAddrs = []string{rule.Match.SourceAddress}
			}
			dstAddrs := rule.Match.DestinationAddresses
			if len(dstAddrs) == 0 {
				dstAddrs = []string{rule.Match.DestinationAddress}
			}

			zp := zonePairIdx{fromZone, toZone}

			// Assign NAT rule counter ID (shared across expanded address pairs)
			ruleKey := rs.Name + "/" + rule.Name
			counterID := result.nextNATCounterID
			result.NATCounterIDs[ruleKey] = counterID
			result.nextNATCounterID++

			for _, srcAddr := range srcAddrs {
				srcAddrID, err := resolveSNATMatchAddr(dp, srcAddr, result)
				if err != nil {
					return fmt.Errorf("snat rule %s/%s source match %q: %w",
						rs.Name, rule.Name, srcAddr, err)
				}
				for _, dstAddr := range dstAddrs {
					dstAddrID, err := resolveSNATMatchAddr(dp, dstAddr, result)
					if err != nil {
						return fmt.Errorf("snat rule %s/%s dest match %q: %w",
							rs.Name, rule.Name, dstAddr, err)
					}

				// Write SNAT rule (v4)
				if len(v4IPs) > 0 {
					val := SNATValue{
						Mode:      curPoolID,
						SrcAddrID: srcAddrID,
						DstAddrID: dstAddrID,
						CounterID: counterID,
					}
					ri := v4RuleIdx[zp]
					if err := dp.SetSNATRule(fromZone, toZone, ri, val); err != nil {
						return fmt.Errorf("set snat rule %s/%s: %w",
							rs.Name, rule.Name, err)
					}
					writtenSNAT[SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ri}] = true
					v4RuleIdx[zp] = ri + 1
					slog.Info("source NAT rule compiled",
						"rule-set", rs.Name, "rule", rule.Name,
						"from", rs.FromZone, "to", rs.ToZone,
						"pool_id", curPoolID, "rule_idx", ri,
						"counter_id", counterID,
						"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
						"src_addr", srcAddr, "dst_addr", dstAddr,
						"v4_ips", len(v4IPs),
						"ports", fmt.Sprintf("%d-%d", poolCfg.PortLow, poolCfg.PortHigh))
				}

				// Write SNAT rule (v6)
				if len(v6IPs) > 0 {
					val := SNATValueV6{
						Mode:      curPoolID,
						SrcAddrID: srcAddrID,
						DstAddrID: dstAddrID,
						CounterID: counterID,
					}
					ri := v6RuleIdx[zp]
					if err := dp.SetSNATRuleV6(fromZone, toZone, ri, val); err != nil {
						return fmt.Errorf("set snat_v6 rule %s/%s: %w",
							rs.Name, rule.Name, err)
					}
					writtenSNATv6[SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ri}] = true
					v6RuleIdx[zp] = ri + 1
					slog.Info("source NAT v6 rule compiled",
						"rule-set", rs.Name, "rule", rule.Name,
						"from", rs.FromZone, "to", rs.ToZone,
						"pool_id", curPoolID, "rule_idx", ri,
						"counter_id", counterID,
						"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
						"src_addr", srcAddr, "dst_addr", dstAddr,
						"v6_ips", len(v6IPs))
				}
				} // end dstAddr loop
			} // end srcAddr loop
		}
	}

	// Destination NAT
	if natCfg.Destination != nil {
		for _, rs := range natCfg.Destination.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == "" {
					continue
				}

				pool, ok := natCfg.Destination.Pools[rule.Then.PoolName]
				if !ok {
					return fmt.Errorf("DNAT pool %q not found (rule %q)",
						rule.Then.PoolName, rule.Name)
				}

				// Validate source-address-name if present (config compatibility)
				if rule.Match.SourceAddressName != "" {
					if _, ok := result.AddrIDs[rule.Match.SourceAddressName]; !ok {
						slog.Warn("DNAT source-address-name not found in address-book",
							"rule", rule.Name, "name", rule.Match.SourceAddressName)
					}
				}

				// Parse match destination address
				if rule.Match.DestinationAddress == "" {
					slog.Warn("DNAT rule has no match destination-address",
						"rule", rule.Name)
					continue
				}

				matchIP, _, err := net.ParseCIDR(rule.Match.DestinationAddress)
				if err != nil {
					// Try as plain IP
					matchIP = net.ParseIP(rule.Match.DestinationAddress)
					if matchIP == nil {
						slog.Warn("invalid DNAT match address",
							"addr", rule.Match.DestinationAddress)
						continue
					}
				}

				// Parse pool address
				poolIP, _, err := net.ParseCIDR(pool.Address)
				if err != nil {
					poolIP = net.ParseIP(pool.Address)
					if poolIP == nil {
						slog.Warn("invalid DNAT pool address",
							"addr", pool.Address)
						continue
					}
				}

				// Resolve application match to protocol+ports if specified.
				// Supports single apps and multi-term application-sets.
				type dnatAppTerm struct {
					proto string
					ports []int
				}
				var appTerms []dnatAppTerm

				if rule.Match.Application != "" {
					userApps := cfg.Applications.Applications
					// Try single application first
					app, found := config.ResolveApplication(rule.Match.Application, userApps)
					if found {
						appTerms = append(appTerms, dnatAppTerm{proto: app.Protocol, ports: appPortsFromSpec(app.DestinationPort)})
					} else if _, isSet := cfg.Applications.ApplicationSets[rule.Match.Application]; isSet {
						// Expand application-set to individual terms
						expanded, eerr := config.ExpandApplicationSet(rule.Match.Application, &cfg.Applications)
						if eerr != nil {
							slog.Warn("DNAT expand application-set failed",
								"rule", rule.Name, "application", rule.Match.Application, "err", eerr)
						} else {
							for _, termName := range expanded {
								tApp, ok := config.ResolveApplication(termName, userApps)
								if !ok {
									slog.Warn("DNAT application-set term not found",
										"rule", rule.Name, "term", termName)
									continue
								}
								appTerms = append(appTerms, dnatAppTerm{proto: tApp.Protocol, ports: appPortsFromSpec(tApp.DestinationPort)})
							}
						}
					} else {
						slog.Warn("DNAT application not found, ignoring",
							"rule", rule.Name, "application", rule.Match.Application)
					}
				}

				// If no application terms resolved, use explicit match values
				if len(appTerms) == 0 {
					appTerms = []dnatAppTerm{{proto: rule.Match.Protocol, ports: rule.Match.DestinationPorts}}
				}

				for _, term := range appTerms {
					// Build list of destination ports for this term
					var dstPorts []uint16
					if len(term.ports) > 0 {
						for _, p := range term.ports {
							dstPorts = append(dstPorts, uint16(p))
						}
					} else if rule.Match.DestinationPort != 0 {
						dstPorts = []uint16{uint16(rule.Match.DestinationPort)}
					} else {
						dstPorts = []uint16{0}
					}

					for _, dstPort := range dstPorts {
						poolPort := dstPort
						if pool.Port != 0 {
							poolPort = uint16(pool.Port)
						}

						// Determine protocol(s) to insert DNAT entries for.
						var protos []uint8
						if term.proto != "" {
							protos = []uint8{protocolNumber(term.proto)}
						} else if dstPort != 0 {
							protos = []uint8{6} // TCP default for port-based DNAT
						} else {
							protos = []uint8{6, 17} // both TCP and UDP for port-less DNAT
						}

						for _, proto := range protos {
							// Route to v4 or v6 DNAT table based on match IP
							if matchIP.To4() != nil {
								dk := DNATKey{
									Protocol: proto,
									DstIP:    ipToUint32BE(matchIP),
									DstPort:  htons(dstPort),
								}
								dv := DNATValue{
									NewDstIP:   ipToUint32BE(poolIP),
									NewDstPort: htons(poolPort),
									Flags:      DNATFlagStatic,
								}
								if err := dp.SetDNATEntry(dk, dv); err != nil {
									return fmt.Errorf("set dnat entry %s/%s proto %d: %w",
										rs.Name, rule.Name, proto, err)
								}
								writtenDNAT[dk] = true
							} else {
								dk := DNATKeyV6{
									Protocol: proto,
									DstIP:    ipTo16Bytes(matchIP),
									DstPort:  htons(dstPort),
								}
								dv := DNATValueV6{
									NewDstIP:   ipTo16Bytes(poolIP),
									NewDstPort: htons(poolPort),
									Flags:      DNATFlagStatic,
								}
								if err := dp.SetDNATEntryV6(dk, dv); err != nil {
									return fmt.Errorf("set dnat_v6 entry %s/%s proto %d: %w",
										rs.Name, rule.Name, proto, err)
								}
								writtenDNATv6[dk] = true
							}

							slog.Info("destination NAT rule compiled",
								"rule-set", rs.Name, "rule", rule.Name,
								"match_ip", matchIP, "match_port", dstPort,
								"proto", proto,
								"pool", pool.Name, "pool_ip", poolIP,
								"pool_port", poolPort)
						}
					}
				}
			}
		}
	}

	// Delete stale NAT entries and zero unused pool slots.
	dp.DeleteStaleSNATRules(writtenSNAT)
	dp.DeleteStaleSNATRulesV6(writtenSNATv6)
	dp.DeleteStaleDNATStatic(writtenDNAT)
	dp.DeleteStaleDNATStaticV6(writtenDNATv6)
	dp.ZeroStaleNATPoolConfigs(uint32(poolID))

	return nil
}

func compileStaticNAT(dp DataPlane,cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenV4 := make(map[StaticNATKeyV4]bool)
	writtenV6 := make(map[StaticNATKeyV6]bool)

	count := 0
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if rule.Match == "" || rule.Then == "" {
				slog.Warn("static NAT rule missing match or then",
					"rule-set", rs.Name, "rule", rule.Name)
				continue
			}

			// Parse external (match) address
			matchCIDR := rule.Match
			if !strings.Contains(matchCIDR, "/") {
				if strings.Contains(matchCIDR, ":") {
					matchCIDR += "/128"
				} else {
					matchCIDR += "/32"
				}
			}
			extIP, _, err := net.ParseCIDR(matchCIDR)
			if err != nil {
				slog.Warn("invalid static NAT match address",
					"addr", rule.Match, "err", err)
				continue
			}

			// Parse internal (then) address
			thenCIDR := rule.Then
			if !strings.Contains(thenCIDR, "/") {
				if strings.Contains(thenCIDR, ":") {
					thenCIDR += "/128"
				} else {
					thenCIDR += "/32"
				}
			}
			intIP, _, err := net.ParseCIDR(thenCIDR)
			if err != nil {
				slog.Warn("invalid static NAT then address",
					"addr", rule.Then, "err", err)
				continue
			}

			// Insert DNAT entry (external -> internal) and SNAT entry (internal -> external)
			if extIP.To4() != nil && intIP.To4() != nil {
				extU32 := ipToUint32BE(extIP)
				intU32 := ipToUint32BE(intIP)

				if err := dp.SetStaticNATEntryV4(extU32, StaticNATDNAT, intU32); err != nil {
					return fmt.Errorf("set static nat dnat v4 %s: %w", rule.Name, err)
				}
				writtenV4[StaticNATKeyV4{IP: extU32, Direction: StaticNATDNAT}] = true
				if err := dp.SetStaticNATEntryV4(intU32, StaticNATSNAT, extU32); err != nil {
					return fmt.Errorf("set static nat snat v4 %s: %w", rule.Name, err)
				}
				writtenV4[StaticNATKeyV4{IP: intU32, Direction: StaticNATSNAT}] = true
			} else {
				extBytes := ipTo16Bytes(extIP)
				intBytes := ipTo16Bytes(intIP)

				if err := dp.SetStaticNATEntryV6(extBytes, StaticNATDNAT, intBytes); err != nil {
					return fmt.Errorf("set static nat dnat v6 %s: %w", rule.Name, err)
				}
				writtenV6[StaticNATKeyV6{IP: extBytes, Direction: StaticNATDNAT}] = true
				if err := dp.SetStaticNATEntryV6(intBytes, StaticNATSNAT, extBytes); err != nil {
					return fmt.Errorf("set static nat snat v6 %s: %w", rule.Name, err)
				}
				writtenV6[StaticNATKeyV6{IP: intBytes, Direction: StaticNATSNAT}] = true
			}

			count++
			slog.Info("static NAT rule compiled",
				"rule-set", rs.Name, "rule", rule.Name,
				"external", rule.Match, "internal", rule.Then)
		}
	}

	if count > 0 {
		slog.Info("static NAT compilation complete", "entries", count)
	}

	// Delete stale static NAT entries.
	dp.DeleteStaleStaticNAT(writtenV4, writtenV6)

	return nil
}

func compileNAT64(dp DataPlane,cfg *config.Config, result *CompileResult) error {
	// Track written prefixes for populate-before-clear.
	writtenPrefixes := make(map[NAT64PrefixKey]bool)

	ruleSets := cfg.Security.NAT.NAT64
	if len(ruleSets) == 0 {
		return nil
	}

	count := uint32(0)
	for _, rs := range ruleSets {
		if count >= 4 { // MAX_NAT64_PREFIXES
			slog.Warn("max NAT64 prefixes exceeded, skipping", "rule-set", rs.Name)
			break
		}

		// Parse the /96 prefix (e.g. "64:ff9b::/96")
		ip, ipNet, err := net.ParseCIDR(rs.Prefix)
		if err != nil {
			return fmt.Errorf("NAT64 rule-set %q: invalid prefix %q: %w", rs.Name, rs.Prefix, err)
		}
		ones, _ := ipNet.Mask.Size()
		if ones != 96 {
			return fmt.Errorf("NAT64 rule-set %q: prefix must be /96, got /%d", rs.Name, ones)
		}

		// Extract first 96 bits as 3 x uint32.
		// BPF stores these as __be32 (raw network bytes). cilium/ebpf serializes
		// Go uint32 using native endian, so use NativeEndian.Uint32 on the raw
		// IP bytes to preserve the byte pattern (same as ipToUint32BE).
		ip16 := ip.To16()
		if ip16 == nil {
			return fmt.Errorf("NAT64 rule-set %q: prefix is not IPv6", rs.Name)
		}
		var prefix [3]uint32
		prefix[0] = binary.NativeEndian.Uint32(ip16[0:4])
		prefix[1] = binary.NativeEndian.Uint32(ip16[4:8])
		prefix[2] = binary.NativeEndian.Uint32(ip16[8:12])

		// Look up the source pool ID
		poolID, ok := result.PoolIDs[rs.SourcePool]
		if !ok {
			return fmt.Errorf("NAT64 rule-set %q: source pool %q not found (must be defined in source NAT)", rs.Name, rs.SourcePool)
		}

		nat64Cfg := NAT64Config{
			Prefix:     prefix,
			SNATPoolID: poolID,
		}
		if err := dp.SetNAT64Config(count, nat64Cfg); err != nil {
			return fmt.Errorf("NAT64 rule-set %q: set config: %w", rs.Name, err)
		}
		writtenPrefixes[NAT64PrefixKey{Prefix: nat64Cfg.Prefix}] = true

		slog.Info("compiled NAT64 prefix",
			"rule-set", rs.Name, "prefix", rs.Prefix,
			"pool", rs.SourcePool, "pool_id", poolID)
		count++
	}

	if err := dp.SetNAT64Count(count); err != nil {
		return fmt.Errorf("set NAT64 count: %w", err)
	}

	// Delete stale NAT64 entries.
	dp.DeleteStaleNAT64(count, writtenPrefixes)

	slog.Info("NAT64 compilation complete", "prefixes", count)
	return nil
}

func compileScreenProfiles(dp DataPlane,cfg *config.Config, result *CompileResult) error {
	var maxScreenID uint32
	for name, profile := range cfg.Security.Screen {
		sid, ok := result.ScreenIDs[name]
		if !ok {
			continue
		}

		var flags uint32
		var sc ScreenConfig

		// TCP flags
		if profile.TCP.Land {
			flags |= ScreenLandAttack
		}
		if profile.TCP.SynFin {
			flags |= ScreenTCPSynFin
		}
		if profile.TCP.NoFlag {
			flags |= ScreenTCPNoFlag
		}
		if profile.TCP.FinNoAck {
			flags |= ScreenTCPFinNoAck
		}
		if profile.TCP.WinNuke {
			flags |= ScreenWinNuke
		}
		if profile.TCP.SynFrag {
			flags |= ScreenSynFrag
		}
		// IP flags (early, before IP section for co-location with related checks)
		if profile.IP.TearDrop {
			flags |= ScreenTearDrop
		}
		if profile.TCP.SynFlood != nil && profile.TCP.SynFlood.AttackThreshold > 0 {
			flags |= ScreenSynFlood
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
		}

		// ICMP flags
		if profile.ICMP.PingDeath {
			flags |= ScreenPingOfDeath
		}
		if profile.ICMP.FloodThreshold > 0 {
			flags |= ScreenICMPFlood
			sc.ICMPFloodThresh = uint32(profile.ICMP.FloodThreshold)
		}

		// IP flags
		if profile.IP.SourceRouteOption {
			flags |= ScreenIPSourceRoute
		}

		// UDP flags
		if profile.UDP.FloodThreshold > 0 {
			flags |= ScreenUDPFlood
			sc.UDPFloodThresh = uint32(profile.UDP.FloodThreshold)
		}

		// Port scan detection
		if profile.TCP.PortScanThreshold > 0 {
			flags |= ScreenPortScan
			sc.PortScanThresh = uint32(profile.TCP.PortScanThreshold)
		}

		// IP sweep detection
		if profile.IP.IPSweepThreshold > 0 {
			flags |= ScreenIPSweep
			sc.IPSweepThresh = uint32(profile.IP.IPSweepThreshold)
		}

		sc.Flags = flags

		if err := dp.SetScreenConfig(uint32(sid), sc); err != nil {
			return fmt.Errorf("set screen config %s (id=%d): %w", name, sid, err)
		}
		if uint32(sid) > maxScreenID {
			maxScreenID = uint32(sid)
		}

		slog.Info("screen profile compiled",
			"name", name, "id", sid,
			"flags", fmt.Sprintf("0x%x", flags),
			"syn_thresh", sc.SynFloodThresh,
			"icmp_thresh", sc.ICMPFloodThresh,
			"udp_thresh", sc.UDPFloodThresh)
	}

	// Zero screen config entries above the highest used ID.
	dp.ZeroStaleScreenConfigs(maxScreenID)

	return nil
}

func compileDefaultPolicy(dp DataPlane,cfg *config.Config) error {
	action := uint8(ActionDeny) // default deny
	if cfg.Security.DefaultPolicy == config.PolicyPermit {
		action = ActionPermit
	}
	if err := dp.SetDefaultPolicy(action); err != nil {
		return fmt.Errorf("set default policy: %w", err)
	}
	if action == ActionPermit {
		slog.Info("default policy compiled", "action", "permit-all")
	} else {
		slog.Info("default policy compiled", "action", "deny-all")
	}
	return nil
}

func compileFlowTimeouts(dp DataPlane,cfg *config.Config) error {
	flow := &cfg.Security.Flow

	// Write all timeout slots; 0 means "use BPF default".
	timeouts := [FlowTimeoutMax]uint32{}

	if flow.TCPSession != nil {
		timeouts[FlowTimeoutTCPEstablished] = uint32(flow.TCPSession.EstablishedTimeout)
		timeouts[FlowTimeoutTCPInitial] = uint32(flow.TCPSession.InitialTimeout)
		timeouts[FlowTimeoutTCPClosing] = uint32(flow.TCPSession.ClosingTimeout)
		timeouts[FlowTimeoutTCPTimeWait] = uint32(flow.TCPSession.TimeWaitTimeout)
	}
	timeouts[FlowTimeoutUDP] = uint32(flow.UDPSessionTimeout)
	timeouts[FlowTimeoutICMP] = uint32(flow.ICMPSessionTimeout)

	for idx := uint32(0); idx < FlowTimeoutMax; idx++ {
		if err := dp.SetFlowTimeout(idx, timeouts[idx]); err != nil {
			return fmt.Errorf("set flow timeout %d: %w", idx, err)
		}
	}

	// Log only if any non-default value was set.
	for _, v := range timeouts {
		if v > 0 {
			slog.Info("flow timeouts compiled",
				"tcp_established", timeouts[FlowTimeoutTCPEstablished],
				"tcp_initial", timeouts[FlowTimeoutTCPInitial],
				"tcp_closing", timeouts[FlowTimeoutTCPClosing],
				"tcp_time_wait", timeouts[FlowTimeoutTCPTimeWait],
				"udp", timeouts[FlowTimeoutUDP],
				"icmp", timeouts[FlowTimeoutICMP])
			break
		}
	}

	return nil
}

func compileFlowConfig(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	flow := &cfg.Security.Flow
	fc := FlowConfigValue{
		TCPMSSIPsec: uint16(flow.TCPMSSIPsecVPN),
		TCPMSSGreIn:  uint16(flow.TCPMSSGreIn),
		TCPMSSGreOut: uint16(flow.TCPMSSGreOut),
	}
	if flow.AllowDNSReply {
		fc.AllowDNSReply = 1
	}
	if flow.AllowEmbeddedICMP {
		fc.AllowEmbeddedICMP = 1
	}
	if flow.GREPerformanceAcceleration {
		fc.GREAccel = 1
	}

	// ALG disable flags (bitfield)
	alg := &cfg.Security.ALG
	if alg.DNSDisable {
		fc.ALGFlags |= 0x01
	}
	if alg.FTPDisable {
		fc.ALGFlags |= 0x02
	}
	if alg.SIPDisable {
		fc.ALGFlags |= 0x04
	}
	if alg.TFTPDisable {
		fc.ALGFlags |= 0x08
	}

	// Lo0 filter IDs for host-bound traffic filtering (0xFFFF = none)
	if result.Lo0FilterV4 != 0xFFFFFFFF {
		fc.Lo0FilterV4 = uint16(result.Lo0FilterV4)
	} else {
		fc.Lo0FilterV4 = Lo0FilterNone
	}
	if result.Lo0FilterV6 != 0xFFFFFFFF {
		fc.Lo0FilterV6 = uint16(result.Lo0FilterV6)
	} else {
		fc.Lo0FilterV6 = Lo0FilterNone
	}

	if err := dp.SetFlowConfig(fc); err != nil {
		return err
	}

	slog.Info("flow config compiled",
		"tcp_mss_ipsec", fc.TCPMSSIPsec,
		"tcp_mss_gre_in", fc.TCPMSSGreIn,
		"tcp_mss_gre_out", fc.TCPMSSGreOut,
		"allow_dns_reply", fc.AllowDNSReply,
		"allow_embedded_icmp", fc.AllowEmbeddedICMP,
		"lo0_filter_v4", fc.Lo0FilterV4,
		"lo0_filter_v6", fc.Lo0FilterV6)

	return nil
}

// getInterfaceIP returns the first IPv4 address of a network interface.
// Accepts Junos-style names (ge-0/0/0) and translates to Linux names.
func getInterfaceIP(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(config.LinuxIfName(ifaceName))
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %s addrs: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", ifaceName)
}

// getInterfaceIPv6 returns the first global unicast IPv6 address of a network interface.
// Accepts Junos-style names (ge-0/0/0) and translates to Linux names.
func getInterfaceIPv6(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(config.LinuxIfName(ifaceName))
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %s addrs: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			continue // skip IPv4
		}
		if ipNet.IP.IsGlobalUnicast() {
			return ipNet.IP, nil
		}
	}
	return nil, fmt.Errorf("no global unicast IPv6 address on interface %s", ifaceName)
}

// rethConfigAddrs extracts IPv4 and IPv6 addresses from a RETH interface's config
// units. Used for interface-mode SNAT when the VIP may not be on this node.
func rethConfigAddrs(ifCfg *config.InterfaceConfig) (v4, v6 []net.IP) {
	for _, unit := range ifCfg.Units {
		for _, addr := range unit.Addresses {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				v4 = append(v4, ip4)
			} else if ip.IsGlobalUnicast() {
				v6 = append(v6, ip)
			}
		}
	}
	return
}

// protocolNumber converts a protocol name to its IANA number.
func protocolNumber(name string) uint8 {
	switch strings.ToLower(name) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmpv6", "icmp6":
		return 58
	case "gre":
		return 47
	default:
		// Try numeric protocol number
		if n, err := strconv.Atoi(name); err == nil && n > 0 && n < 256 {
			return uint8(n)
		}
		return 0
	}
}

// algTypeFromString maps an ALG name to its BPF constant (0=none, 1=FTP, 2=SIP, 3=DNS).
func algTypeFromString(alg string) uint8 {
	switch strings.ToLower(alg) {
	case "ftp":
		return 1
	case "sip":
		return 2
	case "dns":
		return 3
	default:
		return 0
	}
}

// parsePorts parses a port specification like "80", "8080-8090", or "".
// Returns a list of individual ports. For ranges, returns all ports in range.
func parsePorts(spec string) ([]uint16, error) {
	if spec == "" {
		return []uint16{0}, nil
	}

	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		low, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, err
		}
		high, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, err
		}
		var ports []uint16
		for p := low; p <= high; p++ {
			ports = append(ports, uint16(p))
		}
		return ports, nil
	}

	port, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return nil, err
	}
	return []uint16{uint16(port)}, nil
}

// appPortsFromSpec parses an application's DestinationPort spec (e.g. "80", "8080-8090")
// into a slice of individual port ints. Returns nil for empty spec.
func appPortsFromSpec(spec string) []int {
	if spec == "" {
		return nil
	}
	lo, hi, err := parsePortRange(spec)
	if err != nil {
		return nil
	}
	if hi > lo {
		var ports []int
		for p := lo; p <= hi; p++ {
			ports = append(ports, int(p))
		}
		return ports
	}
	return []int{int(lo)}
}

// parsePortRange parses a port spec like "80", "1024-65535", or "" into (low, high).
// Unlike parsePorts, it does NOT expand ranges — returns the range boundaries.
func parsePortRange(spec string) (uint16, uint16, error) {
	if spec == "" {
		return 0, 0, nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		low, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return 0, 0, err
		}
		high, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return 0, 0, err
		}
		return uint16(low), uint16(high), nil
	}
	port, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return 0, 0, err
	}
	return uint16(port), uint16(port), nil
}

// compileFirewallFilters compiles firewall filter config into BPF maps.
// It creates filter_rules, filter_configs, iface_filter_map, and policer_configs entries.
func compileFirewallFilters(dp DataPlane,cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenIfaceFilter := make(map[IfaceFilterKey]bool)

	// Build routing instance name -> table ID map (skip forwarding instances)
	riTableIDs := make(map[string]uint32)
	for _, ri := range cfg.RoutingInstances {
		if ri.InstanceType != "forwarding" {
			riTableIDs[ri.Name] = uint32(ri.TableID)
		}
	}

	// Compile policer definitions (sorted for deterministic IDs, 1-based)
	policerIDs := make(map[string]uint32) // policer name -> ID (1-based)
	if len(cfg.Firewall.Policers) > 0 {
		polNames := make([]string, 0, len(cfg.Firewall.Policers))
		for name := range cfg.Firewall.Policers {
			polNames = append(polNames, name)
		}
		sort.Strings(polNames)
		for i, name := range polNames {
			polID := uint32(i + 1) // 1-based (0 = no policer)
			if polID >= MaxPolicers {
				slog.Warn("policer limit reached", "policer", name)
				break
			}
			pol := cfg.Firewall.Policers[name]
			bpfCfg := PolicerConfig{
				RateBytesSec: pol.BandwidthLimit,
				BurstBytes:   pol.BurstSizeLimit,
			}
			if err := dp.SetPolicerConfig(polID, bpfCfg); err != nil {
				return fmt.Errorf("set policer config %s: %w", name, err)
			}
			policerIDs[name] = polID
			slog.Info("compiled policer",
				"name", name, "rate_bps", pol.BandwidthLimit,
				"burst", pol.BurstSizeLimit, "id", polID)
		}
	}

	// Compile three-color policer definitions (continue IDs after single-rate)
	if len(cfg.Firewall.ThreeColorPolicers) > 0 {
		nextPolID := uint32(len(policerIDs) + 1) // continue after single-rate IDs
		tcpNames := make([]string, 0, len(cfg.Firewall.ThreeColorPolicers))
		for name := range cfg.Firewall.ThreeColorPolicers {
			tcpNames = append(tcpNames, name)
		}
		sort.Strings(tcpNames)
		for _, name := range tcpNames {
			polID := nextPolID
			if polID >= MaxPolicers {
				slog.Warn("three-color policer limit reached", "policer", name)
				break
			}
			tcp := cfg.Firewall.ThreeColorPolicers[name]
			bpfCfg := PolicerConfig{
				RateBytesSec: tcp.CIR,
				BurstBytes:   tcp.CBS,
				PeakRate:     tcp.PIR,
				PeakBurst:    tcp.PBS,
			}
			if tcp.TwoRate {
				bpfCfg.ColorMode = PolicerModeTwoRate
			} else {
				bpfCfg.ColorMode = PolicerModeSR3C
			}
			if err := dp.SetPolicerConfig(polID, bpfCfg); err != nil {
				return fmt.Errorf("set three-color policer %s: %w", name, err)
			}
			policerIDs[name] = polID
			slog.Info("compiled three-color policer",
				"name", name, "mode", bpfCfg.ColorMode,
				"cir", tcp.CIR, "cbs", tcp.CBS,
				"pir", tcp.PIR, "pbs", tcp.PBS, "id", polID)
			nextPolID++
		}
	}

	filterID := uint32(0)
	ruleIdx := uint32(0)
	filterIDs := make(map[string]uint32) // "inet:name" or "inet6:name" -> filter_id

	// Compile inet filters (sorted for deterministic IDs)
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)
	for _, name := range inetNames {
		filter := cfg.Firewall.FiltersInet[name]
		if filterID >= MaxFilterConfigs || ruleIdx >= MaxFilterRules {
			slog.Warn("firewall filter limit reached", "filter", name)
			break
		}
		startIdx := ruleIdx
		for _, term := range filter.Terms {
			rules := expandFilterTerm(term, AFInet, riTableIDs, cfg.PolicyOptions.PrefixLists, policerIDs)
			for _, rule := range rules {
				if ruleIdx >= MaxFilterRules {
					slog.Warn("filter rule limit reached", "filter", name, "term", term.Name)
					break
				}
				if err := dp.SetFilterRule(ruleIdx, rule); err != nil {
					return fmt.Errorf("set filter rule %d: %w", ruleIdx, err)
				}
				ruleIdx++
			}
		}
		numRules := ruleIdx - startIdx
		if err := dp.SetFilterConfig(filterID, FilterConfig{
			NumRules:  numRules,
			RuleStart: startIdx,
		}); err != nil {
			return fmt.Errorf("set filter config %s: %w", name, err)
		}
		filterIDs["inet:"+name] = filterID
		slog.Info("compiled firewall filter",
			"name", name, "family", "inet", "terms", len(filter.Terms),
			"rules", numRules, "filter_id", filterID)
		filterID++
	}

	// Compile inet6 filters (sorted for deterministic IDs)
	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)
	for _, name := range inet6Names {
		filter := cfg.Firewall.FiltersInet6[name]
		if filterID >= MaxFilterConfigs || ruleIdx >= MaxFilterRules {
			slog.Warn("firewall filter limit reached", "filter", name)
			break
		}
		startIdx := ruleIdx
		for _, term := range filter.Terms {
			rules := expandFilterTerm(term, AFInet6, riTableIDs, cfg.PolicyOptions.PrefixLists, policerIDs)
			for _, rule := range rules {
				if ruleIdx >= MaxFilterRules {
					slog.Warn("filter rule limit reached", "filter", name, "term", term.Name)
					break
				}
				if err := dp.SetFilterRule(ruleIdx, rule); err != nil {
					return fmt.Errorf("set filter rule %d: %w", ruleIdx, err)
				}
				ruleIdx++
			}
		}
		numRules := ruleIdx - startIdx
		if err := dp.SetFilterConfig(filterID, FilterConfig{
			NumRules:  numRules,
			RuleStart: startIdx,
		}); err != nil {
			return fmt.Errorf("set filter config %s: %w", name, err)
		}
		filterIDs["inet6:"+name] = filterID
		slog.Info("compiled firewall filter",
			"name", name, "family", "inet6", "terms", len(filter.Terms),
			"rules", numRules, "filter_id", filterID)
		filterID++
	}

	// Map interfaces to their assigned filters
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		for _, unit := range ifCfg.Units {
			if unit.FilterInputV4 == "" && unit.FilterInputV6 == "" &&
				unit.FilterOutputV4 == "" && unit.FilterOutputV6 == "" {
				continue
			}

			physName := config.LinuxIfName(ifCfg.Name)
			vlanID := uint16(unit.VlanID)

			// Resolve ifindex
			iface, err := net.InterfaceByName(physName)
			if err != nil {
				slog.Warn("interface not found for filter assignment",
					"interface", physName, "err", err)
				continue
			}

			ifindex := uint32(iface.Index)
			// If VLAN sub-interface, use the sub-interface ifindex
			if vlanID > 0 {
				subName := fmt.Sprintf("%s.%d", physName, vlanID)
				subIface, err := net.InterfaceByName(subName)
				if err != nil {
					slog.Warn("VLAN sub-interface not found for filter",
						"name", subName, "err", err)
					continue
				}
				ifindex = uint32(subIface.Index)
				// Physical ifindex is used in iface_filter_key since
				// xdp_main uses ctx->ingress_ifindex (parent phys NIC)
				ifindex = uint32(iface.Index)
			}

			if unit.FilterInputV4 != "" {
				fid, ok := filterIDs["inet:"+unit.FilterInputV4]
				if !ok {
					slog.Warn("filter not found for interface",
						"filter", unit.FilterInputV4, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex: ifindex,
						VlanID:  vlanID,
						Family:  AFInet,
					}
					if err := dp.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set iface filter %s inet: %w", physName, err)
					}
					writtenIfaceFilter[key] = true
					slog.Info("assigned filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet", "filter", unit.FilterInputV4)
				}
			}

			if unit.FilterInputV6 != "" {
				fid, ok := filterIDs["inet6:"+unit.FilterInputV6]
				if !ok {
					slog.Warn("filter not found for interface",
						"filter", unit.FilterInputV6, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex: ifindex,
						VlanID:  vlanID,
						Family:  AFInet6,
					}
					if err := dp.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set iface filter %s inet6: %w", physName, err)
					}
					writtenIfaceFilter[key] = true
					slog.Info("assigned filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet6", "filter", unit.FilterInputV6)
				}
			}

			// Output filters use direction=1 and the egress ifindex.
			// For VLAN sub-interfaces, TC egress sees skb->ifindex as
			// the sub-interface, so use its ifindex (not parent).
			egressIfindex := ifindex
			if vlanID > 0 {
				subName := fmt.Sprintf("%s.%d", physName, vlanID)
				if subIface, err := net.InterfaceByName(subName); err == nil {
					egressIfindex = uint32(subIface.Index)
				}
			}

			if unit.FilterOutputV4 != "" {
				fid, ok := filterIDs["inet:"+unit.FilterOutputV4]
				if !ok {
					slog.Warn("output filter not found for interface",
						"filter", unit.FilterOutputV4, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex:   egressIfindex,
						VlanID:    0, // TC egress doesn't track VLAN separately
						Family:    AFInet,
						Direction: 1,
					}
					if err := dp.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set output filter %s inet: %w", physName, err)
					}
					writtenIfaceFilter[key] = true
					slog.Info("assigned output filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet", "filter", unit.FilterOutputV4)
				}
			}

			if unit.FilterOutputV6 != "" {
				fid, ok := filterIDs["inet6:"+unit.FilterOutputV6]
				if !ok {
					slog.Warn("output filter not found for interface",
						"filter", unit.FilterOutputV6, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex:   egressIfindex,
						VlanID:    0,
						Family:    AFInet6,
						Direction: 1,
					}
					if err := dp.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set output filter %s inet6: %w", physName, err)
					}
					writtenIfaceFilter[key] = true
					slog.Info("assigned output filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet6", "filter", unit.FilterOutputV6)
				}
			}
		}
	}

	// Delete stale filter entries and zero unused filter config/rule slots.
	dp.DeleteStaleIfaceFilter(writtenIfaceFilter)
	dp.ZeroStaleFilterConfigs(filterID)

	result.FilterIDs = filterIDs

	// Resolve lo0 filter IDs for host-bound traffic filtering
	if cfg.System.Lo0FilterInputV4 != "" {
		if fid, ok := filterIDs["inet:"+cfg.System.Lo0FilterInputV4]; ok {
			result.Lo0FilterV4 = fid
			slog.Info("lo0 inet filter assigned", "filter", cfg.System.Lo0FilterInputV4, "id", fid)
		} else {
			slog.Warn("lo0 inet filter not found", "filter", cfg.System.Lo0FilterInputV4)
		}
	}
	if cfg.System.Lo0FilterInputV6 != "" {
		if fid, ok := filterIDs["inet6:"+cfg.System.Lo0FilterInputV6]; ok {
			result.Lo0FilterV6 = fid
			slog.Info("lo0 inet6 filter assigned", "filter", cfg.System.Lo0FilterInputV6, "id", fid)
		} else {
			slog.Warn("lo0 inet6 filter not found", "filter", cfg.System.Lo0FilterInputV6)
		}
	}

	return nil
}

// expandFilterTerm expands a single filter term into one or more BPF filter rules.
// Terms with multiple source/destination addresses generate the cross product of rules.
func expandFilterTerm(term *config.FirewallFilterTerm, family uint8, riTableIDs map[string]uint32, prefixLists map[string]*config.PrefixList, policerIDs map[string]uint32) []FilterRule {
	// Base rule with common fields
	base := FilterRule{
		Family:      family,
		DSCPRewrite: 0xFF, // no DSCP rewrite by default
	}

	// Set log flag
	if term.Log {
		base.LogFlag = 1
	}

	// Set action
	if term.RoutingInstance != "" {
		base.Action = FilterActionRoute
		if tableID, ok := riTableIDs[term.RoutingInstance]; ok {
			base.RoutingTable = tableID
		} else {
			slog.Warn("routing-instance not found for filter term",
				"term", term.Name, "instance", term.RoutingInstance)
			base.Action = FilterActionAccept
		}
	} else {
		switch term.Action {
		case "discard":
			base.Action = FilterActionDiscard
		case "reject":
			base.Action = FilterActionReject
		default:
			base.Action = FilterActionAccept
		}
	}

	// DSCP match
	if term.DSCP != "" {
		base.MatchFlags |= FilterMatchDSCP
		if val, ok := DSCPValues[strings.ToLower(term.DSCP)]; ok {
			base.DSCP = val
		} else if v, err := strconv.Atoi(term.DSCP); err == nil {
			base.DSCP = uint8(v)
		}
	}

	// DSCP rewrite action (then dscp <value>)
	if term.DSCPRewrite != "" {
		if val, ok := DSCPValues[strings.ToLower(term.DSCPRewrite)]; ok {
			base.DSCPRewrite = val
		} else if v, err := strconv.Atoi(term.DSCPRewrite); err == nil {
			base.DSCPRewrite = uint8(v)
		}
	}

	// Forwarding-class + loss-priority → DSCP rewrite.
	// Only applies if no explicit dscp rewrite was set.
	if term.ForwardingClass != "" && base.DSCPRewrite == 0xFF {
		if val, ok := forwardingClassToDSCP(term.ForwardingClass, term.LossPriority); ok {
			base.DSCPRewrite = val
		}
	}

	// Policer reference
	if term.Policer != "" {
		if polID, ok := policerIDs[term.Policer]; ok {
			base.PolicerID = uint8(polID)
		} else {
			slog.Warn("policer not found for filter term",
				"term", term.Name, "policer", term.Policer)
		}
	}

	// Protocol match
	if term.Protocol != "" {
		base.MatchFlags |= FilterMatchProtocol
		switch strings.ToLower(term.Protocol) {
		case "tcp":
			base.Protocol = 6
		case "udp":
			base.Protocol = 17
		case "icmp":
			base.Protocol = 1
		case "icmpv6":
			base.Protocol = 58
		default:
			if v, err := strconv.Atoi(term.Protocol); err == nil {
				base.Protocol = uint8(v)
			}
		}
	}

	// ICMP type/code
	if term.ICMPType >= 0 {
		base.MatchFlags |= FilterMatchICMPType
		base.ICMPType = uint8(term.ICMPType)
	}
	if term.ICMPCode >= 0 {
		base.MatchFlags |= FilterMatchICMPCode
		base.ICMPCode = uint8(term.ICMPCode)
	}

	// TCP flags match
	if len(term.TCPFlags) > 0 {
		base.MatchFlags |= FilterMatchTCPFlags
		for _, flag := range term.TCPFlags {
			switch strings.ToLower(flag) {
			case "syn":
				base.TCPFlags |= 0x02
			case "ack":
				base.TCPFlags |= 0x10
			case "fin":
				base.TCPFlags |= 0x01
			case "rst":
				base.TCPFlags |= 0x04
			case "psh":
				base.TCPFlags |= 0x08
			case "urg":
				base.TCPFlags |= 0x20
			}
		}
	}

	// Fragment match
	if term.IsFragment {
		base.MatchFlags |= FilterMatchFragment
		base.IsFragment = 1
	}

	// Flexible match
	if term.FlexMatch != nil {
		base.MatchFlags |= FilterMatchFlex
		base.FlexOffset = term.FlexMatch.ByteOffset
		base.FlexLength = term.FlexMatch.BitLength / 8
		if base.FlexLength == 0 {
			base.FlexLength = 4 // default 32-bit
		}
		base.FlexValue = term.FlexMatch.Value & term.FlexMatch.Mask
		base.FlexMask = term.FlexMatch.Mask
	}

	// Expand prefix list references into address lists.
	// Each address tracks whether it came from an "except" prefix-list reference.
	type filterAddr struct {
		cidr   string
		negate bool
	}
	var srcAddrs []filterAddr
	for _, a := range term.SourceAddresses {
		srcAddrs = append(srcAddrs, filterAddr{cidr: a})
	}
	for _, ref := range term.SourcePrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			for _, p := range pl.Prefixes {
				srcAddrs = append(srcAddrs, filterAddr{cidr: p, negate: ref.Except})
			}
		} else {
			slog.Warn("prefix-list not found", "name", ref.Name, "term", term.Name)
		}
	}
	var dstAddrs []filterAddr
	for _, a := range term.DestAddresses {
		dstAddrs = append(dstAddrs, filterAddr{cidr: a})
	}
	for _, ref := range term.DestPrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			for _, p := range pl.Prefixes {
				dstAddrs = append(dstAddrs, filterAddr{cidr: p, negate: ref.Except})
			}
		} else {
			slog.Warn("prefix-list not found", "name", ref.Name, "term", term.Name)
		}
	}
	if len(srcAddrs) == 0 {
		srcAddrs = []filterAddr{{}} // "any"
	}
	if len(dstAddrs) == 0 {
		dstAddrs = []filterAddr{{}} // "any"
	}

	// Port lists: expand multiple ports into separate rules
	dstPorts := term.DestinationPorts
	if len(dstPorts) == 0 {
		dstPorts = []string{""} // "any"
	}
	srcPorts := term.SourcePorts
	if len(srcPorts) == 0 {
		srcPorts = []string{""} // "any"
	}

	var rules []FilterRule
	for _, src := range srcAddrs {
		for _, dst := range dstAddrs {
			for _, dp := range dstPorts {
				for _, sp := range srcPorts {
					rule := base
					if src.cidr != "" {
						rule.MatchFlags |= FilterMatchSrcAddr
						if src.negate {
							rule.MatchFlags |= FilterMatchSrcNegate
						}
						setFilterAddr(&rule.SrcAddr, &rule.SrcMask, src.cidr, family)
					}
					if dst.cidr != "" {
						rule.MatchFlags |= FilterMatchDstAddr
						if dst.negate {
							rule.MatchFlags |= FilterMatchDstNegate
						}
						setFilterAddr(&rule.DstAddr, &rule.DstMask, dst.cidr, family)
					}
					if dp != "" {
						rule.MatchFlags |= FilterMatchDstPort
						lo, hi := resolvePortRange(dp)
						rule.DstPort = htons(lo)
						if hi > lo {
							rule.DstPortHi = htons(hi)
						}
					}
					if sp != "" {
						rule.MatchFlags |= FilterMatchSrcPort
						lo, hi := resolvePortRange(sp)
						rule.SrcPort = htons(lo)
						if hi > lo {
							rule.SrcPortHi = htons(hi)
						}
					}
					rules = append(rules, rule)
				}
			}
		}
	}

	return rules
}

// setFilterAddr parses a CIDR string and populates addr/mask byte arrays.
func setFilterAddr(addr, mask *[16]byte, cidr string, family uint8) {
	// Strip "except" suffix if present (defensive — negate is tracked via MatchFlags)
	cidr = strings.TrimSuffix(cidr, " except")
	cidr = strings.TrimSuffix(cidr, ";")

	// If no prefix length, assume /32 (v4) or /128 (v6)
	if !strings.Contains(cidr, "/") {
		if family == AFInet {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		slog.Warn("invalid CIDR in filter term", "cidr", cidr, "err", err)
		return
	}

	if family == AFInet {
		ip4 := ip.To4()
		if ip4 == nil {
			return
		}
		copy(addr[:4], ip4)
		copy(mask[:4], ipNet.Mask)
	} else {
		ip16 := ip.To16()
		if ip16 == nil {
			return
		}
		copy(addr[:], ip16)
		copy(mask[:], ipNet.Mask)
	}
}

// resolvePortName maps well-known port names to numbers.
// resolvePortRange parses a port specification that may be a name, number,
// or range ("1000-2000"). Returns low and high port numbers. If not a range,
// hi equals lo.
func resolvePortRange(s string) (lo, hi uint16) {
	if idx := strings.IndexByte(s, '-'); idx > 0 && idx < len(s)-1 {
		lo = resolvePortName(s[:idx])
		hi = resolvePortName(s[idx+1:])
		return lo, hi
	}
	p := resolvePortName(s)
	return p, p
}

// forwardingClassToDSCP maps a Junos forwarding-class + loss-priority to a DSCP value.
// Forwarding classes: best-effort, expedited-forwarding, assured-forwarding, network-control.
// Loss priority selects the AF drop precedence (low=AFx1, medium-low=AFx2, medium-high/high=AFx3).
func forwardingClassToDSCP(fc, lp string) (uint8, bool) {
	fc = strings.ToLower(fc)
	lp = strings.ToLower(lp)
	switch fc {
	case "best-effort":
		return 0, true // CS0/BE
	case "expedited-forwarding":
		return 46, true // EF
	case "network-control":
		return 48, true // CS6
	case "assured-forwarding":
		// AF class 1 with drop precedence from loss-priority
		switch lp {
		case "high", "medium-high":
			return 14, true // AF13
		case "medium-low":
			return 12, true // AF12
		default:
			return 10, true // AF11
		}
	default:
		// Try as DSCP name directly
		if val, ok := DSCPValues[fc]; ok {
			return val, true
		}
		return 0, false
	}
}

func resolvePortName(name string) uint16 {
	switch strings.ToLower(name) {
	case "ssh":
		return 22
	case "http":
		return 80
	case "https":
		return 443
	case "dns", "domain":
		return 53
	case "ftp":
		return 21
	case "ftp-data":
		return 20
	case "smtp":
		return 25
	case "snmp":
		return 161
	case "snmptrap":
		return 162
	case "bgp":
		return 179
	case "ntp":
		return 123
	case "telnet":
		return 23
	case "pop3":
		return 110
	case "imap":
		return 143
	case "ldap":
		return 389
	case "syslog":
		return 514
	case "radacct":
		return 1813
	case "radius":
		return 1812
	case "ike":
		return 500
	default:
		if v, err := strconv.ParseUint(name, 10, 16); err == nil {
			return uint16(v)
		}
		return 0
	}
}

// applyEthtool applies speed and duplex settings via ethtool if configured.
// Errors are logged as warnings since virtual interfaces (virtio-net) don't
// support ethtool speed/duplex changes.
func applyEthtool(ifaceName string, ifCfg *config.InterfaceConfig) {
	speed := parseSpeed(ifCfg.Speed)
	duplex := parseDuplex(ifCfg.Duplex)
	if speed == "" && duplex == "" {
		return
	}
	args := []string{"-s", ifaceName}
	if speed != "" {
		args = append(args, "speed", speed)
	}
	if duplex != "" {
		args = append(args, "duplex", duplex)
	}
	if out, err := exec.Command("ethtool", args...).CombinedOutput(); err != nil {
		slog.Warn("failed to apply ethtool settings",
			"name", ifaceName, "speed", ifCfg.Speed, "duplex", ifCfg.Duplex,
			"err", fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out))))
	} else {
		slog.Info("applied ethtool settings", "name", ifaceName,
			"speed", ifCfg.Speed, "duplex", ifCfg.Duplex)
	}
}

// parseSpeed converts Junos speed values (e.g. "1g", "10g", "100m") to
// ethtool speed in Mbps. Returns "" for unknown/auto/empty values.
func parseSpeed(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "auto":
		return ""
	case "10m":
		return "10"
	case "100m":
		return "100"
	case "1g":
		return "1000"
	case "2.5g":
		return "2500"
	case "5g":
		return "5000"
	case "10g":
		return "10000"
	case "25g":
		return "25000"
	case "40g":
		return "40000"
	case "100g":
		return "100000"
	default:
		// Try to parse as raw Mbps number
		if _, err := strconv.Atoi(s); err == nil {
			return s
		}
		return ""
	}
}

// parseDuplex converts Junos duplex values to ethtool duplex values.
func parseDuplex(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "full":
		return "full"
	case "half":
		return "half"
	default:
		return ""
	}
}

// compilePortMirroring populates the mirror_config BPF map from
// forwarding-options { port-mirroring { instance ... } }.
func compilePortMirroring(dp DataPlane, cfg *config.Config) error {
	dp.ClearMirrorConfigs()

	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil || len(pm.Instances) == 0 {
		return nil
	}

	for name, inst := range pm.Instances {
		if inst.Output == "" {
			slog.Warn("port-mirroring instance has no output interface", "name", name)
			continue
		}

		outIface, err := net.InterfaceByName(inst.Output)
		if err != nil {
			slog.Warn("port-mirroring output interface not found",
				"name", name, "interface", inst.Output, "err", err)
			continue
		}

		rate := uint32(inst.InputRate)

		for _, inputIface := range inst.Input {
			inIface, err := net.InterfaceByName(inputIface)
			if err != nil {
				slog.Warn("port-mirroring input interface not found",
					"name", name, "interface", inputIface, "err", err)
				continue
			}

			if err := dp.SetMirrorConfig(inIface.Index, outIface.Index, rate); err != nil {
				return fmt.Errorf("set mirror config for %s: %w", inputIface, err)
			}

			slog.Info("port-mirroring compiled",
				"instance", name,
				"input", inputIface,
				"output", inst.Output,
				"rate", rate)
		}
	}

	return nil
}
