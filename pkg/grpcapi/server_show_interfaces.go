package grpcapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (s *Server) GetInterfaces(_ context.Context, _ *pb.GetInterfacesRequest) (*pb.GetInterfacesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetInterfacesResponse{}, nil
	}

	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	resp := &pb.GetInterfacesResponse{}
	for ifName := range allInterfaceNames(cfg) {
		iface, err := net.InterfaceByName(ifName)
		ii := &pb.InterfaceInfo{
			Name: ifName,
			Zone: ifZone[ifName],
		}
		if err == nil {
			ii.Ifindex = int32(iface.Index)
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil {
					ii.RxPackets = ctrs.RxPackets
					ii.RxBytes = ctrs.RxBytes
					ii.TxPackets = ctrs.TxPackets
					ii.TxBytes = ctrs.TxBytes
				}
			}
		}
		resp.Interfaces = append(resp.Interfaces, ii)
	}
	sort.Slice(resp.Interfaces, func(i, j int) bool { return resp.Interfaces[i].Name < resp.Interfaces[j].Name })
	return resp, nil
}

func (s *Server) ShowInterfacesDetail(_ context.Context, req *pb.ShowInterfacesDetailRequest) (*pb.ShowInterfacesDetailResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.ShowInterfacesDetailResponse{Output: "no active configuration\n"}, nil
	}

	filterName := req.Filter

	if req.Terse {
		return s.showInterfacesTerse(cfg, filterName)
	}

	// Build interface -> zone mapping
	ifaceZone := make(map[string]*config.ZoneConfig)
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifaceZone[ifName] = zone
			ifaceZoneName[ifName] = name
		}
	}

	// Collect logical interfaces
	type logicalIface struct {
		zoneName string
		zone     *config.ZoneConfig
		physName string
		unitNum  int
		vlanID   int
	}
	var logicals []logicalIface

	for ifName, zone := range ifaceZone {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		parts := strings.SplitN(ifName, ".", 2)
		physName := parts[0]
		unitNum := 0
		if len(parts) == 2 {
			fmt.Sscanf(parts[1], "%d", &unitNum)
		}
		vlanID := 0
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
			if unit, ok := ifCfg.Units[unitNum]; ok {
				vlanID = unit.VlanID
			}
		}
		logicals = append(logicals, logicalIface{
			zoneName: ifaceZoneName[ifName],
			zone:     zone,
			physName: physName,
			unitNum:  unitNum,
			vlanID:   vlanID,
		})
	}

	if len(logicals) == 0 && filterName != "" {
		return &pb.ShowInterfacesDetailResponse{Output: fmt.Sprintf("interface %s not found in configuration\n", filterName)}, nil
	}

	// Group by physical interface
	physGroups := make(map[string][]logicalIface)
	var physOrder []string
	for _, li := range logicals {
		if _, seen := physGroups[li.physName]; !seen {
			physOrder = append(physOrder, li.physName)
		}
		physGroups[li.physName] = append(physGroups[li.physName], li)
	}
	sort.Strings(physOrder)

	var buf strings.Builder
	for _, physName := range physOrder {
		group := physGroups[physName]

		iface, ifErr := net.InterfaceByName(physName)
		if ifErr != nil {
			fmt.Fprintf(&buf, "Physical interface: %s, Not present\n\n", physName)
			continue
		}

		// Determine link state
		linkUp := "Down"
		enabled := "Enabled"
		if iface.Flags&net.FlagUp != 0 {
			linkUp = "Up"
		}
		if iface.Flags&net.FlagUp == 0 {
			enabled = "Disabled"
		}
		// Try /sys/class/net for operstate
		if data, err := os.ReadFile("/sys/class/net/" + physName + "/operstate"); err == nil {
			state := strings.TrimSpace(string(data))
			if state == "up" {
				linkUp = "Up"
			} else if state == "down" {
				linkUp = "Down"
			}
		}

		fmt.Fprintf(&buf, "Physical interface: %s, %s, Physical link is %s\n", physName, enabled, linkUp)

		// Show interface description and configured speed/duplex from config
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
			if ifCfg.Description != "" {
				fmt.Fprintf(&buf, "  Description: %s\n", ifCfg.Description)
			}
			if ifCfg.Speed != "" {
				fmt.Fprintf(&buf, "  Configured speed: %s\n", ifCfg.Speed)
			}
			if ifCfg.Duplex != "" {
				fmt.Fprintf(&buf, "  Configured duplex: %s\n", ifCfg.Duplex)
			}
		}

		// Link-level details
		mtu := iface.MTU
		linkType := "Ethernet"
		var linkExtras []string
		if raw, err := os.ReadFile("/sys/class/net/" + physName + "/speed"); err == nil {
			var mbps int
			if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &mbps); err == nil && mbps > 0 {
				if mbps >= 1000 {
					linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dGbps", mbps/1000))
				} else {
					linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dMbps", mbps))
				}
			}
		}
		if raw, err := os.ReadFile("/sys/class/net/" + physName + "/duplex"); err == nil {
			d := strings.TrimSpace(string(raw))
			if d == "full" {
				linkExtras = append(linkExtras, "Link-mode: Full-duplex")
			} else if d == "half" {
				linkExtras = append(linkExtras, "Link-mode: Half-duplex")
			}
		}
		speedStr := ""
		if len(linkExtras) > 0 {
			speedStr = ", " + strings.Join(linkExtras, ", ")
		}
		fmt.Fprintf(&buf, "  Link-level type: %s, MTU: %d%s\n", linkType, mtu, speedStr)

		if len(iface.HardwareAddr) > 0 {
			fmt.Fprintf(&buf, "  Current address: %s, Hardware address: %s\n", iface.HardwareAddr, iface.HardwareAddr)
		}

		// Device flags
		var flags []string
		flags = append(flags, "Present")
		if linkUp == "Up" {
			flags = append(flags, "Running")
		}
		if linkUp == "Down" {
			flags = append(flags, "Down")
		}
		fmt.Fprintf(&buf, "  Device flags   : %s\n", strings.Join(flags, " "))

		// VLAN tagging
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok && ifCfg.VlanTagging {
			fmt.Fprintln(&buf, "  VLAN tagging: Enabled")
		}

		// Kernel link statistics via /sys/class/net
		s.writeKernelStats(&buf, physName)

		// BPF traffic counters
		if s.dp != nil && s.dp.IsLoaded() {
			if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Fprintln(&buf, "  BPF statistics:")
				fmt.Fprintf(&buf, "    Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Fprintf(&buf, "    Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}

		// Show each logical unit
		for _, li := range group {
			lookupName := physName
			if li.vlanID > 0 {
				lookupName = fmt.Sprintf("%s.%d", physName, li.vlanID)
			}

			fmt.Fprintf(&buf, "\n  Logical interface %s.%d", physName, li.unitNum)
			if li.vlanID > 0 {
				fmt.Fprintf(&buf, " VLAN-Tag [ 0x8100.%d ]", li.vlanID)
			}
			fmt.Fprintln(&buf)

			// Show unit description
			if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
				if u, ok := ifCfg.Units[li.unitNum]; ok && u.Description != "" {
					fmt.Fprintf(&buf, "    Description: %s\n", u.Description)
				}
			}

			fmt.Fprintf(&buf, "    Security: Zone: %s\n", li.zoneName)

			// Host-inbound traffic services
			if li.zone != nil && li.zone.HostInboundTraffic != nil {
				hit := li.zone.HostInboundTraffic
				if len(hit.SystemServices) > 0 {
					fmt.Fprintf(&buf, "    Allowed host-inbound traffic : %s\n", strings.Join(hit.SystemServices, " "))
				}
				if len(hit.Protocols) > 0 {
					fmt.Fprintf(&buf, "    Allowed host-inbound protocols: %s\n", strings.Join(hit.Protocols, " "))
				}
			}

			// DHCP annotations
			var unit *config.InterfaceUnit
			if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
				if u, ok := ifCfg.Units[li.unitNum]; ok {
					unit = u
				}
			}
			if unit != nil {
				if unit.DHCP {
					fmt.Fprintln(&buf, "    DHCPv4: enabled")
					if s.dhcp != nil {
						if lease := s.dhcp.LeaseFor(physName, dhcp.AFInet); lease != nil {
							fmt.Fprintf(&buf, "      Address: %s, Gateway: %s\n", lease.Address, lease.Gateway)
						}
					}
				}
				if unit.DHCPv6 {
					duidInfo := ""
					if unit.DHCPv6Client != nil && unit.DHCPv6Client.DUIDType != "" {
						duidInfo = fmt.Sprintf(" (DUID type: %s)", unit.DHCPv6Client.DUIDType)
					}
					fmt.Fprintf(&buf, "    DHCPv6: enabled%s\n", duidInfo)
					if s.dhcp != nil {
						if lease := s.dhcp.LeaseFor(physName, dhcp.AFInet6); lease != nil {
							fmt.Fprintf(&buf, "      Address: %s, Gateway: %s\n", lease.Address, lease.Gateway)
						}
					}
				}
			}

			// Addresses grouped by protocol
			liface, _ := net.InterfaceByName(lookupName)
			if liface == nil {
				liface = iface
			}
			if liface != nil {
				addrs, err := liface.Addrs()
				if err == nil && len(addrs) > 0 {
					var v4Addrs, v6Addrs []string
					for _, addr := range addrs {
						a := addr.String()
						ip, _, err := net.ParseCIDR(a)
						if err != nil {
							continue
						}
						if ip.To4() != nil {
							v4Addrs = append(v4Addrs, a)
						} else {
							v6Addrs = append(v6Addrs, a)
						}
					}
					if len(v4Addrs) > 0 {
						fmt.Fprintf(&buf, "    Protocol inet, MTU: %d\n", mtu)
						for _, a := range v4Addrs {
							fmt.Fprintln(&buf, "      Addresses, Flags: Is-Preferred Is-Primary")
							fmt.Fprintf(&buf, "        Local: %s\n", a)
						}
					}
					if len(v6Addrs) > 0 {
						fmt.Fprintf(&buf, "    Protocol inet6, MTU: %d\n", mtu)
						for _, a := range v6Addrs {
							fl := "Is-Preferred Is-Primary"
							if strings.HasPrefix(a, "fe80:") {
								fl = "Is-Preferred"
							}
							fmt.Fprintf(&buf, "      Addresses, Flags: %s\n", fl)
							fmt.Fprintf(&buf, "        Local: %s\n", a)
						}
					}
				}
			}
		}

		fmt.Fprintln(&buf)
	}

	return &pb.ShowInterfacesDetailResponse{Output: buf.String()}, nil
}

func (s *Server) showInterfacesTerse(cfg *config.Config, filterName string) (*pb.ShowInterfacesDetailResponse, error) {
	// Build zone mapping: interface name -> zone name
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifaceZoneName[ifName] = name
		}
	}

	// Build RETH mappings
	physToReth := make(map[string]string) // physical member → reth parent
	rethToPhys := cfg.RethToPhysical()    // reth → physical member
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg.RedundantParent != "" {
			physToReth[ifCfg.Name] = ifCfg.RedundantParent
		}
	}

	// Collect all configured interfaces with units
	type ifUnit struct {
		physName string
		unitNum  int
		vlanID   int
	}
	var units []ifUnit
	seen := make(map[string]bool)
	for physName, ifCfg := range cfg.Interfaces.Interfaces {
		if filterName != "" && !strings.HasPrefix(physName, filterName) {
			continue
		}
		seen[physName] = true
		if rethName, ok := physToReth[physName]; ok {
			// Physical RETH member: inherit units from RETH parent
			if rethCfg, ok := cfg.Interfaces.Interfaces[rethName]; ok {
				for unitNum, unit := range rethCfg.Units {
					units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
				}
			}
		} else {
			for unitNum, unit := range ifCfg.Units {
				units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
			}
		}
	}
	// Also include zone-only interfaces not in interfaces config
	for ifName := range ifaceZoneName {
		parts := strings.SplitN(ifName, ".", 2)
		physName := parts[0]
		if filterName != "" && !strings.HasPrefix(physName, filterName) {
			continue
		}
		if !seen[physName] {
			seen[physName] = true
			unitNum := 0
			if len(parts) == 2 {
				fmt.Sscanf(parts[1], "%d", &unitNum)
			}
			units = append(units, ifUnit{physName: physName, unitNum: unitNum})
		}
	}

	// Add peer node interfaces (cluster mode).
	// Peer interfaces don't exist locally — compile the peer's config from the
	// raw tree and extract interfaces not in our compiled config.
	peerIfaces := make(map[string]bool) // peer-only interface names
	peerLinkUp := make(map[string]bool) // peer interface link status from heartbeat
	if s.cluster != nil {
		// Determine peer node ID.
		peerNodeID := -1
		if s.cluster.PeerAlive() {
			peerNodeID = s.cluster.PeerNodeID()
		} else if cfg.Chassis.Cluster != nil {
			// Derive from config: find the other node in any RG.
			localID := s.cluster.NodeID()
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				for nid := range rg.NodePriorities {
					if nid != localID {
						peerNodeID = nid
						break
					}
				}
				if peerNodeID >= 0 {
					break
				}
			}
		}
		if peerNodeID >= 0 {
			// Build peer monitor status map.
			if peerMons := s.cluster.PeerMonitorStatuses(); peerMons != nil {
				for _, pm := range peerMons {
					peerLinkUp[pm.Interface] = pm.Up
				}
			}
			tree := s.store.ActiveTree()
			if tree != nil {
				peerCfg, err := config.CompileConfigForNode(tree, peerNodeID)
				if err == nil {
					for physName, ifCfg := range peerCfg.Interfaces.Interfaces {
						if _, isLocal := cfg.Interfaces.Interfaces[physName]; isLocal {
							continue // shared (reth, fxp, fab, etc.)
						}
						if filterName != "" && !strings.HasPrefix(physName, filterName) {
							continue
						}
						peerIfaces[physName] = true
						if ifCfg.RedundantParent != "" {
							physToReth[physName] = ifCfg.RedundantParent
							if rethCfg, ok := peerCfg.Interfaces.Interfaces[ifCfg.RedundantParent]; ok {
								for unitNum, unit := range rethCfg.Units {
									units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
								}
							}
						} else {
							for unitNum, unit := range ifCfg.Units {
								units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
							}
						}
					}
				}
			}
		}
	}

	// Sort by physical name then unit number
	sort.Slice(units, func(i, j int) bool {
		if units[i].physName != units[j].physName {
			return units[i].physName < units[j].physName
		}
		return units[i].unitNum < units[j].unitNum
	})

	var buf strings.Builder
	fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%-22s\n", "Interface", "Admin", "Link", "Proto", "Local")

	// Track which physical interfaces we've printed
	printedPhys := make(map[string]bool)

	for _, u := range units {
		isPeer := peerIfaces[u.physName]

		// Print the physical interface line if not printed yet
		if !printedPhys[u.physName] {
			printedPhys[u.physName] = true
			admin := "up"
			link := "up"
			if isPeer {
				// Peer interface: use heartbeat monitor data.
				if up, ok := peerLinkUp[u.physName]; ok {
					if !up {
						link = "down"
					}
				} else if s.cluster != nil && !s.cluster.PeerAlive() {
					link = "down"
				}
			} else {
				// Local interface: query kernel.
				// For RETH interfaces, get status from physical member
				statusIf := u.physName
				if phys, ok := rethToPhys[u.physName]; ok {
					statusIf = phys
				}
				kernelIf := config.LinuxIfName(statusIf)
				iface, err := net.InterfaceByName(kernelIf)
				if err != nil {
					link = "down"
				} else {
					if iface.Flags&net.FlagUp == 0 {
						admin = "down"
					}
					data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate")
					if err == nil {
						state := strings.TrimSpace(string(data))
						if state != "up" {
							link = "down"
						}
					}
				}
			}
			// Show description if configured
			desc := ""
			if ifCfg, ok := cfg.Interfaces.Interfaces[u.physName]; ok && ifCfg.Description != "" {
				desc = ifCfg.Description
			}
			if desc != "" {
				fmt.Fprintf(&buf, "%-24s%-6s%-6s%s\n", u.physName, admin, link, desc)
			} else {
				fmt.Fprintf(&buf, "%-24s%-6s%-6s\n", u.physName, admin, link)
			}
		}

		// Determine the logical interface name
		logicalName := fmt.Sprintf("%s.%d", u.physName, u.unitNum)

		// Physical RETH member: show aenet --> rethN.M
		if rethName, ok := physToReth[u.physName]; ok {
			admin := "up"
			link := "up"
			if isPeer {
				if up, ok := peerLinkUp[u.physName]; ok {
					if !up {
						link = "down"
					}
				} else if s.cluster != nil && !s.cluster.PeerAlive() {
					link = "down"
				}
			} else {
				kernelIf := config.LinuxIfName(u.physName)
				iface, err := net.InterfaceByName(kernelIf)
				if err != nil {
					link = "down"
				} else {
					if iface.Flags&net.FlagUp == 0 {
						admin = "down"
					}
					data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate")
					if err == nil && strings.TrimSpace(string(data)) != "up" {
						link = "down"
					}
				}
			}
			rethLogical := fmt.Sprintf("%s.%d", rethName, u.unitNum)
			fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%s\n", logicalName, admin, link, "aenet", "--> "+rethLogical)
			continue
		}

		// RETH interface: get addresses from config, status from physical member
		if physMember, ok := rethToPhys[u.physName]; ok {
			var v4Addrs, v6Addrs []string
			if ifCfg, ok := cfg.Interfaces.Interfaces[u.physName]; ok {
				if unit, ok := ifCfg.Units[u.unitNum]; ok {
					for _, addr := range unit.Addresses {
						ip, _, err := net.ParseCIDR(addr)
						if err != nil {
							continue
						}
						if ip.To4() != nil {
							v4Addrs = append(v4Addrs, addr)
						} else {
							v6Addrs = append(v6Addrs, addr)
						}
					}
				}
			}
			admin := "up"
			link := "up"
			kernelPhys := config.LinuxIfName(physMember)
			iface, err := net.InterfaceByName(kernelPhys)
			if err != nil {
				link = "down"
			} else {
				if iface.Flags&net.FlagUp == 0 {
					admin = "down"
				}
				data, err := os.ReadFile("/sys/class/net/" + kernelPhys + "/operstate")
				if err == nil && strings.TrimSpace(string(data)) != "up" {
					link = "down"
				}
			}
			firstProto := ""
			firstAddr := ""
			if len(v4Addrs) > 0 {
				firstProto = "inet"
				firstAddr = v4Addrs[0]
			} else if len(v6Addrs) > 0 {
				firstProto = "inet6"
				firstAddr = v6Addrs[0]
			}
			fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)
			for i := 1; i < len(v4Addrs); i++ {
				fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet", v4Addrs[i])
			}
			startIdx := 0
			if firstProto == "inet6" {
				startIdx = 1
			}
			for i := startIdx; i < len(v6Addrs); i++ {
				fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
			}
			continue
		}

		// Normal interface: get addresses from kernel
		lookupName := config.LinuxIfName(u.physName)
		if u.vlanID > 0 {
			lookupName = fmt.Sprintf("%s.%d", config.LinuxIfName(u.physName), u.vlanID)
		}

		var v4Addrs, v6Addrs []string
		liface, err := net.InterfaceByName(lookupName)
		if err != nil {
			// Try the physical interface for unit 0
			liface, err = net.InterfaceByName(config.LinuxIfName(u.physName))
		}
		if err == nil {
			addrs, _ := liface.Addrs()
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ones, _ := ipNet.Mask.Size()
				addrStr := fmt.Sprintf("%s/%d", ipNet.IP, ones)
				if ipNet.IP.To4() != nil {
					v4Addrs = append(v4Addrs, addrStr)
				} else {
					v6Addrs = append(v6Addrs, addrStr)
				}
			}
		}

		admin := "up"
		link := "up"
		if liface == nil {
			link = "down"
		} else {
			if liface.Flags&net.FlagUp == 0 {
				admin = "down"
			}
		}

		firstProto := ""
		firstAddr := ""
		if len(v4Addrs) > 0 {
			firstProto = "inet"
			firstAddr = v4Addrs[0]
		} else if len(v6Addrs) > 0 {
			firstProto = "inet6"
			firstAddr = v6Addrs[0]
		}

		fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)

		if len(v4Addrs) > 1 {
			for _, a := range v4Addrs[1:] {
				fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet", a)
			}
		}

		startIdx := 0
		if firstProto == "inet6" {
			startIdx = 1
		}
		if firstProto == "inet" {
			startIdx = 0
		}
		for i := startIdx; i < len(v6Addrs); i++ {
			fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
		}
	}

	return &pb.ShowInterfacesDetailResponse{Output: buf.String()}, nil
}

func (s *Server) writeKernelStats(buf *strings.Builder, ifaceName string) {
	readStat := func(name string) uint64 {
		data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/%s", ifaceName, name))
		if err != nil {
			return 0
		}
		var v uint64
		fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &v)
		return v
	}
	rxPkts := readStat("rx_packets")
	rxBytes := readStat("rx_bytes")
	txPkts := readStat("tx_packets")
	txBytes := readStat("tx_bytes")
	fmt.Fprintf(buf, "  Input rate     : %d packets, %d bytes\n", rxPkts, rxBytes)
	fmt.Fprintf(buf, "  Output rate    : %d packets, %d bytes\n", txPkts, txBytes)
	rxErr := readStat("rx_errors")
	txErr := readStat("tx_errors")
	if rxErr > 0 || txErr > 0 {
		fmt.Fprintf(buf, "  Errors         : %d input, %d output\n", rxErr, txErr)
	}
	rxDrop := readStat("rx_dropped")
	txDrop := readStat("tx_dropped")
	if rxDrop > 0 || txDrop > 0 {
		fmt.Fprintf(buf, "  Drops          : %d input, %d output\n", rxDrop, txDrop)
	}
}
