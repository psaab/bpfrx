package cli

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
)

func (c *CLI) showTunnelInterfaces() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	tunnels, err := c.routing.GetTunnelStatus()
	if err != nil {
		return fmt.Errorf("tunnel status: %w", err)
	}

	if len(tunnels) == 0 {
		fmt.Println("No tunnel interfaces")
		return nil
	}

	for _, t := range tunnels {
		fmt.Printf("Tunnel interface: %s\n", t.Name)
		fmt.Printf("  State: %s\n", t.State)
		if t.Source != "" {
			fmt.Printf("  Source: %s\n", t.Source)
		}
		if t.Destination != "" {
			fmt.Printf("  Destination: %s\n", t.Destination)
		}
		for _, addr := range t.Addresses {
			fmt.Printf("  Address: %s\n", addr)
		}
		if t.KeepaliveInfo != "" {
			fmt.Printf("  Keepalive: %s\n", t.KeepaliveInfo)
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showInterfaces(args []string) error {
	// Handle "show interfaces tunnel" sub-command
	if len(args) > 0 && args[0] == "tunnel" {
		return c.showTunnelInterfaces()
	}

	// Handle "show interfaces terse" sub-command
	if len(args) > 0 && args[0] == "terse" {
		return c.showInterfacesTerse()
	}
	// Handle "show interfaces detail" sub-command
	if len(args) > 0 && args[0] == "detail" {
		return c.showInterfacesDetail("")
	}
	// Handle "show interfaces extensive" sub-command
	if len(args) > 0 && args[0] == "extensive" {
		return c.showInterfacesExtensive()
	}
	// Handle "show interfaces statistics" sub-command
	if len(args) > 0 && args[0] == "statistics" {
		return c.showInterfacesStatistics()
	}

	// Handle "show interfaces <name> detail"
	if len(args) >= 2 && args[len(args)-1] == "detail" {
		return c.showInterfacesDetail(args[0])
	}
	// Handle "show interfaces <name> extensive"
	if len(args) >= 2 && args[len(args)-1] == "extensive" {
		return c.showInterfacesExtensiveFiltered(args[0])
	}

	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	// Optional filter by interface name
	var filterName string
	if len(args) > 0 {
		filterName = args[0]
	}

	// Build interface -> zone mapping
	ifaceZone := make(map[string]*config.ZoneConfig)
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifaceName := range zone.Interfaces {
			ifaceZone[ifaceName] = zone
			ifaceZoneName[ifaceName] = name
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

	for ifaceName, zone := range ifaceZone {
		if filterName != "" && !strings.HasPrefix(ifaceName, filterName) {
			continue
		}
		parts := strings.SplitN(ifaceName, ".", 2)
		physName := parts[0]
		unitNum := 0
		if len(parts) == 2 {
			unitNum, _ = strconv.Atoi(parts[1])
		}
		vlanID := 0
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
			if unit, ok := ifCfg.Units[unitNum]; ok {
				vlanID = unit.VlanID
			}
		}
		logicals = append(logicals, logicalIface{
			zoneName: ifaceZoneName[ifaceName],
			zone:     zone,
			physName: physName,
			unitNum:  unitNum,
			vlanID:   vlanID,
		})
	}

	if len(logicals) == 0 && filterName != "" {
		return fmt.Errorf("interface %s not found in configuration", filterName)
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

	for _, physName := range physOrder {
		group := physGroups[physName]

		// Get netlink link for richer info
		link, nlErr := netlink.LinkByName(physName)

		// Fallback to net.InterfaceByName if netlink fails
		iface, stdErr := net.InterfaceByName(physName)
		if stdErr != nil && nlErr != nil {
			fmt.Printf("Physical interface: %s, Not present\n\n", physName)
			continue
		}

		// Determine link state
		linkUp := "Down"
		enabled := "Enabled"
		if nlErr == nil {
			attrs := link.Attrs()
			if attrs.OperState == netlink.OperUp {
				linkUp = "Up"
			}
			if attrs.Flags&net.FlagUp == 0 {
				enabled = "Disabled"
			}
		} else if iface != nil {
			if iface.Flags&net.FlagUp != 0 {
				linkUp = "Up"
			}
		}

		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n",
			physName, enabled, linkUp)
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok && ifCfg.Description != "" {
			fmt.Printf("  Description: %s\n", ifCfg.Description)
		}

		// Link-level details
		mtu := 0
		var hwAddr net.HardwareAddr
		if nlErr == nil {
			attrs := link.Attrs()
			mtu = attrs.MTU
			hwAddr = attrs.HardwareAddr
		} else if iface != nil {
			mtu = iface.MTU
			hwAddr = iface.HardwareAddr
		}

		linkType := "Ethernet"
		var linkDetails []string
		if speed := readLinkSpeed(physName); speed > 0 {
			linkDetails = append(linkDetails, "Speed: "+formatSpeed(speed))
		}
		if duplex := readLinkDuplex(physName); duplex != "" {
			linkDetails = append(linkDetails, "Link-mode: "+formatDuplex(duplex))
		}
		extra := ""
		if len(linkDetails) > 0 {
			extra = ", " + strings.Join(linkDetails, ", ")
		}

		fmt.Printf("  Link-level type: %s, MTU: %d%s\n", linkType, mtu, extra)

		if len(hwAddr) > 0 {
			fmt.Printf("  Current address: %s, Hardware address: %s\n", hwAddr, hwAddr)
		}

		// Device flags
		if nlErr == nil {
			attrs := link.Attrs()
			var flags []string
			flags = append(flags, "Present")
			if attrs.OperState == netlink.OperUp {
				flags = append(flags, "Running")
			}
			if linkUp == "Down" {
				flags = append(flags, "Down")
			}
			fmt.Printf("  Device flags   : %s\n", strings.Join(flags, " "))
		}

		// VLAN tagging
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok && ifCfg.VlanTagging {
			fmt.Println("  VLAN tagging: Enabled")
		}

		// Kernel link statistics
		if nlErr == nil {
			attrs := link.Attrs()
			if s := attrs.Statistics; s != nil {
				fmt.Printf("  Input rate     : %d packets, %d bytes\n",
					s.RxPackets, s.RxBytes)
				fmt.Printf("  Output rate    : %d packets, %d bytes\n",
					s.TxPackets, s.TxBytes)
				if s.RxErrors > 0 || s.TxErrors > 0 {
					fmt.Printf("  Errors         : %d input, %d output\n",
						s.RxErrors, s.TxErrors)
				}
				if s.RxDropped > 0 || s.TxDropped > 0 {
					fmt.Printf("  Drops          : %d input, %d output\n",
						s.RxDropped, s.TxDropped)
				}
			}
		}

		// BPF traffic counters (XDP/TC level)
		if c.dp != nil && c.dp.IsLoaded() && iface != nil {
			counters, err := c.dp.ReadInterfaceCounters(iface.Index)
			if err == nil && (counters.RxPackets > 0 || counters.TxPackets > 0) {
				fmt.Println("  BPF statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n",
					counters.RxPackets, counters.RxBytes)
				fmt.Printf("    Output: %d packets, %d bytes\n",
					counters.TxPackets, counters.TxBytes)
			}
		}

		// Show each logical unit
		for _, li := range group {
			lookupName := physName
			if li.vlanID > 0 {
				lookupName = fmt.Sprintf("%s.%d", physName, li.vlanID)
			}

			fmt.Printf("\n  Logical interface %s.%d", physName, li.unitNum)
			if li.vlanID > 0 {
				fmt.Printf(" VLAN-Tag [ 0x8100.%d ]", li.vlanID)
			}
			fmt.Println()

			fmt.Printf("    Security: Zone: %s\n", li.zoneName)

			// Host-inbound traffic services
			if li.zone != nil && li.zone.HostInboundTraffic != nil {
				hit := li.zone.HostInboundTraffic
				if len(hit.SystemServices) > 0 {
					fmt.Printf("    Allowed host-inbound traffic : %s\n",
						strings.Join(hit.SystemServices, " "))
				}
				if len(hit.Protocols) > 0 {
					fmt.Printf("    Allowed host-inbound protocols: %s\n",
						strings.Join(hit.Protocols, " "))
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
					fmt.Println("    DHCPv4: enabled")
					if lease := c.dhcpLease(physName, dhcp.AFInet); lease != nil {
						fmt.Printf("      Address: %s, Gateway: %s\n",
							lease.Address, lease.Gateway)
					}
				}
				if unit.DHCPv6 {
					duidInfo := ""
					if unit.DHCPv6Client != nil && unit.DHCPv6Client.DUIDType != "" {
						duidInfo = fmt.Sprintf(" (DUID type: %s)", unit.DHCPv6Client.DUIDType)
					}
					fmt.Printf("    DHCPv6: enabled%s\n", duidInfo)
					if lease := c.dhcpLease(physName, dhcp.AFInet6); lease != nil {
						fmt.Printf("      Address: %s, Gateway: %s\n",
							lease.Address, lease.Gateway)
					}
				}
			}

			// Addresses grouped by protocol
			liface, err := net.InterfaceByName(lookupName)
			if err != nil && iface != nil {
				liface = iface
			}
			if liface != nil {
				addrs, err := liface.Addrs()
				if err == nil && len(addrs) > 0 {
					var v4Addrs, v6Addrs []string
					for _, addr := range addrs {
						ipNet, ok := addr.(*net.IPNet)
						if !ok {
							continue
						}
						ones, _ := ipNet.Mask.Size()
						if ipNet.IP.To4() != nil {
							v4Addrs = append(v4Addrs, fmt.Sprintf("%s/%d", ipNet.IP, ones))
						} else {
							v6Addrs = append(v6Addrs, fmt.Sprintf("%s/%d", ipNet.IP, ones))
						}
					}
					if len(v4Addrs) > 0 {
						fmt.Printf("    Protocol inet, MTU: %d\n", mtu)
						for _, a := range v4Addrs {
							fmt.Printf("      Addresses, Flags: Is-Preferred Is-Primary\n")
							fmt.Printf("        Local: %s\n", a)
						}
					}
					if len(v6Addrs) > 0 {
						fmt.Printf("    Protocol inet6, MTU: %d\n", mtu)
						for _, a := range v6Addrs {
							flags := "Is-Preferred Is-Primary"
							if strings.HasPrefix(a, "fe80:") {
								flags = "Is-Preferred"
							}
							fmt.Printf("      Addresses, Flags: %s\n", flags)
							fmt.Printf("        Local: %s\n", a)
						}
					}
				}
			}
		}

		fmt.Println()
	}

	return nil
}

// dhcpLease returns the DHCP lease for an interface/family, or nil.

func (c *CLI) showInterfacesDetail(filterName string) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	// Build zone + description lookup from active config
	ifZoneMap := make(map[string]string)
	ifDescMap := make(map[string]string)
	if activeCfg := c.store.ActiveConfig(); activeCfg != nil {
		for _, z := range activeCfg.Security.Zones {
			for _, ifName := range z.Interfaces {
				ifZoneMap[ifName] = z.Name
			}
		}
		for _, ifc := range activeCfg.Interfaces.Interfaces {
			if ifc.Description != "" {
				ifDescMap[ifc.Name] = ifc.Description
			}
		}
	}

	found := false
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		if filterName != "" && attrs.Name != filterName {
			continue
		}
		found = true

		adminUp := attrs.Flags&net.FlagUp != 0
		operUp := attrs.OperState == netlink.OperUp
		adminStr := "Disabled"
		if adminUp {
			adminStr = "Enabled"
		}
		linkStr := "Down"
		if operUp {
			linkStr = "Up"
		}
		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n", attrs.Name, adminStr, linkStr)
		if desc, ok := ifDescMap[attrs.Name]; ok {
			fmt.Printf("  Description: %s\n", desc)
		}
		fmt.Printf("  Interface index: %d, SNMP ifIndex: %d\n", attrs.Index, attrs.Index)

		// Link type, MTU, speed, duplex
		linkType := "Ethernet"
		if attrs.EncapType != "" {
			linkType = attrs.EncapType
		}
		speedStr := ""
		if speed := readLinkSpeed(attrs.Name); speed > 0 {
			speedStr = ", Speed: " + formatSpeed(speed)
		}
		duplexStr := ""
		if d := readLinkDuplex(attrs.Name); d != "" {
			duplexStr = ", Duplex: " + formatDuplex(d)
		}
		fmt.Printf("  Link-level type: %s, MTU: %d%s%s\n", linkType, attrs.MTU, speedStr, duplexStr)

		if len(attrs.HardwareAddr) > 0 {
			fmt.Printf("  Current address: %s\n", attrs.HardwareAddr)
		}
		if zone, ok := ifZoneMap[attrs.Name]; ok {
			fmt.Printf("  Security zone: %s\n", zone)
		}

		// Logical interface with flags and addresses
		var flags []string
		if adminUp {
			flags = append(flags, "Up")
		}
		if attrs.RawFlags&0x2 != 0 { // IFF_BROADCAST
			flags = append(flags, "BROADCAST")
		}
		if attrs.OperState == netlink.OperUp {
			flags = append(flags, "RUNNING")
		}
		if attrs.RawFlags&0x1000 != 0 { // IFF_MULTICAST
			flags = append(flags, "MULTICAST")
		}
		fmt.Printf("  Logical interface %s.0\n", attrs.Name)
		if len(flags) > 0 {
			fmt.Printf("    Flags: %s\n", strings.Join(flags, " "))
		}

		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		if len(addrs) > 0 {
			fmt.Println("    Addresses:")
			for _, a := range addrs {
				fmt.Printf("      %s\n", a.IPNet)
			}
		}

		// Traffic statistics
		if s := attrs.Statistics; s != nil {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input  packets:             %12d\n", s.RxPackets)
			fmt.Printf("    Output packets:             %12d\n", s.TxPackets)
			fmt.Printf("    Input  bytes:               %12d\n", s.RxBytes)
			fmt.Printf("    Output bytes:               %12d\n", s.TxBytes)
			fmt.Printf("    Input  errors:              %12d\n", s.RxErrors)
			fmt.Printf("    Output errors:              %12d\n", s.TxErrors)
		}
		fmt.Println()
	}
	if filterName != "" && !found {
		fmt.Printf("Interface %s not found\n", filterName)
	}
	return nil
}

func (c *CLI) showInterfacesTerse() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	// Build RETH mappings
	physToReth := make(map[string]string) // physical member → reth parent
	rethToPhys := cfg.RethToPhysical()    // reth → physical member
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg.RedundantParent != "" {
			physToReth[ifCfg.Name] = ifCfg.RedundantParent
		}
	}

	type ifUnit struct {
		physName string
		unitNum  int
		vlanID   int
	}
	var units []ifUnit

	for physName, ifCfg := range cfg.Interfaces.Interfaces {
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

	// Add peer node interfaces (cluster mode).
	peerIfaces := make(map[string]bool)
	peerLinkUp := make(map[string]bool)
	if c.cluster != nil {
		peerNodeID := -1
		if c.cluster.PeerAlive() {
			peerNodeID = c.cluster.PeerNodeID()
		} else if cfg.Chassis.Cluster != nil {
			localID := c.cluster.NodeID()
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
			if peerMons := c.cluster.PeerMonitorStatuses(); peerMons != nil {
				for _, pm := range peerMons {
					peerLinkUp[pm.Interface] = pm.Up
				}
			}
			tree := c.store.ActiveTree()
			if tree != nil {
				peerCfg, err := config.CompileConfigForNode(tree, peerNodeID)
				if err == nil {
					for physName, ifCfg := range peerCfg.Interfaces.Interfaces {
						if _, isLocal := cfg.Interfaces.Interfaces[physName]; isLocal {
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

	sort.Slice(units, func(i, j int) bool {
		if units[i].physName != units[j].physName {
			return units[i].physName < units[j].physName
		}
		return units[i].unitNum < units[j].unitNum
	})

	fmt.Printf("%-24s%-6s%-6s%-9s%-22s\n", "Interface", "Admin", "Link", "Proto", "Local")

	printedPhys := make(map[string]bool)

	for _, u := range units {
		isPeer := peerIfaces[u.physName]

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
				} else if c.cluster != nil && !c.cluster.PeerAlive() {
					link = "down"
				}
			} else {
				// Local interface: query kernel.
				// Check config-level disable flag
				if ifCfg, ok := cfg.Interfaces.Interfaces[u.physName]; ok && ifCfg.Disable {
					admin = "down"
				}
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
						if admin == "up" {
							admin = "down" // kernel says down
						}
					}
					data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate")
					if err == nil && strings.TrimSpace(string(data)) != "up" {
						link = "down"
					}
				}
			}
			fmt.Printf("%-24s%-6s%-6s\n", u.physName, admin, link)
		}

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
				} else if c.cluster != nil && !c.cluster.PeerAlive() {
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
			fmt.Printf("%-24s%-6s%-6s%-9s%s\n", logicalName, admin, link, "aenet", "--> "+rethLogical)
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
			fmt.Printf("%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)
			for i := 1; i < len(v4Addrs); i++ {
				fmt.Printf("%-36s%-9s%-22s\n", "", "inet", v4Addrs[i])
			}
			startIdx := 0
			if firstProto == "inet6" {
				startIdx = 1
			}
			for i := startIdx; i < len(v6Addrs); i++ {
				fmt.Printf("%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
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
		} else if liface.Flags&net.FlagUp == 0 {
			admin = "down"
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

		fmt.Printf("%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)

		for i := 1; i < len(v4Addrs); i++ {
			fmt.Printf("%-36s%-9s%-22s\n", "", "inet", v4Addrs[i])
		}
		startIdx := 0
		if firstProto == "inet6" {
			startIdx = 1
		}
		for i := startIdx; i < len(v6Addrs); i++ {
			fmt.Printf("%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
		}
	}

	return nil
}

// showInterfacesExtensive shows detailed per-interface statistics including
// all error counters, queue depths, and ethtool-style information.

func (c *CLI) showInterfacesExtensive() error {
	return c.showInterfacesExtensiveFiltered("")
}

func (c *CLI) showInterfacesExtensiveFiltered(filterName string) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	// Build zone lookup from active config
	ifZoneMap := make(map[string]string)
	ifDescMap := make(map[string]string)
	ifCfgMap := make(map[string]*config.InterfaceConfig)
	if activeCfg := c.store.ActiveConfig(); activeCfg != nil {
		for _, z := range activeCfg.Security.Zones {
			for _, ifName := range z.Interfaces {
				ifZoneMap[ifName] = z.Name
			}
		}
		for _, ifc := range activeCfg.Interfaces.Interfaces {
			ifCfgMap[ifc.Name] = ifc
			if ifc.Description != "" {
				ifDescMap[ifc.Name] = ifc.Description
			}
		}
	}

	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		if filterName != "" && attrs.Name != filterName {
			continue
		}

		// State
		adminUp := attrs.Flags&net.FlagUp != 0
		operUp := attrs.OperState == netlink.OperUp
		adminStr := "Disabled"
		if adminUp {
			adminStr = "Enabled"
		}
		linkStr := "Down"
		if operUp {
			linkStr = "Up"
		}
		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n", attrs.Name, adminStr, linkStr)
		if desc, ok := ifDescMap[attrs.Name]; ok {
			fmt.Printf("  Description: %s\n", desc)
		}
		if zone, ok := ifZoneMap[attrs.Name]; ok {
			fmt.Printf("  Security zone: %s\n", zone)
		}
		if ifCfg, ok := ifCfgMap[attrs.Name]; ok {
			if ifCfg.Speed != "" {
				fmt.Printf("  Configured speed: %s\n", ifCfg.Speed)
			}
			if ifCfg.Duplex != "" {
				fmt.Printf("  Configured duplex: %s\n", ifCfg.Duplex)
			}
		}

		// Type + speed + MTU
		linkType := "Ethernet"
		if attrs.EncapType != "" {
			linkType = attrs.EncapType
		}
		var linkExtras []string
		if speed := readLinkSpeed(attrs.Name); speed > 0 {
			linkExtras = append(linkExtras, "Speed: "+formatSpeed(speed))
		}
		duplexStr := "Full-duplex"
		if duplex := readLinkDuplex(attrs.Name); duplex != "" {
			duplexStr = formatDuplex(duplex)
		}
		linkExtras = append(linkExtras, "Link-mode: "+duplexStr)
		fmt.Printf("  Link-level type: %s, MTU: %d, %s\n",
			linkType, attrs.MTU, strings.Join(linkExtras, ", "))

		// MAC
		if len(attrs.HardwareAddr) > 0 {
			fmt.Printf("  Current address: %s, Hardware address: %s\n",
				attrs.HardwareAddr, attrs.HardwareAddr)
		}

		// Device flags
		var flags []string
		flags = append(flags, "Present")
		if operUp {
			flags = append(flags, "Running")
		}
		if !adminUp {
			flags = append(flags, "Down")
		}
		fmt.Printf("  Device flags   : %s\n", strings.Join(flags, " "))
		fmt.Printf("  Interface index: %d, SNMP ifIndex: %d\n", attrs.Index, attrs.Index)

		if attrs.TxQLen > 0 {
			fmt.Printf("  Link type      : %s, TxQueueLen: %d\n", attrs.EncapType, attrs.TxQLen)
		}

		// Detailed statistics
		if s := attrs.Statistics; s != nil {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input:  %d bytes, %d packets\n", s.RxBytes, s.RxPackets)
			fmt.Printf("    Output: %d bytes, %d packets\n", s.TxBytes, s.TxPackets)
			fmt.Println("  Input errors:")
			fmt.Printf("    Errors: %d, Drops: %d, Overruns: %d, Frame: %d\n",
				s.RxErrors, s.RxDropped, s.RxOverErrors, s.RxFrameErrors)
			fmt.Printf("    FIFO errors: %d, Missed: %d, Compressed: %d\n",
				s.RxFifoErrors, s.RxMissedErrors, s.RxCompressed)
			fmt.Println("  Output errors:")
			fmt.Printf("    Errors: %d, Drops: %d, Carrier: %d, Collisions: %d\n",
				s.TxErrors, s.TxDropped, s.TxCarrierErrors, s.Collisions)
			fmt.Printf("    FIFO errors: %d, Heartbeat: %d, Compressed: %d\n",
				s.TxFifoErrors, s.TxHeartbeatErrors, s.TxCompressed)
			if s.Multicast > 0 {
				fmt.Printf("    Multicast: %d\n", s.Multicast)
			}
		}

		// BPF traffic counters (XDP/TC level)
		if c.dp != nil && c.dp.IsLoaded() {
			if ctrs, err := c.dp.ReadInterfaceCounters(attrs.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Println("  BPF statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Printf("    Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}

		// Addresses
		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		if len(addrs) > 0 {
			var v4, v6 []string
			for _, a := range addrs {
				if a.IP.To4() != nil {
					v4 = append(v4, a.IPNet.String())
				} else {
					v6 = append(v6, a.IPNet.String())
				}
			}
			if len(v4) > 0 {
				fmt.Printf("  Protocol inet, MTU: %d\n", attrs.MTU)
				for _, a := range v4 {
					fmt.Printf("    Local: %s\n", a)
				}
			}
			if len(v6) > 0 {
				fmt.Printf("  Protocol inet6, MTU: %d\n", attrs.MTU)
				for _, a := range v6 {
					flags := "Is-Preferred Is-Primary"
					if strings.HasPrefix(a, "fe80:") {
						flags = "Is-Preferred"
					}
					fmt.Printf("    Local: %s, Flags: %s\n", a, flags)
				}
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showInterfacesStatistics() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing links: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	fmt.Printf("%-16s %15s %15s %15s %15s %10s %10s\n",
		"Interface", "Input packets", "Input bytes", "Output packets", "Output bytes", "In errors", "Out errors")

	for _, l := range links {
		name := l.Attrs().Name
		if name == "lo" || strings.HasPrefix(name, "vrf-") ||
			strings.HasPrefix(name, "xfrm") || strings.HasPrefix(name, "gre-") {
			continue
		}
		stats := l.Attrs().Statistics
		if stats == nil {
			continue
		}
		fmt.Printf("%-16s %15d %15d %15d %15d %10d %10d\n",
			name, stats.RxPackets, stats.RxBytes, stats.TxPackets, stats.TxBytes,
			stats.RxErrors, stats.TxErrors)
	}
	return nil
}

// showVlans displays VLAN assignments per interface (like Junos "show vlans").

func (c *CLI) showVlans() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Build zone lookup: interface name → zone name
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		for _, iface := range zone.Interfaces {
			ifZone[iface] = zoneName
		}
	}

	// Collect VLAN entries
	type vlanEntry struct {
		iface  string
		unit   int
		vlanID int
		zone   string
		trunk  bool
	}
	var entries []vlanEntry
	for _, ifc := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifc.Units {
			if unit.VlanID > 0 || ifc.VlanTagging {
				zone := ifZone[ifc.Name]
				entries = append(entries, vlanEntry{
					iface:  ifc.Name,
					unit:   unitNum,
					vlanID: unit.VlanID,
					zone:   zone,
					trunk:  ifc.VlanTagging,
				})
			}
		}
	}

	if len(entries) == 0 {
		fmt.Println("No VLANs configured")
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].iface != entries[j].iface {
			return entries[i].iface < entries[j].iface
		}
		return entries[i].unit < entries[j].unit
	})

	fmt.Printf("%-16s %-6s %-8s %-12s %s\n", "Interface", "Unit", "VLAN ID", "Zone", "Mode")
	for _, e := range entries {
		mode := "access"
		if e.trunk {
			mode = "trunk"
		}
		vid := fmt.Sprintf("%d", e.vlanID)
		if e.vlanID == 0 {
			vid = "native"
		}
		fmt.Printf("%-16s %-6d %-8s %-12s %s\n", e.iface, e.unit, vid, e.zone, mode)
	}
	return nil
}
