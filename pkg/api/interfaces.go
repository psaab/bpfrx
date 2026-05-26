package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

func (s *Server) interfacesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []InterfaceStats{})
		return
	}

	// Build interface->zone map
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	var result []InterfaceStats
	for ifName := range allInterfaceNames(cfg) {
		iface, err := net.InterfaceByName(ifName)
		is := InterfaceStats{
			Name: ifName,
			Zone: ifZone[ifName],
		}
		if err == nil {
			is.Ifindex = iface.Index
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil {
					is.RxPackets = ctrs.RxPackets
					is.RxBytes = ctrs.RxBytes
					is.TxPackets = ctrs.TxPackets
					is.TxBytes = ctrs.TxBytes
				}
			}
		}
		result = append(result, is)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) interfacesDetailHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, TextResponse{Output: "no active configuration\n"})
		return
	}

	filterName := r.URL.Query().Get("filter")
	terse := r.URL.Query().Get("terse") == "true"

	if terse {
		s.writeInterfacesTerse(w, cfg, filterName)
		return
	}

	s.writeInterfacesDetail(w, cfg, filterName)
}

func (s *Server) writeInterfacesTerse(w http.ResponseWriter, cfg *config.Config, filterName string) {
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

	var b strings.Builder
	fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", "Interface", "Admin", "Link", "Addresses")

	var ifNames []string
	for ifName := range allInterfaceNames(cfg) {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		baseName := strings.SplitN(ifName, ".", 2)[0]

		// Physical RETH member: show aenet --> rethN[.M]
		if rethName, ok := physToReth[baseName]; ok {
			kernelIf := config.LinuxIfName(baseName)
			iface, err := net.InterfaceByName(kernelIf)
			admin, link := "down", "down"
			if err == nil {
				if iface.Flags&net.FlagUp != 0 {
					admin = "up"
				}
				if data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate"); err == nil {
					if strings.TrimSpace(string(data)) == "up" {
						link = "up"
					}
				}
			}
			aenetTarget := rethName
			if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
				aenetTarget = rethName + "." + parts[1]
			}
			fmt.Fprintf(&b, "%-20s %-10s %-10s aenet --> %s\n", ifName, admin, link, aenetTarget)
			continue
		}

		// RETH interface: get addresses from config, status from physical member
		if physMember, ok := rethToPhys[baseName]; ok {
			kernelPhys := config.LinuxIfName(physMember)
			iface, err := net.InterfaceByName(kernelPhys)
			admin, link := "down", "down"
			if err == nil {
				if iface.Flags&net.FlagUp != 0 {
					admin = "up"
				}
				if data, err := os.ReadFile("/sys/class/net/" + kernelPhys + "/operstate"); err == nil {
					if strings.TrimSpace(string(data)) == "up" {
						link = "up"
					}
				}
			}
			var addrs []string
			if ifCfg, ok := cfg.Interfaces.Interfaces[baseName]; ok {
				// Determine which unit to look up
				unitNum := 0
				if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
					fmt.Sscanf(parts[1], "%d", &unitNum)
				}
				if unit, ok := ifCfg.Units[unitNum]; ok {
					addrs = append(addrs, unit.Addresses...)
				}
			}
			addrStr := strings.Join(addrs, ", ")
			if addrStr == "" {
				addrStr = "-"
			}
			fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", ifName, admin, link, addrStr)
			continue
		}

		// Normal interface: get addresses from kernel
		kernelName := config.LinuxIfName(ifName)
		iface, err := net.InterfaceByName(kernelName)
		admin, link := "down", "down"
		var addrs []string
		if err == nil {
			if iface.Flags&net.FlagUp != 0 {
				admin = "up"
			}
			if data, err := os.ReadFile("/sys/class/net/" + kernelName + "/operstate"); err == nil {
				if strings.TrimSpace(string(data)) == "up" {
					link = "up"
				}
			}
			if ifAddrs, err := iface.Addrs(); err == nil {
				for _, a := range ifAddrs {
					addrs = append(addrs, a.String())
				}
			}
		}
		addrStr := strings.Join(addrs, ", ")
		if addrStr == "" {
			addrStr = "-"
		}
		fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", ifName, admin, link, addrStr)
	}

	writeOK(w, TextResponse{Output: b.String()})
}

func (s *Server) writeInterfacesDetail(w http.ResponseWriter, cfg *config.Config, filterName string) {
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifaceZoneName[ifName] = name
		}
	}

	var b strings.Builder
	var ifNames []string
	for ifName := range allInterfaceNames(cfg) {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			fmt.Fprintf(&b, "Interface: %s, Not present\n\n", ifName)
			continue
		}

		linkUp := "Down"
		if iface.Flags&net.FlagUp != 0 {
			linkUp = "Up"
		}
		if data, err := os.ReadFile("/sys/class/net/" + ifName + "/operstate"); err == nil {
			if strings.TrimSpace(string(data)) == "up" {
				linkUp = "Up"
			}
		}

		fmt.Fprintf(&b, "Interface: %s, Physical link is %s\n", ifName, linkUp)
		fmt.Fprintf(&b, "  MTU: %d", iface.MTU)
		if len(iface.HardwareAddr) > 0 {
			fmt.Fprintf(&b, ", MAC: %s", iface.HardwareAddr)
		}
		b.WriteString("\n")

		if zone, ok := ifaceZoneName[ifName]; ok {
			fmt.Fprintf(&b, "  Zone: %s\n", zone)
		}

		if s.dp != nil && s.dp.IsLoaded() {
			if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Fprintf(&b, "  BPF Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Fprintf(&b, "  BPF Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}

		if addrs, err := iface.Addrs(); err == nil && len(addrs) > 0 {
			fmt.Fprintf(&b, "  Addresses:\n")
			for _, a := range addrs {
				fmt.Fprintf(&b, "    %s\n", a.String())
			}
		}

		// DHCP annotations
		if s.dhcp != nil {
			if lease := s.dhcp.LeaseFor(ifName, dhcp.AFInet); lease != nil {
				fmt.Fprintf(&b, "  DHCPv4: %s (gw %s)\n", lease.Address, lease.Gateway)
			}
			if lease := s.dhcp.LeaseFor(ifName, dhcp.AFInet6); lease != nil {
				fmt.Fprintf(&b, "  DHCPv6: %s (gw %s)\n", lease.Address, lease.Gateway)
			}
		}

		b.WriteString("\n")
	}

	writeOK(w, TextResponse{Output: b.String()})
}
