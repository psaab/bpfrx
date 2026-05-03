// Phase 6 of #1043: extract the three netlink-driven interfaces
// ShowText case bodies (`interfaces-extensive`, `interfaces-detail`,
// `interfaces-statistics`) into dedicated methods. Same methodology as
// Phases 1-5 (#1148, #1150, #1151, #1153, #1154): semantic relocation,
// no behavior change. Each case body is moved verbatim apart from
// `&buf` references becoming `buf` (passed-in `*strings.Builder`).
//
// Unlike the earlier phases, these three case bodies have an early
// `netlink.LinkList()` error path that returns a gRPC status error, so
// the methods return `error` and the dispatcher rewraps via
// `if err := ...; err != nil { return nil, err }`. Error semantics are
// preserved verbatim from the original case bodies.

package grpcapi

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// showInterfacesExtensive renders the Junos-style extensive interface
// listing — admin/oper state, description, speed/duplex from sysfs,
// MTU, MAC, kernel and BPF traffic counters, and address list.
func (s *Server) showInterfacesExtensive(cfg *config.Config, buf *strings.Builder) error {
	linksList, err := netlink.LinkList()
	if err != nil {
		return status.Errorf(codes.Internal, "listing interfaces: %v", err)
	}
	sort.Slice(linksList, func(i, j int) bool {
		return linksList[i].Attrs().Name < linksList[j].Attrs().Name
	})
	// Build config lookup for description/speed/duplex/zone
	ifCfgMap := make(map[string]*config.InterfaceConfig)
	ifZoneMap := make(map[string]string)
	if cfg != nil {
		for _, ifc := range cfg.Interfaces.Interfaces {
			ifCfgMap[ifc.Name] = ifc
		}
		for _, z := range cfg.Security.Zones {
			for _, ifName := range z.Interfaces {
				ifZoneMap[ifName] = z.Name
			}
		}
	}
	for _, link := range linksList {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
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
		fmt.Fprintf(buf, "Physical interface: %s, %s, Physical link is %s\n", attrs.Name, adminStr, linkStr)
		if ifCfg, ok := ifCfgMap[attrs.Name]; ok {
			if ifCfg.Description != "" {
				fmt.Fprintf(buf, "  Description: %s\n", ifCfg.Description)
			}
			if ifCfg.Speed != "" {
				fmt.Fprintf(buf, "  Speed: %s\n", ifCfg.Speed)
			}
			if ifCfg.Duplex != "" {
				fmt.Fprintf(buf, "  Duplex: %s\n", ifCfg.Duplex)
			}
		}
		if zone, ok := ifZoneMap[attrs.Name]; ok {
			fmt.Fprintf(buf, "  Security zone: %s\n", zone)
		}
		// Speed/duplex from sysfs
		var linkExtras []string
		if data, err := os.ReadFile("/sys/class/net/" + attrs.Name + "/speed"); err == nil {
			if spd, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && spd > 0 {
				if spd >= 1000 {
					linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dGbps", spd/1000))
				} else {
					linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dMbps", spd))
				}
			}
		}
		duplexStr := "Full-duplex"
		if data, err := os.ReadFile("/sys/class/net/" + attrs.Name + "/duplex"); err == nil {
			d := strings.TrimSpace(string(data))
			if d == "half" {
				duplexStr = "Half-duplex"
			}
		}
		linkExtras = append(linkExtras, "Link-mode: "+duplexStr)
		fmt.Fprintf(buf, "  Link-level type: %s, MTU: %d, %s\n", attrs.EncapType, attrs.MTU, strings.Join(linkExtras, ", "))
		if len(attrs.HardwareAddr) > 0 {
			fmt.Fprintf(buf, "  Current address: %s\n", attrs.HardwareAddr)
		}
		fmt.Fprintf(buf, "  Interface index: %d\n", attrs.Index)
		if st := attrs.Statistics; st != nil {
			fmt.Fprintf(buf, "  Traffic statistics:\n")
			fmt.Fprintf(buf, "    Input:  %d bytes, %d packets\n", st.RxBytes, st.RxPackets)
			fmt.Fprintf(buf, "    Output: %d bytes, %d packets\n", st.TxBytes, st.TxPackets)
			fmt.Fprintf(buf, "  Input errors:\n")
			fmt.Fprintf(buf, "    Errors: %d, Drops: %d, Overruns: %d, Frame: %d\n",
				st.RxErrors, st.RxDropped, st.RxOverErrors, st.RxFrameErrors)
			fmt.Fprintf(buf, "  Output errors:\n")
			fmt.Fprintf(buf, "    Errors: %d, Drops: %d, Carrier: %d, Collisions: %d\n",
				st.TxErrors, st.TxDropped, st.TxCarrierErrors, st.Collisions)
		}
		// BPF traffic counters (XDP/TC level)
		if s.dp != nil && s.dp.IsLoaded() {
			if ctrs, err := s.dp.ReadInterfaceCounters(attrs.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Fprintf(buf, "  BPF statistics:\n")
				fmt.Fprintf(buf, "    Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Fprintf(buf, "    Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}
		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		for _, a := range addrs {
			fmt.Fprintf(buf, "  Address: %s\n", a.IPNet)
		}
		fmt.Fprintln(buf)
	}
	return nil
}

// showInterfacesDetail renders the Junos-style detail view, optionally
// filtered to a single interface name (`filter`).
func (s *Server) showInterfacesDetail(cfg *config.Config, filter string, buf *strings.Builder) error {
	linksList, err := netlink.LinkList()
	if err != nil {
		return status.Errorf(codes.Internal, "listing interfaces: %v", err)
	}
	sort.Slice(linksList, func(i, j int) bool {
		return linksList[i].Attrs().Name < linksList[j].Attrs().Name
	})
	ifZoneMap := make(map[string]string)
	ifDescMap := make(map[string]string)
	if cfg != nil {
		for _, z := range cfg.Security.Zones {
			for _, ifName := range z.Interfaces {
				ifZoneMap[ifName] = z.Name
			}
		}
		for _, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Description != "" {
				ifDescMap[ifc.Name] = ifc.Description
			}
		}
	}
	for _, link := range linksList {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		if filter != "" && attrs.Name != filter {
			continue
		}
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
		fmt.Fprintf(buf, "Physical interface: %s, %s, Physical link is %s\n", attrs.Name, adminStr, linkStr)
		if desc, ok := ifDescMap[attrs.Name]; ok {
			fmt.Fprintf(buf, "  Description: %s\n", desc)
		}
		fmt.Fprintf(buf, "  Interface index: %d, SNMP ifIndex: %d\n", attrs.Index, attrs.Index)
		// Speed/duplex from sysfs
		linkType := attrs.EncapType
		if linkType == "" {
			linkType = "Ethernet"
		}
		speedStr := ""
		if data, err := os.ReadFile("/sys/class/net/" + attrs.Name + "/speed"); err == nil {
			if spd, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && spd > 0 {
				if spd >= 1000 {
					speedStr = fmt.Sprintf(", Speed: %dGbps", spd/1000)
				} else {
					speedStr = fmt.Sprintf(", Speed: %dMbps", spd)
				}
			}
		}
		duplexStr := ""
		if data, err := os.ReadFile("/sys/class/net/" + attrs.Name + "/duplex"); err == nil {
			d := strings.TrimSpace(string(data))
			switch d {
			case "full":
				duplexStr = ", Duplex: Full-duplex"
			case "half":
				duplexStr = ", Duplex: Half-duplex"
			}
		}
		fmt.Fprintf(buf, "  Link-level type: %s, MTU: %d%s%s\n", linkType, attrs.MTU, speedStr, duplexStr)
		if len(attrs.HardwareAddr) > 0 {
			fmt.Fprintf(buf, "  Current address: %s\n", attrs.HardwareAddr)
		}
		if zone, ok := ifZoneMap[attrs.Name]; ok {
			fmt.Fprintf(buf, "  Security zone: %s\n", zone)
		}
		fmt.Fprintf(buf, "  Logical interface %s.0\n", attrs.Name)
		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		if len(addrs) > 0 {
			fmt.Fprintf(buf, "    Addresses:\n")
			for _, a := range addrs {
				fmt.Fprintf(buf, "      %s\n", a.IPNet)
			}
		}
		if st := attrs.Statistics; st != nil {
			fmt.Fprintf(buf, "  Traffic statistics:\n")
			fmt.Fprintf(buf, "    Input  packets:             %12d\n", st.RxPackets)
			fmt.Fprintf(buf, "    Output packets:             %12d\n", st.TxPackets)
			fmt.Fprintf(buf, "    Input  bytes:               %12d\n", st.RxBytes)
			fmt.Fprintf(buf, "    Output bytes:               %12d\n", st.TxBytes)
			fmt.Fprintf(buf, "    Input  errors:              %12d\n", st.RxErrors)
			fmt.Fprintf(buf, "    Output errors:              %12d\n", st.TxErrors)
		}
		fmt.Fprintln(buf)
	}
	return nil
}

// showInterfacesStatistics renders the per-interface kernel
// counter table (input/output packets/bytes/errors), excluding lo,
// VRFs, XFRM, and GRE devices.
func (s *Server) showInterfacesStatistics(buf *strings.Builder) error {
	linksList, err := netlink.LinkList()
	if err != nil {
		return status.Errorf(codes.Internal, "listing interfaces: %v", err)
	}
	sort.Slice(linksList, func(i, j int) bool {
		return linksList[i].Attrs().Name < linksList[j].Attrs().Name
	})
	fmt.Fprintf(buf, "%-16s %15s %15s %15s %15s %10s %10s\n",
		"Interface", "Input packets", "Input bytes", "Output packets", "Output bytes", "In errors", "Out errors")
	for _, link := range linksList {
		name := link.Attrs().Name
		if name == "lo" || strings.HasPrefix(name, "vrf-") ||
			strings.HasPrefix(name, "xfrm") || strings.HasPrefix(name, "gre-") {
			continue
		}
		st := link.Attrs().Statistics
		if st == nil {
			continue
		}
		fmt.Fprintf(buf, "%-16s %15d %15d %15d %15d %10d %10d\n",
			name, st.RxPackets, st.RxBytes, st.TxPackets, st.TxBytes,
			st.RxErrors, st.TxErrors)
	}
	return nil
}
