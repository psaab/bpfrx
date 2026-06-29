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
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
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
			if z == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
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
			if z == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
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

// --- #1700: residual ShowText branches ---

func (s *Server) showClassOfService(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	selector := ""
	if strings.HasPrefix(req.Topic, "class-of-service:") {
		selector = strings.TrimPrefix(req.Topic, "class-of-service:")
	}
	var status *dpuserspace.ProcessStatus
	if userspaceStatus, err := s.userspaceDataplaneStatus(); err == nil {
		status = &userspaceStatus
	}
	buf.WriteString(dpformat.FormatCoSInterfaceSummary(cfg, status, selector))
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showVLANs(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		buf.WriteString("No VLANs configured\n")
	} else {
		ifZone := make(map[string]string)
		for zoneName, zone := range cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			for _, iface := range zone.Interfaces {
				ifZone[iface] = zoneName
			}
		}
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
					entries = append(entries, vlanEntry{
						iface:  ifc.Name,
						unit:   unitNum,
						vlanID: unit.VlanID,
						zone:   ifZone[ifc.Name],
						trunk:  ifc.VlanTagging,
					})
				}
			}
		}
		if len(entries) == 0 {
			buf.WriteString("No VLANs configured\n")
		} else {
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].iface != entries[j].iface {
					return entries[i].iface < entries[j].iface
				}
				return entries[i].unit < entries[j].unit
			})
			fmt.Fprintf(buf, "%-16s %-6s %-8s %-12s %s\n", "Interface", "Unit", "VLAN ID", "Zone", "Mode")
			for _, e := range entries {
				mode := "access"
				if e.trunk {
					mode = "trunk"
				}
				vid := fmt.Sprintf("%d", e.vlanID)
				if e.vlanID == 0 {
					vid = "native"
				}
				fmt.Fprintf(buf, "%-16s %-6d %-8s %-12s %s\n", e.iface, e.unit, vid, e.zone, mode)
			}
		}
	}
}

func (s *Server) showIPv6RouterAdvertisement(cfg *config.Config, buf *strings.Builder) {
	if s.raMgr == nil {
		fmt.Fprintln(buf, "Router Advertisements: not available")
	} else {
		senders := s.raMgr.Status()
		if len(senders) == 0 {
			fmt.Fprintln(buf, "Router Advertisements: no active senders")
		} else {
			fmt.Fprintf(buf, "Router Advertisement: %d sender(s)\n\n", len(senders))
			for _, info := range senders {
				fmt.Fprintf(buf, "Interface: %s\n", info.Interface)
				if info.State == "draining" {
					// A withdrawing router (emitting its lifetime-0 goodbye);
					// no longer advertising. Report state and move on.
					fmt.Fprintln(buf, "  State:              draining (withdrawing)")
					fmt.Fprintln(buf)
					continue
				}
				fmt.Fprintf(buf, "  Source address:     %s\n", info.SrcAddr)
				fmt.Fprintf(buf, "  Router lifetime:    %ds\n", info.Lifetime)
				fmt.Fprintf(buf, "  Preference:         %s\n", info.Preference)
				fmt.Fprintf(buf, "  Max RA interval:    %ds\n", info.MaxInterval)
				fmt.Fprintf(buf, "  Min RA interval:    %ds\n", info.MinInterval)
				if info.Managed {
					fmt.Fprintln(buf, "  Managed flag:       on")
				}
				if info.Other {
					fmt.Fprintln(buf, "  Other config flag:  on")
				}
				if info.LinkMTU > 0 {
					fmt.Fprintf(buf, "  Link MTU:           %d\n", info.LinkMTU)
				}
				for _, pfx := range info.Prefixes {
					fmt.Fprintf(buf, "  Prefix:             %s\n", pfx)
				}
				if len(info.DNSServers) > 0 {
					fmt.Fprintf(buf, "  DNS servers:        %s\n", strings.Join(info.DNSServers, ", "))
				}
				if info.NAT64Prefix != "" {
					fmt.Fprintf(buf, "  PREF64:             %s\n", info.NAT64Prefix)
				}
				fmt.Fprintf(buf, "  Last RA sent:       %s\n", info.LastRA)
				fmt.Fprintln(buf)
			}
		}
	}
}
