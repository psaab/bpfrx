package routing

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RouteEntry represents a kernel routing table entry.
type RouteEntry struct {
	Destination string
	NextHop     string
	Interface   string
	Protocol    string
	Preference  int
}

// TableRoutes groups routes by their routing table name.
type TableRoutes struct {
	Name    string       // "inet.0", "VRF-name.inet.0", etc.
	Entries []RouteEntry // routes in this table
}

// routeLister is the minimal netlink read surface the route reader
// needs. Satisfied by *netlink.Handle in production.
type routeLister interface {
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	LinkByIndex(index int) (netlink.Link, error)
	LinkByName(name string) (netlink.Link, error)
}

// routeReader reads kernel routing tables and converts them to
// RouteEntry values. It is stateless apart from the borrowed netlink
// read surface.
type routeReader struct {
	ops routeLister
}

// GetRoutesForTable reads routes from a specific kernel routing table.
func (rr *routeReader) GetRoutesForTable(tableID int) ([]RouteEntry, error) {
	var entries []RouteEntry

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		filter := &netlink.Route{Table: tableID}
		routes, err := rr.ops.RouteListFiltered(family, filter, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		for _, r := range routes {
			entries = append(entries, rr.routeToEntry(r, family))
		}
	}

	return entries, nil
}

// GetRoutes reads the main kernel routing table.
func (rr *routeReader) GetRoutes() ([]RouteEntry, error) {
	var entries []RouteEntry

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := rr.ops.RouteList(nil, family)
		if err != nil {
			continue
		}
		for _, r := range routes {
			entries = append(entries, rr.routeToEntry(r, family))
		}
	}

	return entries, nil
}

// GetVRFRoutes reads routes from a VRF's routing table by VRF device name.
func (rr *routeReader) GetVRFRoutes(vrfName string) ([]RouteEntry, error) {
	// VRF devices are created with "vrf-" prefix.
	devName := vrfName
	if !strings.HasPrefix(devName, "vrf-") {
		devName = "vrf-" + devName
	}
	link, err := rr.ops.LinkByName(devName)
	if err != nil {
		return nil, fmt.Errorf("VRF %q not found: %w", vrfName, err)
	}
	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return nil, fmt.Errorf("%q is not a VRF device", vrfName)
	}
	return rr.GetRoutesForTable(int(vrf.Table))
}

// GetTableRoutes returns routes for a Junos-style table name (e.g. "inet.0",
// "inet6.0", "dmz-vr.inet.0", "dmz-vr.inet6.0"). It resolves the VRF and
// filters by address family.
func (rr *routeReader) GetTableRoutes(tableName string) ([]RouteEntry, error) {
	// Determine VRF name and address family from Junos table name.
	vrfName := ""
	isV6 := false
	switch {
	case tableName == "inet.0":
		// main table, IPv4
	case tableName == "inet6.0":
		isV6 = true
	case strings.HasSuffix(tableName, ".inet6.0"):
		vrfName = strings.TrimSuffix(tableName, ".inet6.0")
		isV6 = true
	case strings.HasSuffix(tableName, ".inet.0"):
		vrfName = strings.TrimSuffix(tableName, ".inet.0")
	default:
		// Treat as VRF name directly (backwards compat).
		vrfName = tableName
	}

	var entries []RouteEntry
	var err error
	if vrfName == "" {
		entries, err = rr.GetRoutes()
	} else {
		entries, err = rr.GetVRFRoutes(vrfName)
	}
	if err != nil {
		return nil, err
	}

	// Filter by address family.
	var filtered []RouteEntry
	for _, e := range entries {
		entryIsV6 := strings.Contains(e.Destination, ":")
		if entryIsV6 == isV6 {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

// GetAllTableRoutes returns routes from the main table and all configured VRFs.
// IPv4 and IPv6 routes are split into separate inet.0/inet6.0 tables.
func (rr *routeReader) GetAllTableRoutes(instances []*config.RoutingInstanceConfig) ([]TableRoutes, error) {
	var tables []TableRoutes

	// Main table
	mainEntries, err := rr.GetRoutes()
	if err != nil {
		return nil, err
	}
	tables = appendSplitAF(tables, "", mainEntries)

	// Per-VRF tables
	for _, ri := range instances {
		if ri.TableID == 0 {
			continue
		}
		entries, err := rr.GetRoutesForTable(ri.TableID)
		if err != nil {
			continue
		}
		tables = appendSplitAF(tables, ri.Name, entries)
	}
	return tables, nil
}

// routeToEntry converts a netlink route to a RouteEntry.
func (rr *routeReader) routeToEntry(r netlink.Route, family int) RouteEntry {
	entry := RouteEntry{
		Preference: r.Priority,
		Protocol:   rtProtoName(r.Protocol),
	}

	if r.Dst != nil {
		entry.Destination = r.Dst.String()
	} else {
		if family == netlink.FAMILY_V6 {
			entry.Destination = "::/0"
		} else {
			entry.Destination = "0.0.0.0/0"
		}
	}

	if r.Gw != nil {
		entry.NextHop = r.Gw.String()
	} else if r.Type == unix.RTN_BLACKHOLE {
		entry.NextHop = "discard"
	} else {
		entry.NextHop = "direct"
	}

	if r.LinkIndex > 0 {
		link, err := rr.ops.LinkByIndex(r.LinkIndex)
		if err == nil {
			entry.Interface = link.Attrs().Name
		} else {
			entry.Interface = strconv.Itoa(r.LinkIndex)
		}
	}

	return entry
}

// rtprotZStatic is FRR's private rtnetlink protocol value for staticd-
// installed routes (RTPROT_ZSTATIC). It is NOT a Linux UAPI constant, so
// it has no golang.org/x/sys/unix counterpart; FRR's zebra2proto() maps
// ZEBRA_ROUTE_STATIC -> RTPROT_ZSTATIC (zebra/rt_netlink.h, value 196)
// and proto2zebra() reads both RTPROT_STATIC and RTPROT_ZSTATIC back as
// ZEBRA_ROUTE_STATIC.
const rtprotZStatic = 196

// rtProtoName maps a netlink route protocol to its xpf protocol name.
//
// The argument is the kernel rtnetlink rtm_protocol byte. FRR's zebra
// stamps each FIB route with the originating daemon's RTPROT_* value via
// zebra2proto(): bgpd->RTPROT_BGP, ospfd/ospf6d->RTPROT_OSPF,
// isisd->RTPROT_ISIS, ripd->RTPROT_RIP, staticd->RTPROT_ZSTATIC(196),
// connected/local/kernel->RTPROT_KERNEL. RTPROT_ZEBRA(11) is reserved by
// FRR for ZEBRA_ROUTE_TABLE/NHG routes, which xpf does not surface as a
// named protocol, so it falls through to its numeric string like any
// other unrecognized value. The numeric comments record the constant
// values for the reader. The returned name feeds protoTag() and
// junosProtoName() in routeformat.go and the `show route protocol <x>`
// filter in pkg/cli/cli_show_routing.go.
func rtProtoName(p netlink.RouteProtocol) string {
	switch int(p) {
	case unix.RTPROT_REDIRECT: // 1
		return "redirect"
	case unix.RTPROT_KERNEL: // 2 — also FRR connected/local/kernel
		return "connected"
	case unix.RTPROT_BOOT: // 3
		return "dhcp"
	case unix.RTPROT_STATIC: // 4 — manual `ip route` static
		return "static"
	case unix.RTPROT_DHCP: // 16
		return "dhcp"
	case unix.RTPROT_BGP: // 186
		return "bgp"
	case unix.RTPROT_ISIS: // 187
		return "isis"
	case unix.RTPROT_OSPF: // 188
		return "ospf"
	case unix.RTPROT_RIP: // 189
		return "rip"
	case rtprotZStatic: // 196 — FRR staticd (RTPROT_ZSTATIC)
		return "static"
	default:
		return strconv.Itoa(int(p))
	}
}
