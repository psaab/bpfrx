//go:build dpdk

package dpdk

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

// fibEntry is a compiled route ready for DPDK LPM insertion.
type fibEntry struct {
	family    uint8 // AF_INET or AF_INET6
	dst       net.IP
	prefixLen int
	nexthopID uint32
}

// fibNexthop holds resolved forwarding info for a nexthop.
type fibNexthop struct {
	portID  uint32
	ifindex uint32
	vlanID  uint16
	dmac    [6]byte
	smac    [6]byte
}

// StartFIBSync begins a background goroutine that periodically reads
// kernel routes and neighbors, then pushes them into the DPDK FIB
// (rte_lpm) tables. This replaces bpf_fib_lookup which is unavailable
// in DPDK.
//
// The goroutine reads the main routing table (254) plus any VRF tables
// discovered from VRF devices. For each route, it resolves the gateway
// MAC via the kernel neighbor table.
func (m *Manager) StartFIBSync(ctx context.Context) {
	go m.fibSyncLoop(ctx)
}

func (m *Manager) fibSyncLoop(ctx context.Context) {
	// Initial sync after a short delay to let interfaces come up.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}
	m.syncFIB()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.syncFIB()
		}
	}
}

// syncFIB reads kernel routes and neighbors, then repopulates the DPDK
// LPM tables. It does a full clear-and-rebuild on each cycle since
// rte_lpm doesn't support efficient incremental updates.
func (m *Manager) syncFIB() {
	if m.platform.shm == nil {
		return
	}

	handle, err := netlink.NewHandle()
	if err != nil {
		slog.Warn("FIB sync: failed to get netlink handle", "err", err)
		return
	}
	defer handle.Close()

	// Build interface index → port/MAC mapping.
	ifMap := m.buildIfaceMap(handle)

	// Read all IPv4 and IPv6 routes from the main table.
	var entries []fibEntry
	var nexthops []fibNexthop
	nhIndex := map[string]uint32{} // key: "ifindex:gwIP" → nexthop ID

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := handle.RouteList(nil, family)
		if err != nil {
			slog.Debug("FIB sync: RouteList failed", "family", family, "err", err)
			continue
		}
		for _, r := range routes {
			m.compileRoute(handle, r, family, ifMap, &entries, &nexthops, nhIndex)
		}
	}

	// Also read VRF routing tables.
	links, err := handle.LinkList()
	if err == nil {
		for _, link := range links {
			vrf, ok := link.(*netlink.Vrf)
			if !ok {
				continue
			}
			tableID := int(vrf.Table)
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				filter := &netlink.Route{Table: tableID}
				vrfRoutes, err := handle.RouteListFiltered(family, filter, netlink.RT_FILTER_TABLE)
				if err != nil {
					continue
				}
				for _, r := range vrfRoutes {
					m.compileRoute(handle, r, family, ifMap, &entries, &nexthops, nhIndex)
				}
			}
		}
	}

	// Write to DPDK tables.
	m.ClearFIBRoutes()

	for id, nh := range nexthops {
		if err := m.SetFIBNexthop(uint32(id), nh.portID, nh.ifindex, nh.vlanID, nh.dmac, nh.smac); err != nil {
			slog.Debug("FIB sync: SetFIBNexthop failed", "id", id, "err", err)
		}
	}

	for _, e := range entries {
		if err := m.SetFIBRoute(e.family, e.dst, e.prefixLen, e.nexthopID); err != nil {
			slog.Debug("FIB sync: SetFIBRoute failed", "dst", e.dst, "err", err)
		}
	}

	m.BumpFIBGeneration()
}

// ifaceInfo caches per-interface forwarding info.
type ifaceInfo struct {
	index  int
	portID uint32
	mac    [6]byte
}

// buildIfaceMap enumerates system interfaces and builds ifindex → info mapping.
// portID is currently mapped 1:1 with ifindex; this should be updated
// when DPDK port assignment is configurable.
func (m *Manager) buildIfaceMap(handle *netlink.Handle) map[int]*ifaceInfo {
	result := map[int]*ifaceInfo{}
	links, err := handle.LinkList()
	if err != nil {
		return result
	}
	for _, link := range links {
		attrs := link.Attrs()
		info := &ifaceInfo{
			index:  attrs.Index,
			portID: uint32(attrs.Index), // TODO: map ifindex → DPDK port_id
		}
		hw := attrs.HardwareAddr
		if len(hw) >= 6 {
			copy(info.mac[:], hw[:6])
		}
		result[attrs.Index] = info
	}
	return result
}

// compileRoute converts a single netlink route into FIB entries.
func (m *Manager) compileRoute(
	handle *netlink.Handle,
	r netlink.Route,
	family int,
	ifMap map[int]*ifaceInfo,
	entries *[]fibEntry,
	nexthops *[]fibNexthop,
	nhIndex map[string]uint32,
) {
	// Skip blackhole/unreachable/prohibit routes.
	if r.Type != 0 && r.Type != 1 { // RTN_UNSPEC or RTN_UNICAST
		return
	}

	// Get destination prefix.
	var dst net.IP
	var prefixLen int

	if r.Dst != nil {
		dst = r.Dst.IP
		prefixLen, _ = r.Dst.Mask.Size()
	} else {
		// Default route.
		if family == netlink.FAMILY_V6 {
			dst = net.IPv6zero
		} else {
			dst = net.IPv4zero.To4()
		}
		prefixLen = 0
	}

	af := uint8(2) // AF_INET
	if family == netlink.FAMILY_V6 {
		af = 10 // AF_INET6
	}

	// Handle multipath (ECMP) routes.
	if len(r.MultiPath) > 0 {
		for _, mp := range r.MultiPath {
			nhID := m.resolveNexthop(handle, mp.Gw, mp.LinkIndex, family, ifMap, nexthops, nhIndex)
			if nhID != ^uint32(0) {
				*entries = append(*entries, fibEntry{
					family:    af,
					dst:       dst,
					prefixLen: prefixLen,
					nexthopID: nhID,
				})
				break // rte_lpm only supports one nexthop per prefix
			}
		}
		return
	}

	// Single-path route.
	nhID := m.resolveNexthop(handle, r.Gw, r.LinkIndex, family, ifMap, nexthops, nhIndex)
	if nhID == ^uint32(0) {
		return // No resolvable nexthop
	}

	*entries = append(*entries, fibEntry{
		family:    af,
		dst:       dst,
		prefixLen: prefixLen,
		nexthopID: nhID,
	})
}

// resolveNexthop finds or creates a nexthop entry. Returns the nexthop ID,
// or ^uint32(0) if resolution fails (no interface, no neighbor).
func (m *Manager) resolveNexthop(
	handle *netlink.Handle,
	gw net.IP,
	linkIndex int,
	family int,
	ifMap map[int]*ifaceInfo,
	nexthops *[]fibNexthop,
	nhIndex map[string]uint32,
) uint32 {
	if linkIndex == 0 {
		return ^uint32(0)
	}

	iface, ok := ifMap[linkIndex]
	if !ok {
		return ^uint32(0)
	}

	// Build dedup key.
	gwStr := "direct"
	if gw != nil {
		gwStr = gw.String()
	}
	key := net.JoinHostPort(gwStr, string(rune(linkIndex)))

	if id, exists := nhIndex[key]; exists {
		return id
	}

	nh := fibNexthop{
		portID:  iface.portID,
		ifindex: uint32(linkIndex),
		smac:    iface.mac,
	}

	// Resolve destination MAC via kernel neighbor table.
	if gw != nil && !gw.IsUnspecified() {
		dmac := m.lookupNeighborMAC(handle, linkIndex, family, gw)
		if dmac != [6]byte{} {
			nh.dmac = dmac
		} else {
			// No neighbor entry — nexthop unusable for direct forwarding.
			// Still add it so connected routes work (dmac will be zero,
			// which means the packet needs kernel-assisted forwarding).
		}
	}

	id := uint32(len(*nexthops))
	*nexthops = append(*nexthops, nh)
	nhIndex[key] = id
	return id
}

// lookupNeighborMAC queries the kernel ARP/NDP table for the MAC address
// of a specific IP on a specific interface.
func (m *Manager) lookupNeighborMAC(
	handle *netlink.Handle,
	linkIndex int,
	family int,
	ip net.IP,
) [6]byte {
	var mac [6]byte

	neighs, err := handle.NeighList(linkIndex, family)
	if err != nil {
		return mac
	}

	for _, n := range neighs {
		if !n.IP.Equal(ip) {
			continue
		}
		// Accept REACHABLE, STALE, or PERMANENT entries.
		if n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT) == 0 {
			continue
		}
		if len(n.HardwareAddr) >= 6 {
			copy(mac[:], n.HardwareAddr[:6])
			return mac
		}
	}

	return mac
}

// --- Stub for non-dpdk builds is not needed since fib.go has //go:build dpdk ---

// portIDForIP resolves the DPDK port ID for a destination by checking
// the kernel FIB. This is used for directly connected routes where
// there is no gateway.
func (m *Manager) portIDForIP(_ net.IP) uint32 {
	// For now, return 0 to indicate kernel-assisted forwarding.
	return 0
}

// bytesToIPv4 converts a network-byte-order uint32 to net.IP.
func bytesToIPv4(be uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, be)
	return ip
}
