// Package routing manages static routes and GRE tunnels via netlink.
package routing

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Manager handles static route and tunnel lifecycle.
type Manager struct {
	nlHandle *netlink.Handle
	routes   []netlink.Route // currently installed static routes (for cleanup)
	tunnels  []string        // currently created tunnel interface names
}

// New creates a new routing Manager.
func New() (*Manager, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("netlink handle: %w", err)
	}
	return &Manager{nlHandle: h}, nil
}

// Close releases the netlink handle.
func (m *Manager) Close() error {
	if m.nlHandle != nil {
		m.nlHandle.Close()
	}
	return nil
}

// ApplyStaticRoutes installs static routes in the kernel FIB.
// Previous routes are removed first.
func (m *Manager) ApplyStaticRoutes(routes []*config.StaticRoute) error {
	if err := m.ClearStaticRoutes(); err != nil {
		slog.Warn("failed to clear previous static routes", "err", err)
	}

	for _, sr := range routes {
		_, dst, err := net.ParseCIDR(sr.Destination)
		if err != nil {
			slog.Warn("invalid static route destination", "dst", sr.Destination, "err", err)
			continue
		}

		route := netlink.Route{
			Dst:      dst,
			Priority: sr.Preference,
			Protocol: unix.RTPROT_STATIC,
		}

		if sr.Discard {
			route.Type = unix.RTN_BLACKHOLE
		} else if sr.NextHop != "" {
			gw := net.ParseIP(sr.NextHop)
			if gw == nil {
				slog.Warn("invalid static route next-hop", "nh", sr.NextHop)
				continue
			}
			route.Gw = gw
		}

		if sr.Interface != "" {
			link, err := m.nlHandle.LinkByName(sr.Interface)
			if err != nil {
				slog.Warn("static route interface not found",
					"iface", sr.Interface, "err", err)
				continue
			}
			route.LinkIndex = link.Attrs().Index
		}

		if err := m.nlHandle.RouteAdd(&route); err != nil {
			slog.Warn("failed to add static route",
				"dst", sr.Destination, "err", err)
			continue
		}
		slog.Info("static route added", "dst", sr.Destination,
			"nh", sr.NextHop, "iface", sr.Interface, "discard", sr.Discard)
		m.routes = append(m.routes, route)
	}

	return nil
}

// ClearStaticRoutes removes all previously installed static routes.
func (m *Manager) ClearStaticRoutes() error {
	for _, r := range m.routes {
		if err := m.nlHandle.RouteDel(&r); err != nil {
			slog.Warn("failed to remove static route", "dst", r.Dst, "err", err)
		}
	}
	m.routes = nil
	return nil
}

// ApplyTunnels creates GRE tunnel interfaces, brings them up, and assigns addresses.
// Previous tunnels are removed first.
func (m *Manager) ApplyTunnels(tunnels []*config.TunnelConfig) error {
	if err := m.ClearTunnels(); err != nil {
		slog.Warn("failed to clear previous tunnels", "err", err)
	}

	for _, tc := range tunnels {
		localIP := net.ParseIP(tc.Source)
		remoteIP := net.ParseIP(tc.Destination)
		if localIP == nil || remoteIP == nil {
			slog.Warn("invalid tunnel endpoints",
				"name", tc.Name, "src", tc.Source, "dst", tc.Destination)
			continue
		}

		ttl := tc.TTL
		if ttl == 0 {
			ttl = 64
		}

		link := &netlink.Gretun{
			LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
			Local:     localIP,
			Remote:    remoteIP,
			Ttl:       uint8(ttl),
		}
		if tc.Key > 0 {
			link.IKey = tc.Key
			link.OKey = tc.Key
		}

		if err := m.nlHandle.LinkAdd(link); err != nil {
			slog.Warn("failed to create tunnel",
				"name", tc.Name, "err", err)
			continue
		}

		if err := m.nlHandle.LinkSetUp(link); err != nil {
			slog.Warn("failed to bring up tunnel",
				"name", tc.Name, "err", err)
		}

		// Assign IP addresses
		for _, addrStr := range tc.Addresses {
			addr, err := netlink.ParseAddr(addrStr)
			if err != nil {
				slog.Warn("invalid tunnel address",
					"name", tc.Name, "addr", addrStr, "err", err)
				continue
			}
			if err := m.nlHandle.AddrAdd(link, addr); err != nil {
				slog.Warn("failed to add tunnel address",
					"name", tc.Name, "addr", addrStr, "err", err)
			}
		}

		slog.Info("tunnel created", "name", tc.Name,
			"src", tc.Source, "dst", tc.Destination)
		m.tunnels = append(m.tunnels, tc.Name)
	}

	return nil
}

// ClearTunnels removes all previously created tunnel interfaces.
func (m *Manager) ClearTunnels() error {
	for _, name := range m.tunnels {
		link, err := m.nlHandle.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := m.nlHandle.LinkDel(link); err != nil {
			slog.Warn("failed to delete tunnel", "name", name, "err", err)
		} else {
			slog.Info("tunnel removed", "name", name)
		}
	}
	m.tunnels = nil
	return nil
}

// TunnelStatus holds the status of a tunnel interface.
type TunnelStatus struct {
	Name        string
	Source      string
	Destination string
	State       string // "up" or "down"
	Addresses   []string
}

// GetTunnelStatus returns the status of managed tunnel interfaces.
func (m *Manager) GetTunnelStatus() ([]TunnelStatus, error) {
	var result []TunnelStatus
	for _, name := range m.tunnels {
		ts := TunnelStatus{Name: name, State: "down"}

		link, err := m.nlHandle.LinkByName(name)
		if err != nil {
			ts.State = "not found"
			result = append(result, ts)
			continue
		}

		if link.Attrs().Flags&net.FlagUp != 0 {
			ts.State = "up"
		}

		if gre, ok := link.(*netlink.Gretun); ok {
			ts.Source = gre.Local.String()
			ts.Destination = gre.Remote.String()
		}

		addrs, err := m.nlHandle.AddrList(link, netlink.FAMILY_ALL)
		if err == nil {
			for _, a := range addrs {
				ts.Addresses = append(ts.Addresses, a.IPNet.String())
			}
		}

		result = append(result, ts)
	}
	return result, nil
}

// RouteEntry represents a kernel routing table entry.
type RouteEntry struct {
	Destination string
	NextHop     string
	Interface   string
	Protocol    string
	Preference  int
}

// GetRoutes reads the kernel routing table.
func (m *Manager) GetRoutes() ([]RouteEntry, error) {
	var entries []RouteEntry

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := m.nlHandle.RouteList(nil, family)
		if err != nil {
			continue
		}
		for _, r := range routes {
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
				link, err := m.nlHandle.LinkByIndex(r.LinkIndex)
				if err == nil {
					entry.Interface = link.Attrs().Name
				} else {
					entry.Interface = strconv.Itoa(r.LinkIndex)
				}
			}

			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func rtProtoName(p netlink.RouteProtocol) string {
	pi := int(p)
	switch pi {
	case unix.RTPROT_REDIRECT:
		return "redirect"
	case unix.RTPROT_KERNEL:
		return "connected"
	case unix.RTPROT_BOOT:
		return "boot"
	case unix.RTPROT_STATIC:
		return "static"
	case 11:
		return "ospf"
	case 12:
		return "isis"
	case 186:
		return "bgp"
	case 188:
		return "ospf"
	case 189:
		return "rip"
	default:
		return strconv.Itoa(pi)
	}
}
