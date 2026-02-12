// Package routing manages static routes and GRE tunnels via netlink.
package routing

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Manager handles tunnel and VRF lifecycle.
type Manager struct {
	nlHandle *netlink.Handle
	tunnels  []string // currently created tunnel interface names
	vrfs     []string // currently created VRF device names
	xfrmis   []string // currently created xfrmi interface names
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

// CreateVRF creates a Linux VRF device and assigns it a routing table.
func (m *Manager) CreateVRF(name string, tableID int) error {
	vrfName := "vrf-" + name

	// Check if VRF already exists
	if _, err := m.nlHandle.LinkByName(vrfName); err == nil {
		// Already exists, ensure it's up
		link, _ := m.nlHandle.LinkByName(vrfName)
		m.nlHandle.LinkSetUp(link)
		slog.Debug("VRF already exists", "name", vrfName, "table", tableID)
		return nil
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: vrfName},
		Table:     uint32(tableID),
	}
	if err := m.nlHandle.LinkAdd(vrf); err != nil {
		return fmt.Errorf("create VRF %s: %w", vrfName, err)
	}
	link, err := m.nlHandle.LinkByName(vrfName)
	if err != nil {
		return fmt.Errorf("find VRF %s: %w", vrfName, err)
	}
	if err := m.nlHandle.LinkSetUp(link); err != nil {
		return fmt.Errorf("set VRF %s up: %w", vrfName, err)
	}
	m.vrfs = append(m.vrfs, vrfName)
	slog.Info("VRF created", "name", vrfName, "table", tableID)
	return nil
}

// BindInterfaceToVRF binds a network interface to a VRF device.
func (m *Manager) BindInterfaceToVRF(ifaceName, instanceName string) error {
	vrfName := "vrf-" + instanceName

	iface, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	vrf, err := m.nlHandle.LinkByName(vrfName)
	if err != nil {
		return fmt.Errorf("VRF %s not found: %w", vrfName, err)
	}
	if err := m.nlHandle.LinkSetMaster(iface, vrf); err != nil {
		return fmt.Errorf("bind %s to VRF %s: %w", ifaceName, vrfName, err)
	}
	slog.Info("interface bound to VRF", "interface", ifaceName, "vrf", vrfName)
	return nil
}

// ClearVRFs removes all previously created VRF devices.
func (m *Manager) ClearVRFs() error {
	for _, name := range m.vrfs {
		link, err := m.nlHandle.LinkByName(name)
		if err != nil {
			continue
		}
		if err := m.nlHandle.LinkDel(link); err != nil {
			slog.Warn("failed to delete VRF", "name", name, "err", err)
		} else {
			slog.Info("VRF removed", "name", name)
		}
	}
	m.vrfs = nil
	return nil
}

// GetRoutesForTable reads routes from a specific kernel routing table.
func (m *Manager) GetRoutesForTable(tableID int) ([]RouteEntry, error) {
	var entries []RouteEntry

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		filter := &netlink.Route{Table: tableID}
		routes, err := m.nlHandle.RouteListFiltered(family, filter, netlink.RT_FILTER_TABLE)
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

		var tunnelLink netlink.Link
		switch tc.Mode {
		case "ipip":
			tunnelLink = &netlink.Iptun{
				LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
				Local:     localIP,
				Remote:    remoteIP,
				Ttl:       uint8(ttl),
			}
		default: // "gre" or ""
			greLink := &netlink.Gretun{
				LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
				Local:     localIP,
				Remote:    remoteIP,
				Ttl:       uint8(ttl),
			}
			if tc.Key > 0 {
				greLink.IKey = tc.Key
				greLink.OKey = tc.Key
			}
			tunnelLink = greLink
		}

		if err := m.nlHandle.LinkAdd(tunnelLink); err != nil {
			slog.Warn("failed to create tunnel",
				"name", tc.Name, "mode", tc.Mode, "err", err)
			continue
		}

		if err := m.nlHandle.LinkSetUp(tunnelLink); err != nil {
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
			if err := m.nlHandle.AddrAdd(tunnelLink, addr); err != nil {
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

// ApplyXfrmi creates XFRM virtual interfaces for IPsec VPN tunnels.
// Each VPN with a BindInterface (e.g. "st0.0") gets an xfrmi device
// with a unique XFRM interface ID derived from the "stN" index.
func (m *Manager) ApplyXfrmi(vpns map[string]*config.IPsecVPN) error {
	if err := m.ClearXfrmi(); err != nil {
		slog.Warn("failed to clear previous xfrmi interfaces", "err", err)
	}

	for _, vpn := range vpns {
		if vpn.BindInterface == "" {
			continue
		}

		// Parse interface name: "st0.0" -> device "st0", if_id from index
		ifName, ifID := parseXfrmiName(vpn.BindInterface)
		if ifName == "" || ifID == 0 {
			slog.Warn("invalid bind-interface name",
				"vpn", vpn.Name, "bind-interface", vpn.BindInterface)
			continue
		}

		// Check if already exists
		if _, err := m.nlHandle.LinkByName(ifName); err == nil {
			link, _ := m.nlHandle.LinkByName(ifName)
			m.nlHandle.LinkSetUp(link)
			slog.Debug("xfrmi already exists", "name", ifName, "if_id", ifID)
			// Track if not already tracked
			found := false
			for _, x := range m.xfrmis {
				if x == ifName {
					found = true
					break
				}
			}
			if !found {
				m.xfrmis = append(m.xfrmis, ifName)
			}
			continue
		}

		xfrmi := &netlink.Xfrmi{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifName,
			},
			Ifid: ifID,
		}

		if err := m.nlHandle.LinkAdd(xfrmi); err != nil {
			slog.Warn("failed to create xfrmi",
				"name", ifName, "if_id", ifID, "err", err)
			continue
		}

		link, err := m.nlHandle.LinkByName(ifName)
		if err != nil {
			slog.Warn("failed to find xfrmi after creation",
				"name", ifName, "err", err)
			continue
		}

		if err := m.nlHandle.LinkSetUp(link); err != nil {
			slog.Warn("failed to bring up xfrmi",
				"name", ifName, "err", err)
		}

		slog.Info("xfrmi created", "name", ifName, "if_id", ifID, "vpn", vpn.Name)
		m.xfrmis = append(m.xfrmis, ifName)
	}

	return nil
}

// ClearXfrmi removes all previously created xfrmi interfaces.
func (m *Manager) ClearXfrmi() error {
	for _, name := range m.xfrmis {
		link, err := m.nlHandle.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := m.nlHandle.LinkDel(link); err != nil {
			slog.Warn("failed to delete xfrmi", "name", name, "err", err)
		} else {
			slog.Info("xfrmi removed", "name", name)
		}
	}
	m.xfrmis = nil
	return nil
}

// parseXfrmiName parses "st0.0" into device name "st0" and if_id 1,
// or "st1.0" into "st1" and if_id 2. The if_id is stN_index + 1.
func parseXfrmiName(bindIface string) (string, uint32) {
	// Strip unit number: "st0.0" -> "st0"
	devName := bindIface
	if dot := strings.IndexByte(bindIface, '.'); dot >= 0 {
		devName = bindIface[:dot]
	}

	// Parse "stN" to get N
	if len(devName) < 3 || devName[:2] != "st" {
		return "", 0
	}
	idx, err := strconv.Atoi(devName[2:])
	if err != nil {
		return "", 0
	}
	// if_id starts at 1 (st0 -> 1, st1 -> 2, etc.)
	return devName, uint32(idx + 1)
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

		switch tun := link.(type) {
		case *netlink.Gretun:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		case *netlink.Iptun:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
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
		return "dhcp"
	case unix.RTPROT_STATIC:
		return "static"
	case 16: // RTPROT_DHCP
		return "dhcp"
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
	case 196:
		return "static" // RTPROT_ZEBRA — FRR staticd-installed routes
	default:
		return strconv.Itoa(pi)
	}
}
