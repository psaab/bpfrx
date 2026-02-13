// Package routing manages static routes and GRE tunnels via netlink.
package routing

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
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
			entries = append(entries, routeToEntry(m, r, family))
		}
	}

	return entries, nil
}

// routeToEntry converts a netlink route to a RouteEntry.
func routeToEntry(m *Manager, r netlink.Route, family int) RouteEntry {
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

	return entry
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

		// Bind tunnel to VRF if routing-instance is configured.
		if tc.RoutingInstance != "" {
			if err := m.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); err != nil {
				slog.Warn("failed to bind tunnel to VRF",
					"name", tc.Name, "vrf", tc.RoutingInstance, "err", err)
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

// GetRoutes reads the main kernel routing table.
func (m *Manager) GetRoutes() ([]RouteEntry, error) {
	var entries []RouteEntry

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := m.nlHandle.RouteList(nil, family)
		if err != nil {
			continue
		}
		for _, r := range routes {
			entries = append(entries, routeToEntry(m, r, family))
		}
	}

	return entries, nil
}

// protoTag returns a single-letter Junos-style route protocol marker.
func protoTag(proto string) string {
	switch proto {
	case "static":
		return "S"
	case "connected":
		return "C"
	case "bgp":
		return "B"
	case "ospf":
		return "O"
	case "isis":
		return "I"
	case "rip":
		return "R"
	case "dhcp":
		return "D"
	default:
		return "?"
	}
}

// FormatRouteTerse formats routes in Junos "show route terse" style.
func FormatRouteTerse(entries []RouteEntry) string {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Destination < entries[j].Destination
	})

	var buf strings.Builder
	fmt.Fprintf(&buf, "%-3s %-40s %-4s %-20s %s\n", "A/S", "Destination", "P", "Next-hop", "Interface")
	for _, e := range entries {
		tag := protoTag(e.Protocol)
		marker := "* "
		nh := e.NextHop
		if nh == "" {
			nh = ">"
		}
		fmt.Fprintf(&buf, "%-3s %-40s %-4s %-20s %s\n", marker, e.Destination, tag, nh, e.Interface)
	}
	return buf.String()
}

// GetVRFRoutes reads routes from a VRF's routing table by VRF device name.
func (m *Manager) GetVRFRoutes(vrfName string) ([]RouteEntry, error) {
	link, err := m.nlHandle.LinkByName(vrfName)
	if err != nil {
		return nil, fmt.Errorf("VRF %q not found: %w", vrfName, err)
	}
	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return nil, fmt.Errorf("%q is not a VRF device", vrfName)
	}
	return m.GetRoutesForTable(int(vrf.Table))
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

// nextTableRulePriority is the base priority for next-table ip rules.
// Lower values = higher priority. We use 100-199 range for next-table rules.
const nextTableRulePriority = 100

// ribGroupRulePriority is the base priority for rib-group ip rules.
// Must be AFTER the main table (32766) so VRF routes supplement rather
// than override main table routing. We use 33000-33099 range.
const ribGroupRulePriority = 33000

// ApplyNextTableRules creates Linux policy routing rules (ip rule) for
// static routes with next-table directives. This implements inter-VRF
// route leaking: "route X/Y next-table Instance.inet.0" means traffic
// to X/Y should be looked up in Instance's routing table.
func (m *Manager) ApplyNextTableRules(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig) error {
	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Clean up old next-table rules (priority range 100-199)
	if err := m.clearNextTableRules(); err != nil {
		slog.Warn("failed to clear old next-table rules", "err", err)
	}

	prio := nextTableRulePriority
	for _, sr := range routes {
		if sr.NextTable == "" {
			continue
		}
		tableID, ok := tableIDs[sr.NextTable]
		if !ok {
			slog.Warn("next-table references unknown routing instance",
				"destination", sr.Destination, "instance", sr.NextTable)
			continue
		}

		_, dst, err := net.ParseCIDR(sr.Destination)
		if err != nil {
			slog.Warn("invalid next-table destination", "destination", sr.Destination, "err", err)
			continue
		}

		family := unix.AF_INET
		if dst.IP.To4() == nil {
			family = unix.AF_INET6
		}

		rule := netlink.NewRule()
		rule.Dst = dst
		rule.Table = tableID
		rule.Priority = prio
		rule.Family = family

		if err := m.nlHandle.RuleAdd(rule); err != nil {
			slog.Warn("failed to add next-table rule",
				"destination", sr.Destination, "instance", sr.NextTable,
				"table", tableID, "err", err)
			continue
		}
		slog.Info("next-table rule added",
			"destination", sr.Destination, "instance", sr.NextTable, "table", tableID)
		prio++
	}
	return nil
}

// clearNextTableRules removes all ip rules in the next-table priority range.
func (m *Manager) clearNextTableRules() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := m.nlHandle.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority >= nextTableRulePriority && r.Priority < nextTableRulePriority+100 {
				if err := m.nlHandle.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale next-table rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// ApplyRibGroupRules creates Linux policy routing rules (ip rule) for
// rib-group route leaking. When a routing instance has interface-routes
// with a rib-group reference, the instance's routes are leaked to other
// tables listed in the rib-group's import-rib list.
//
// For example, if dmz-vr (table 101) has interface-routes rib-group "dmz-leak",
// and dmz-leak has import-rib [ dmz-vr.inet.0 inet.0 ], then an ip rule is
// created to make table 101 visible to main table lookups:
//
//	ip rule add from all lookup 101 pref 200
func (m *Manager) ApplyRibGroupRules(ribGroups map[string]*config.RibGroup, instances []*config.RoutingInstanceConfig) error {
	// Clean up old rib-group rules
	if err := m.clearRibGroupRules(); err != nil {
		slog.Warn("failed to clear old rib-group rules", "err", err)
	}

	if len(ribGroups) == 0 || len(instances) == 0 {
		return nil
	}

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Track which source tables we've already added rules for
	// (avoid duplicate rules if multiple rib-groups reference the same table)
	leakedTables := make(map[int]bool)

	prio := ribGroupRulePriority
	for _, inst := range instances {
		rgName := inst.InterfaceRoutesRibGroup
		if rgName == "" {
			continue
		}
		rg, ok := ribGroups[rgName]
		if !ok {
			slog.Warn("interface-routes references unknown rib-group",
				"instance", inst.Name, "rib-group", rgName)
			continue
		}

		sourceTable := inst.TableID

		// Check if any import-rib entry targets a different table (i.e., route leaking needed)
		needsLeak := false
		for _, ribName := range rg.ImportRibs {
			targetTable := resolveRibTable(ribName, tableIDs)
			if targetTable != sourceTable {
				needsLeak = true
				break
			}
		}
		if !needsLeak {
			continue
		}

		if leakedTables[sourceTable] {
			continue
		}
		leakedTables[sourceTable] = true

		// Add IPv4 rule
		rule := netlink.NewRule()
		rule.Table = sourceTable
		rule.Priority = prio
		rule.Family = unix.AF_INET

		if err := m.nlHandle.RuleAdd(rule); err != nil {
			slog.Warn("failed to add rib-group IPv4 rule",
				"instance", inst.Name, "table", sourceTable, "err", err)
		} else {
			slog.Info("rib-group rule added",
				"instance", inst.Name, "rib-group", rg.Name,
				"table", sourceTable, "family", "inet", "pref", prio)
		}
		prio++

		// Add IPv6 rule
		rule6 := netlink.NewRule()
		rule6.Table = sourceTable
		rule6.Priority = prio
		rule6.Family = unix.AF_INET6

		if err := m.nlHandle.RuleAdd(rule6); err != nil {
			slog.Warn("failed to add rib-group IPv6 rule",
				"instance", inst.Name, "table", sourceTable, "err", err)
		} else {
			slog.Info("rib-group rule added",
				"instance", inst.Name, "rib-group", rg.Name,
				"table", sourceTable, "family", "inet6", "pref", prio)
		}
		prio++
	}
	return nil
}

// clearRibGroupRules removes all ip rules in the rib-group priority range.
// Also cleans up legacy rules from the old 200-299 range.
func (m *Manager) clearRibGroupRules() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := m.nlHandle.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			inCurrent := r.Priority >= ribGroupRulePriority && r.Priority < ribGroupRulePriority+100
			inLegacy := r.Priority >= 200 && r.Priority < 300
			if inCurrent || inLegacy {
				if err := m.nlHandle.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale rib-group rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// pbrRulePriority is the base priority for policy-based routing ip rules.
// After rib-group rules (33000-33099), before the default table (32766 is main).
// We use 34000-34999 range.
const pbrRulePriority = 34000

// PBRRule describes a single policy-based routing rule derived from a
// firewall filter term with a routing-instance action.
type PBRRule struct {
	Family   int    // unix.AF_INET or unix.AF_INET6
	TOS      uint8  // TOS byte (DSCP << 2), 0 = no TOS match
	Src      string // source CIDR, "" = any
	Dst      string // destination CIDR, "" = any
	TableID  int    // target routing table
	Instance string // routing instance name (for logging)
}

// ApplyPBRRules creates Linux policy routing rules (ip rule) for firewall
// filter terms that use a routing-instance action. This implements
// policy-based routing: traffic matching DSCP/source/destination criteria
// is routed via the specified VRF's routing table.
func (m *Manager) ApplyPBRRules(rules []PBRRule) error {
	// Clean up old PBR rules first
	if err := m.clearPBRRules(); err != nil {
		slog.Warn("failed to clear old PBR rules", "err", err)
	}

	if len(rules) == 0 {
		return nil
	}

	prio := pbrRulePriority
	for _, pbr := range rules {
		rule := netlink.NewRule()
		rule.Table = pbr.TableID
		rule.Priority = prio
		rule.Family = pbr.Family

		if pbr.TOS != 0 {
			rule.Tos = uint(pbr.TOS)
		}
		if pbr.Src != "" {
			_, src, err := net.ParseCIDR(pbr.Src)
			if err != nil {
				slog.Warn("invalid PBR source", "src", pbr.Src, "err", err)
				continue
			}
			rule.Src = src
		}
		if pbr.Dst != "" {
			_, dst, err := net.ParseCIDR(pbr.Dst)
			if err != nil {
				slog.Warn("invalid PBR destination", "dst", pbr.Dst, "err", err)
				continue
			}
			rule.Dst = dst
		}

		if err := m.nlHandle.RuleAdd(rule); err != nil {
			slog.Warn("failed to add PBR rule",
				"instance", pbr.Instance, "tos", pbr.TOS,
				"src", pbr.Src, "dst", pbr.Dst,
				"table", pbr.TableID, "err", err)
			continue
		}
		slog.Info("PBR rule added",
			"instance", pbr.Instance, "tos", pbr.TOS,
			"src", pbr.Src, "dst", pbr.Dst, "table", pbr.TableID)
		prio++
		if prio >= pbrRulePriority+1000 {
			slog.Warn("PBR rule limit reached")
			break
		}
	}
	return nil
}

// clearPBRRules removes all ip rules in the PBR priority range.
func (m *Manager) clearPBRRules() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := m.nlHandle.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority >= pbrRulePriority && r.Priority < pbrRulePriority+1000 {
				if err := m.nlHandle.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale PBR rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// BuildPBRRules extracts policy-based routing rules from firewall filter
// configuration. Each filter term with a routing-instance action produces
// one or more PBR rules depending on the match criteria.
func BuildPBRRules(fw *config.FirewallConfig, instances []*config.RoutingInstanceConfig) []PBRRule {
	if fw == nil {
		return nil
	}

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	var rules []PBRRule
	// Process inet filters
	for _, filter := range fw.FiltersInet {
		rules = append(rules, buildPBRFromFilter(filter, unix.AF_INET, tableIDs)...)
	}
	// Process inet6 filters
	for _, filter := range fw.FiltersInet6 {
		rules = append(rules, buildPBRFromFilter(filter, unix.AF_INET6, tableIDs)...)
	}
	return rules
}

// buildPBRFromFilter extracts PBR rules from a single firewall filter.
func buildPBRFromFilter(filter *config.FirewallFilter, family int, tableIDs map[string]int) []PBRRule {
	var rules []PBRRule
	for _, term := range filter.Terms {
		if term.RoutingInstance == "" {
			continue
		}
		tableID, ok := tableIDs[term.RoutingInstance]
		if !ok {
			slog.Warn("PBR: routing-instance not found",
				"filter", filter.Name, "term", term.Name,
				"instance", term.RoutingInstance)
			continue
		}

		// Determine TOS byte from DSCP value
		var tos uint8
		if term.DSCP != "" {
			tos = dscpToTOS(term.DSCP)
		}

		// If the term has source/dest addresses, create a rule per address.
		// If it has neither addresses nor DSCP, we can't express it as ip rule.
		srcs := term.SourceAddresses
		dsts := term.DestAddresses
		if len(srcs) == 0 {
			srcs = []string{""}
		}
		if len(dsts) == 0 {
			dsts = []string{""}
		}

		// Check if we have anything ip rule can match on
		hasCriteria := tos != 0 || term.SourceAddresses != nil || term.DestAddresses != nil
		if !hasCriteria {
			slog.Warn("PBR: filter term has routing-instance but no ip-rule-compatible criteria (dscp, source-address, destination-address)",
				"filter", filter.Name, "term", term.Name)
			continue
		}

		for _, src := range srcs {
			for _, dst := range dsts {
				rules = append(rules, PBRRule{
					Family:   family,
					TOS:      tos,
					Src:      src,
					Dst:      dst,
					TableID:  tableID,
					Instance: term.RoutingInstance,
				})
			}
		}
	}
	return rules
}

// dscpToTOS converts a DSCP name or numeric value to a TOS byte.
// TOS byte = DSCP value << 2 (DSCP occupies the upper 6 bits of the TOS byte).
func dscpToTOS(dscp string) uint8 {
	// DSCP name → numeric value mapping (same values as dataplane.DSCPValues)
	dscpValues := map[string]uint8{
		"ef":   46,
		"af11": 10, "af12": 12, "af13": 14,
		"af21": 18, "af22": 20, "af23": 22,
		"af31": 26, "af32": 28, "af33": 30,
		"af41": 34, "af42": 36, "af43": 38,
		"cs0": 0, "cs1": 8, "cs2": 16, "cs3": 24,
		"cs4": 32, "cs5": 40, "cs6": 48, "cs7": 56,
		"be": 0,
	}

	name := strings.ToLower(dscp)
	if val, ok := dscpValues[name]; ok {
		return val << 2
	}
	if v, err := strconv.Atoi(dscp); err == nil && v >= 0 && v <= 63 {
		return uint8(v) << 2
	}
	return 0
}

// resolveRibTable maps a Junos RIB name to a Linux routing table ID.
// "inet.0" or "inet6.0" maps to main table (254).
// "<instance>.inet.0" or "<instance>.inet6.0" maps to the instance's table.
func resolveRibTable(ribName string, tableIDs map[string]int) int {
	if ribName == "inet.0" || ribName == "inet6.0" {
		return 254 // main table
	}
	// Parse "instance-name.inet.0" or "instance-name.inet6.0"
	if idx := strings.Index(ribName, ".inet"); idx > 0 {
		instanceName := ribName[:idx]
		if tableID, ok := tableIDs[instanceName]; ok {
			return tableID
		}
	}
	return 0
}
