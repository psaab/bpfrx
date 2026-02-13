// Package frr generates FRR configuration and queries routing state via vtysh.
package frr

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

const (
	// DefaultFRRConf is the main FRR config file.
	DefaultFRRConf = "/etc/frr/frr.conf"

	markerBegin = "! BEGIN BPFRX MANAGED CONFIG - do not edit this section"
	markerEnd   = "! END BPFRX MANAGED CONFIG"
)

// Manager handles FRR config generation and state queries.
type Manager struct {
	frrConf string
}

// New creates a new FRR manager.
func New() *Manager {
	return &Manager{
		frrConf: DefaultFRRConf,
	}
}

// InstanceConfig pairs routing config with a VRF name for per-instance generation.
type InstanceConfig struct {
	VRFName      string
	OSPF         *config.OSPFConfig
	BGP          *config.BGPConfig
	RIP          *config.RIPConfig
	ISIS         *config.ISISConfig
	StaticRoutes []*config.StaticRoute
}

// DHCPRoute represents a default route learned via DHCP.
type DHCPRoute struct {
	Gateway   string // "10.0.2.1" or "fe80::1"
	Interface string // needed for IPv6 link-local gateways
	IsIPv6    bool
}

// FullConfig holds the complete routing config for a single FRR apply.
type FullConfig struct {
	OSPF          *config.OSPFConfig
	BGP           *config.BGPConfig
	RIP           *config.RIPConfig
	ISIS          *config.ISISConfig
	StaticRoutes  []*config.StaticRoute
	DHCPRoutes    []DHCPRoute
	Instances     []InstanceConfig
	PolicyOptions *config.PolicyOptionsConfig
}

// Apply generates an FRR config from OSPF/BGP settings and reloads FRR.
func (m *Manager) Apply(ospf *config.OSPFConfig, bgp *config.BGPConfig) error {
	return m.ApplyFull(&FullConfig{
		OSPF: ospf,
		BGP:  bgp,
	})
}

// ApplyWithInstances generates FRR config for the global context and per-VRF instances.
func (m *Manager) ApplyWithInstances(ospf *config.OSPFConfig, bgp *config.BGPConfig, instances []InstanceConfig) error {
	return m.ApplyFull(&FullConfig{
		OSPF:      ospf,
		BGP:       bgp,
		Instances: instances,
	})
}

// RIPRouteEntry represents a RIP route.
type RIPRouteEntry struct {
	Network  string
	NextHop  string
	Metric   string
	Interface string
}

// GetRIPRoutes queries FRR for RIP routes.
func (m *Manager) GetRIPRoutes() ([]RIPRouteEntry, error) {
	output, err := vtyshCmd("show ip rip")
	if err != nil {
		return nil, err
	}
	var routes []RIPRouteEntry
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Skip headers
		if fields[0] == "Network" || strings.HasPrefix(line, "Codes") || strings.HasPrefix(line, " ") && len(fields) < 3 {
			continue
		}
		r := RIPRouteEntry{Network: fields[0]}
		if len(fields) >= 2 {
			r.NextHop = fields[1]
		}
		if len(fields) >= 3 {
			r.Metric = fields[2]
		}
		if len(fields) >= 4 {
			r.Interface = fields[3]
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// ISISAdjacency represents an IS-IS adjacency.
type ISISAdjacency struct {
	SystemID  string
	Interface string
	Level     string
	State     string
	HoldTime  string
}

// GetISISAdjacency queries FRR for IS-IS adjacencies.
func (m *Manager) GetISISAdjacency() ([]ISISAdjacency, error) {
	output, err := vtyshCmd("show isis neighbor")
	if err != nil {
		return nil, err
	}
	var adjs []ISISAdjacency
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "System" || strings.HasPrefix(line, "Area") {
			continue
		}
		adj := ISISAdjacency{
			SystemID: fields[0],
		}
		if len(fields) >= 2 {
			adj.Interface = fields[1]
		}
		if len(fields) >= 3 {
			adj.Level = fields[2]
		}
		if len(fields) >= 4 {
			adj.State = fields[3]
		}
		if len(fields) >= 5 {
			adj.HoldTime = fields[4]
		}
		adjs = append(adjs, adj)
	}
	return adjs, nil
}

// GetISISRoutes returns raw IS-IS route output.
func (m *Manager) GetISISRoutes() (string, error) {
	return vtyshCmd("show isis route")
}

// ApplyFull generates the complete FRR config including static routes,
// DHCP-learned defaults, per-VRF routes, and dynamic protocols, then reloads FRR.
func (m *Manager) ApplyFull(fc *FullConfig) error {
	if fc == nil {
		return m.Clear()
	}

	hasContent := fc.OSPF != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil ||
		len(fc.StaticRoutes) > 0 || len(fc.DHCPRoutes) > 0
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil || len(inst.StaticRoutes) > 0 {
			hasContent = true
			break
		}
	}
	if !hasContent {
		return m.Clear()
	}

	var b strings.Builder
	b.WriteString("! bpfrx managed config - do not edit\n")
	b.WriteString("!\n")

	// Global static routes
	if len(fc.StaticRoutes) > 0 {
		for _, sr := range fc.StaticRoutes {
			b.WriteString(m.generateStaticRoute(sr, ""))
		}
		b.WriteString("!\n")
	}

	// DHCP-learned default routes (admin distance 200)
	if len(fc.DHCPRoutes) > 0 {
		for _, dr := range fc.DHCPRoutes {
			if dr.IsIPv6 {
				if dr.Interface != "" {
					fmt.Fprintf(&b, "ipv6 route ::/0 %s %s 200\n", dr.Gateway, dr.Interface)
				} else {
					fmt.Fprintf(&b, "ipv6 route ::/0 %s 200\n", dr.Gateway)
				}
			} else {
				fmt.Fprintf(&b, "ip route 0.0.0.0/0 %s 200\n", dr.Gateway)
			}
		}
		b.WriteString("!\n")
	}

	// Per-VRF static routes and dynamic protocols
	for _, inst := range fc.Instances {
		if len(inst.StaticRoutes) > 0 {
			for _, sr := range inst.StaticRoutes {
				b.WriteString(m.generateStaticRoute(sr, inst.VRFName))
			}
			b.WriteString("!\n")
		}
	}

	// Policy options: prefix-lists and route-maps
	if fc.PolicyOptions != nil {
		b.WriteString(m.generatePolicyOptions(fc.PolicyOptions))
	}

	// Global dynamic protocols
	if fc.OSPF != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil {
		b.WriteString(m.generateProtocols(fc.OSPF, fc.BGP, fc.RIP, fc.ISIS, ""))
	}

	// Per-VRF dynamic protocols
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil {
			b.WriteString(m.generateProtocols(inst.OSPF, inst.BGP, inst.RIP, inst.ISIS, inst.VRFName))
		}
	}

	section := b.String()

	if err := m.writeManagedSection(section); err != nil {
		return err
	}

	slog.Info("FRR config written", "path", m.frrConf)

	// Reload FRR (frr-reload.py diffs running vs on-disk config)
	if err := m.reload(); err != nil {
		slog.Warn("FRR reload failed", "err", err)
		return err
	}

	return nil
}

// generateStaticRoute produces FRR static route commands.
// Multiple next-hops produce one line each (FRR creates ECMP).
func (m *Manager) generateStaticRoute(sr *config.StaticRoute, vrfName string) string {
	isV6 := strings.Contains(sr.Destination, ":")
	prefix := "ip"
	if isV6 {
		prefix = "ipv6"
	}

	vrfPart := ""
	if vrfName != "" {
		vrfPart = " vrf " + vrfName
	}

	// Discard or no next-hops: single Null0 line.
	if sr.Discard || len(sr.NextHops) == 0 {
		nexthop := "Null0"
		if sr.Preference > 0 {
			return fmt.Sprintf("%s route %s %s %d%s\n", prefix, sr.Destination, nexthop, sr.Preference, vrfPart)
		}
		return fmt.Sprintf("%s route %s %s%s\n", prefix, sr.Destination, nexthop, vrfPart)
	}

	// One line per next-hop → FRR creates ECMP.
	var b strings.Builder
	for _, nh := range sr.NextHops {
		var nexthop string
		switch {
		case nh.Address != "" && nh.Interface != "":
			nexthop = nh.Address + " " + nh.Interface
		case nh.Address != "":
			nexthop = nh.Address
		case nh.Interface != "":
			nexthop = nh.Interface
		default:
			continue
		}
		if sr.Preference > 0 {
			fmt.Fprintf(&b, "%s route %s %s %d%s\n", prefix, sr.Destination, nexthop, sr.Preference, vrfPart)
		} else {
			fmt.Fprintf(&b, "%s route %s %s%s\n", prefix, sr.Destination, nexthop, vrfPart)
		}
	}
	return b.String()
}

// Clear removes the bpfrx managed section from frr.conf and reloads FRR.
func (m *Manager) Clear() error {
	if err := m.writeManagedSection(""); err != nil {
		return err
	}
	_ = m.reload()
	return nil
}

// writeManagedSection replaces the bpfrx-managed section in frr.conf.
// If section is empty, the managed block is removed entirely.
func (m *Manager) writeManagedSection(section string) error {
	existing, err := os.ReadFile(m.frrConf)
	if err != nil {
		if os.IsNotExist(err) {
			existing = []byte("log syslog informational\n")
		} else {
			return fmt.Errorf("read frr.conf: %w", err)
		}
	}

	// Strip existing managed section
	content := string(existing)
	if start := strings.Index(content, markerBegin); start >= 0 {
		end := strings.Index(content, markerEnd)
		if end >= 0 {
			end += len(markerEnd)
			// Also consume the trailing newline
			if end < len(content) && content[end] == '\n' {
				end++
			}
			content = content[:start] + content[end:]
		}
	}

	// Append new managed section
	if section != "" {
		content = strings.TrimRight(content, "\n") + "\n"
		content += markerBegin + "\n"
		content += section
		content += markerEnd + "\n"
	}

	if err := os.WriteFile(m.frrConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("write frr.conf: %w", err)
	}
	return nil
}

// generateOSPFBGP generates FRR CLI config for OSPF and/or BGP.
// If vrfName is non-empty, generates VRF-scoped commands.
func (m *Manager) generateProtocols(ospf *config.OSPFConfig, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string) string {
	var b strings.Builder

	vrfSuffix := ""
	if vrfName != "" {
		vrfSuffix = " vrf " + vrfName
	}

	if ospf != nil {
		fmt.Fprintf(&b, "router ospf%s\n", vrfSuffix)
		if ospf.RouterID != "" {
			fmt.Fprintf(&b, " ospf router-id %s\n", ospf.RouterID)
		}
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, " network %s area %s\n",
					ifaceNetwork(iface.Name), area.ID)
				if iface.Passive {
					fmt.Fprintf(&b, " passive-interface %s\n", iface.Name)
				}
			}
		}
		for _, export := range ospf.Export {
			fmt.Fprintf(&b, " redistribute %s\n", export)
		}
		b.WriteString("exit\n!\n")
		// OSPF interface costs
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				if iface.Cost > 0 {
					fmt.Fprintf(&b, "interface %s\n ip ospf cost %d\n ip ospf area %s\nexit\n!\n",
						iface.Name, iface.Cost, area.ID)
				}
			}
		}
	}

	if bgp != nil && bgp.LocalAS > 0 {
		fmt.Fprintf(&b, "router bgp %d%s\n", bgp.LocalAS, vrfSuffix)
		if bgp.RouterID != "" {
			fmt.Fprintf(&b, " bgp router-id %s\n", bgp.RouterID)
		}
		for _, n := range bgp.Neighbors {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", n.Address, n.PeerAS)
			if n.Description != "" {
				fmt.Fprintf(&b, " neighbor %s description %s\n", n.Address, n.Description)
			}
			if n.MultihopTTL > 0 {
				fmt.Fprintf(&b, " neighbor %s ebgp-multihop %d\n", n.Address, n.MultihopTTL)
			}
		}
		for _, export := range bgp.Export {
			fmt.Fprintf(&b, " redistribute %s\n", export)
		}

		// Address-family blocks for neighbors with family declarations
		var inet4Neighbors, inet6Neighbors []*config.BGPNeighbor
		for _, n := range bgp.Neighbors {
			if n.FamilyInet {
				inet4Neighbors = append(inet4Neighbors, n)
			}
			if n.FamilyInet6 {
				inet6Neighbors = append(inet6Neighbors, n)
			}
		}
		if len(inet4Neighbors) > 0 {
			b.WriteString(" !\n address-family ipv4 unicast\n")
			for _, n := range inet4Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				for _, exp := range n.Export {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, exp)
				}
			}
			b.WriteString(" exit-address-family\n")
		}
		if len(inet6Neighbors) > 0 {
			b.WriteString(" !\n address-family ipv6 unicast\n")
			for _, n := range inet6Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				for _, exp := range n.Export {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, exp)
				}
			}
			b.WriteString(" exit-address-family\n")
		}

		b.WriteString("exit\n!\n")
	}

	if rip != nil {
		fmt.Fprintf(&b, "router rip%s\n", vrfSuffix)
		for _, iface := range rip.Interfaces {
			fmt.Fprintf(&b, " network %s\n", iface)
		}
		for _, iface := range rip.Passive {
			fmt.Fprintf(&b, " passive-interface %s\n", iface)
		}
		for _, r := range rip.Redistribute {
			fmt.Fprintf(&b, " redistribute %s\n", r)
		}
		b.WriteString("exit\n!\n")
	}

	if isis != nil {
		fmt.Fprintf(&b, "router isis bpfrx%s\n", vrfSuffix)
		if isis.NET != "" {
			fmt.Fprintf(&b, " net %s\n", isis.NET)
		}
		level := isis.Level
		if level == "" {
			level = "level-2"
		}
		switch level {
		case "level-1":
			b.WriteString(" is-type level-1\n")
		case "level-2":
			b.WriteString(" is-type level-2-only\n")
		case "level-1-2":
			b.WriteString(" is-type level-1-2\n")
		}
		for _, export := range isis.Export {
			fmt.Fprintf(&b, " redistribute %s\n", export)
		}
		b.WriteString("exit\n!\n")
		for _, iface := range isis.Interfaces {
			fmt.Fprintf(&b, "interface %s\n", iface.Name)
			fmt.Fprintf(&b, " ip router isis bpfrx\n")
			if iface.Passive {
				b.WriteString(" isis passive\n")
			}
			if iface.Metric > 0 {
				fmt.Fprintf(&b, " isis metric %d\n", iface.Metric)
			}
			b.WriteString("exit\n!\n")
		}
	}

	return b.String()
}

func (m *Manager) reload() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Try systemctl reload first (runs frr-reload.py which diffs running vs frr.conf)
	cmd := exec.CommandContext(ctx, "systemctl", "reload", "frr")
	if err := cmd.Run(); err == nil {
		slog.Info("FRR reloaded via systemctl")
		return nil
	}

	// Fallback: load config directly via vtysh
	cmd = exec.CommandContext(ctx, "vtysh", "-f", m.frrConf)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vtysh reload: %w: %s", err, string(output))
	}
	slog.Info("FRR config loaded via vtysh")
	return nil
}

// ifaceNetwork returns a placeholder network string for an interface.
// In real use FRR matches based on interface addresses.
func ifaceNetwork(name string) string {
	// Use 0.0.0.0/0 as a catch-all; FRR resolves per-interface
	return "0.0.0.0/0"
}

// OSPFNeighbor represents an OSPF neighbor.
type OSPFNeighbor struct {
	NeighborID string
	Priority   string
	State      string
	Address    string
	Interface  string
}

// GetOSPFNeighbors queries FRR for OSPF neighbor state.
func (m *Manager) GetOSPFNeighbors() ([]OSPFNeighbor, error) {
	output, err := vtyshCmd("show ip ospf neighbor")
	if err != nil {
		return nil, err
	}

	var neighbors []OSPFNeighbor
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Skip header lines
		if fields[0] == "Neighbor" || strings.HasPrefix(line, "-") {
			continue
		}
		n := OSPFNeighbor{
			NeighborID: fields[0],
			Priority:   fields[1],
			State:      fields[2],
		}
		if len(fields) >= 5 {
			n.Address = fields[len(fields)-2]
			n.Interface = fields[len(fields)-1]
		}
		neighbors = append(neighbors, n)
	}
	return neighbors, nil
}

// GetOSPFDatabase returns raw OSPF database output.
func (m *Manager) GetOSPFDatabase() (string, error) {
	return vtyshCmd("show ip ospf database")
}

// BGPPeerSummary represents a BGP peer in the summary.
type BGPPeerSummary struct {
	Neighbor string
	AS       string
	MsgRcvd  string
	MsgSent  string
	UpDown   string
	State    string
	PfxRcd   string
}

// GetBGPSummary queries FRR for BGP peer summary.
func (m *Manager) GetBGPSummary() ([]BGPPeerSummary, error) {
	output, err := vtyshCmd("show bgp summary")
	if err != nil {
		return nil, err
	}

	var peers []BGPPeerSummary
	lines := strings.Split(output, "\n")
	inTable := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Neighbor") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		p := BGPPeerSummary{
			Neighbor: fields[0],
			AS:       fields[2],
		}
		if len(fields) >= 10 {
			p.MsgRcvd = fields[3]
			p.MsgSent = fields[4]
			p.UpDown = fields[8]
			p.State = fields[9]
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// BGPRoute represents a BGP route.
type BGPRoute struct {
	Network string
	NextHop string
	Metric  string
	Path    string
}

// GetBGPRoutes queries FRR for BGP routes.
func (m *Manager) GetBGPRoutes() ([]BGPRoute, error) {
	output, err := vtyshCmd("show bgp ipv4 unicast")
	if err != nil {
		return nil, err
	}

	var routes []BGPRoute
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, " ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		r := BGPRoute{
			Network: fields[1],
			NextHop: fields[2],
		}
		if len(fields) >= 5 {
			r.Path = strings.Join(fields[4:], " ")
		}
		routes = append(routes, r)
	}
	return routes, nil
}

func (m *Manager) generatePolicyOptions(po *config.PolicyOptionsConfig) string {
	var b strings.Builder

	// Generate FRR prefix-lists from Junos prefix-lists
	names := make([]string, 0, len(po.PrefixLists))
	for name := range po.PrefixLists {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pl := po.PrefixLists[name]
		for i, prefix := range pl.Prefixes {
			if strings.Contains(prefix, ":") {
				fmt.Fprintf(&b, "ipv6 prefix-list %s seq %d permit %s\n", name, (i+1)*5, prefix)
			} else {
				fmt.Fprintf(&b, "ip prefix-list %s seq %d permit %s\n", name, (i+1)*5, prefix)
			}
		}
	}
	if len(po.PrefixLists) > 0 {
		b.WriteString("!\n")
	}

	// Generate FRR route-maps from Junos policy-statements
	psNames := make([]string, 0, len(po.PolicyStatements))
	for name := range po.PolicyStatements {
		psNames = append(psNames, name)
	}
	sort.Strings(psNames)
	for _, name := range psNames {
		ps := po.PolicyStatements[name]
		seq := 10
		for _, term := range ps.Terms {
			action := "permit"
			if term.Action == "reject" {
				action = "deny"
			}
			fmt.Fprintf(&b, "route-map %s %s %d\n", name, action, seq)

			// Generate an inline prefix-list for route-filters
			if len(term.RouteFilters) > 0 {
				plName := name + "-" + term.Name
				for i, rf := range term.RouteFilters {
					matchStr := "le 32"
					if strings.Contains(rf.Prefix, ":") {
						matchStr = "le 128"
					}
					switch rf.MatchType {
					case "exact":
						matchStr = ""
					case "longer":
						matchStr = "ge 1"
					case "orlonger":
						// orlonger = exact match or any longer prefix
						matchStr = "" // already matches prefix itself
					}
					if strings.Contains(rf.Prefix, ":") {
						fmt.Fprintf(&b, "ipv6 prefix-list %s seq %d permit %s", plName, (i+1)*5, rf.Prefix)
					} else {
						fmt.Fprintf(&b, "ip prefix-list %s seq %d permit %s", plName, (i+1)*5, rf.Prefix)
					}
					if matchStr != "" {
						fmt.Fprintf(&b, " %s", matchStr)
					}
					b.WriteString("\n")
				}
				if strings.Contains(term.RouteFilters[0].Prefix, ":") {
					fmt.Fprintf(&b, " match ipv6 address prefix-list %s\n", plName)
				} else {
					fmt.Fprintf(&b, " match ip address prefix-list %s\n", plName)
				}
			}

			if term.FromProtocol != "" {
				proto := term.FromProtocol
				if proto == "direct" {
					proto = "connected"
				}
				fmt.Fprintf(&b, " match source-protocol %s\n", proto)
			}

			b.WriteString("exit\n")
			seq += 10
		}

		// Default action
		if ps.DefaultAction == "reject" || ps.DefaultAction == "" {
			fmt.Fprintf(&b, "route-map %s deny %d\n", name, seq)
			b.WriteString("exit\n")
		} else if ps.DefaultAction == "accept" {
			fmt.Fprintf(&b, "route-map %s permit %d\n", name, seq)
			b.WriteString("exit\n")
		}
		b.WriteString("!\n")
	}

	return b.String()
}

func vtyshCmd(command string) (string, error) {
	cmd := exec.Command("vtysh", "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vtysh %q: %w: %s", command, err, stderr.String())
	}
	return stdout.String(), nil
}
