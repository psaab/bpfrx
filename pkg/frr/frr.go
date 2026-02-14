// Package frr generates FRR configuration and queries routing state via vtysh.
package frr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strconv"
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
	OSPFv3       *config.OSPFv3Config
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
	OSPFv3        *config.OSPFv3Config
	BGP           *config.BGPConfig
	RIP           *config.RIPConfig
	ISIS          *config.ISISConfig
	StaticRoutes      []*config.StaticRoute
	Inet6StaticRoutes []*config.StaticRoute // rib inet6.0 static routes
	DHCPRoutes        []DHCPRoute
	Instances         []InstanceConfig
	PolicyOptions     *config.PolicyOptionsConfig

	// ForwardingTableExport is the export policy for the forwarding table (ECMP).
	ForwardingTableExport string

	// BackupRouter is the fallback default gateway (system backup-router).
	// Installed with admin distance 250 so it's only used when all other defaults fail.
	BackupRouter    string // next-hop IP (e.g. "192.168.50.1")
	BackupRouterDst string // destination prefix (e.g. "192.168.0.0/16"), default "0.0.0.0/0"

	// ConsistentHash is set when the forwarding-table export policy uses
	// "load-balance consistent-hash". The daemon should set
	// net.ipv4.fib_multipath_hash_policy=1 for L4 ECMP hashing.
	ConsistentHash bool
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

	hasContent := fc.OSPF != nil || fc.OSPFv3 != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil ||
		len(fc.StaticRoutes) > 0 || len(fc.Inet6StaticRoutes) > 0 || len(fc.DHCPRoutes) > 0 || fc.BackupRouter != ""
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.OSPFv3 != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil || len(inst.StaticRoutes) > 0 {
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

	// IPv6 RIB static routes (rib inet6.0)
	if len(fc.Inet6StaticRoutes) > 0 {
		for _, sr := range fc.Inet6StaticRoutes {
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

	// Backup router: fallback default gateway with admin distance 250
	if fc.BackupRouter != "" {
		dst := fc.BackupRouterDst
		if dst == "" {
			dst = "0.0.0.0/0"
		}
		prefix := "ip"
		if strings.Contains(dst, ":") {
			prefix = "ipv6"
		}
		fmt.Fprintf(&b, "%s route %s %s 250\n", prefix, dst, fc.BackupRouter)
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

	// Resolve forwarding-table export policy for ECMP.
	// If the referenced policy has "load-balance per-packet" or "consistent-hash",
	// enable ECMP multipath (maximum-paths 64) in BGP/OSPF.
	// "consistent-hash" additionally signals the daemon to set
	// fib_multipath_hash_policy=1 for L4 hashing.
	ecmpMaxPaths := 0
	if fc.ForwardingTableExport != "" && fc.PolicyOptions != nil {
		if ps, ok := fc.PolicyOptions.PolicyStatements[fc.ForwardingTableExport]; ok {
			for _, term := range ps.Terms {
				if term.LoadBalance != "" {
					ecmpMaxPaths = 64
				}
				if term.LoadBalance == "consistent-hash" {
					fc.ConsistentHash = true
				}
			}
		}
	}

	// Global dynamic protocols
	if fc.OSPF != nil || fc.OSPFv3 != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil {
		b.WriteString(m.generateProtocols(fc.OSPF, fc.OSPFv3, fc.BGP, fc.RIP, fc.ISIS, "", ecmpMaxPaths, fc.PolicyOptions))
	}

	// Per-VRF dynamic protocols
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.OSPFv3 != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil {
			b.WriteString(m.generateProtocols(inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS, inst.VRFName, ecmpMaxPaths, fc.PolicyOptions))
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
// Routes with NextTable are handled via ip rule (policy routing), not FRR.
func (m *Manager) generateStaticRoute(sr *config.StaticRoute, vrfName string) string {
	if sr.NextTable != "" {
		return "" // handled via ip rule in routing package
	}
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
		// Strip Junos default unit suffix ".0" (e.g. "wan0.0" → "wan0") for FRR
		// kernel names. VLAN suffixes like ".50" in "wan0.50" are real kernel
		// interface names and must NOT be stripped.
		ifName := nh.Interface
		if strings.HasSuffix(ifName, ".0") {
			ifName = ifName[:len(ifName)-2]
		}

		var nexthop string
		switch {
		case nh.Address != "" && ifName != "":
			nexthop = nh.Address + " " + ifName
		case nh.Address != "":
			nexthop = nh.Address
		case ifName != "":
			nexthop = ifName
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

// knownRedistProtocols are the FRR redistribute protocol keywords.
var knownRedistProtocols = map[string]bool{
	"connected": true, "static": true, "ospf": true, "bgp": true,
	"rip": true, "isis": true, "kernel": true,
}

// resolveRedistribute converts a Junos export value into FRR redistribute commands.
// If the value is a known protocol name, it emits a bare "redistribute <proto>".
// If it matches a policy-statement, it extracts protocols from the terms and emits
// "redistribute <proto> route-map <name>" for each.
func (m *Manager) resolveRedistribute(export string, po *config.PolicyOptionsConfig) string {
	if knownRedistProtocols[export] {
		return fmt.Sprintf(" redistribute %s\n", export)
	}

	if po != nil && po.PolicyStatements != nil {
		if ps, ok := po.PolicyStatements[export]; ok {
			protocols := make(map[string]bool)
			for _, term := range ps.Terms {
				if term.FromProtocol != "" {
					proto := term.FromProtocol
					if proto == "direct" {
						proto = "connected"
					}
					protocols[proto] = true
				}
			}
			if len(protocols) > 0 {
				sorted := make([]string, 0, len(protocols))
				for p := range protocols {
					sorted = append(sorted, p)
				}
				sort.Strings(sorted)
				var sb strings.Builder
				for _, proto := range sorted {
					fmt.Fprintf(&sb, " redistribute %s route-map %s\n", proto, export)
				}
				return sb.String()
			}
		}
	}

	// Fallback: treat as bare redistribute (best-effort)
	return fmt.Sprintf(" redistribute %s\n", export)
}

// generateProtocols generates FRR CLI config for OSPF, BGP, RIP, and IS-IS.
// If vrfName is non-empty, generates VRF-scoped commands.
// ecmpMaxPaths > 1 enables ECMP with the given maximum equal-cost paths.
// policyOptions is used to resolve export policy names to route-map references.
func (m *Manager) generateProtocols(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig) string {
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
		if ospf.ReferenceBandwidth > 0 {
			fmt.Fprintf(&b, " auto-cost reference-bandwidth %d\n", ospf.ReferenceBandwidth)
		}
		if ospf.PassiveDefault {
			b.WriteString(" passive-interface default\n")
		}
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, " network %s area %s\n",
					ifaceNetwork(iface.Name), area.ID)
				if ospf.PassiveDefault {
					if iface.NoPassive {
						fmt.Fprintf(&b, " no passive-interface %s\n", iface.Name)
					}
				} else if iface.Passive {
					fmt.Fprintf(&b, " passive-interface %s\n", iface.Name)
				}
			}
			if area.AreaType != "" {
				if area.NoSummary {
					fmt.Fprintf(&b, " area %s %s no-summary\n", area.ID, area.AreaType)
				} else {
					fmt.Fprintf(&b, " area %s %s\n", area.ID, area.AreaType)
				}
			}
			for _, vl := range area.VirtualLinks {
				fmt.Fprintf(&b, " area %s virtual-link %s\n", vl.TransitArea, vl.NeighborID)
			}
		}
		if ecmpMaxPaths > 1 {
			fmt.Fprintf(&b, " maximum-paths %d\n", ecmpMaxPaths)
		}
		for _, export := range ospf.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions))
		}
		b.WriteString("exit\n!\n")
		// OSPF interface settings (cost, authentication, BFD)
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				if iface.Cost > 0 || iface.NetworkType != "" || iface.AuthType != "" || iface.BFD {
					fmt.Fprintf(&b, "interface %s\n", iface.Name)
					if iface.Cost > 0 {
						fmt.Fprintf(&b, " ip ospf cost %d\n", iface.Cost)
					}
					if iface.NetworkType != "" {
						fmt.Fprintf(&b, " ip ospf network %s\n", iface.NetworkType)
					}
					if iface.AuthType == "md5" {
						b.WriteString(" ip ospf authentication message-digest\n")
						keyID := iface.AuthKeyID
						if keyID == 0 {
							keyID = 1
						}
						fmt.Fprintf(&b, " ip ospf message-digest-key %d md5 %s\n", keyID, iface.AuthKey)
					} else if iface.AuthType == "simple" {
						b.WriteString(" ip ospf authentication\n")
						fmt.Fprintf(&b, " ip ospf authentication-key %s\n", iface.AuthKey)
					}
					if iface.BFD {
						b.WriteString(" ip ospf bfd\n")
					}
					fmt.Fprintf(&b, " ip ospf area %s\n", area.ID)
					b.WriteString("exit\n!\n")
				}
			}
		}
	}

	if ospfv3 != nil {
		fmt.Fprintf(&b, "router ospf6%s\n", vrfSuffix)
		if ospfv3.RouterID != "" {
			fmt.Fprintf(&b, " ospf6 router-id %s\n", ospfv3.RouterID)
		}
		for _, area := range ospfv3.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, " interface %s area %s\n", iface.Name, area.ID)
			}
		}
		for _, export := range ospfv3.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions))
		}
		b.WriteString("exit\n!\n")
		for _, area := range ospfv3.Areas {
			for _, iface := range area.Interfaces {
				if iface.Cost > 0 || iface.Passive {
					fmt.Fprintf(&b, "interface %s\n", iface.Name)
					if iface.Passive {
						b.WriteString(" ipv6 ospf6 passive\n")
					}
					if iface.Cost > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 cost %d\n", iface.Cost)
					}
					b.WriteString("exit\n!\n")
				}
			}
		}
	}

	if bgp != nil && bgp.LocalAS > 0 {
		fmt.Fprintf(&b, "router bgp %d%s\n", bgp.LocalAS, vrfSuffix)
		if bgp.RouterID != "" {
			fmt.Fprintf(&b, " bgp router-id %s\n", bgp.RouterID)
		}
		if bgp.ClusterID != "" {
			fmt.Fprintf(&b, " bgp cluster-id %s\n", bgp.ClusterID)
		}
		if bgp.GracefulRestart {
			b.WriteString(" bgp graceful-restart\n")
		}
		if bgp.LogNeighborChanges {
			b.WriteString(" bgp log-neighbor-changes\n")
		}
		if bgp.MultipathMultipleAS {
			b.WriteString(" bgp bestpath as-path multipath-relax\n")
		}
		if bgp.Dampening {
			hl := bgp.DampeningHalfLife
			if hl == 0 {
				hl = 15
			}
			reuse := bgp.DampeningReuse
			if reuse == 0 {
				reuse = 750
			}
			suppress := bgp.DampeningSuppress
			if suppress == 0 {
				suppress = 2000
			}
			maxSup := bgp.DampeningMaxSuppress
			if maxSup == 0 {
				maxSup = 60
			}
			fmt.Fprintf(&b, " bgp dampening %d %d %d %d\n", hl, reuse, suppress, maxSup)
		}
		for _, n := range bgp.Neighbors {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", n.Address, n.PeerAS)
			if n.Description != "" {
				fmt.Fprintf(&b, " neighbor %s description %s\n", n.Address, n.Description)
			}
			if n.MultihopTTL > 0 {
				fmt.Fprintf(&b, " neighbor %s ebgp-multihop %d\n", n.Address, n.MultihopTTL)
			}
			if n.AuthPassword != "" {
				fmt.Fprintf(&b, " neighbor %s password %s\n", n.Address, n.AuthPassword)
			}
			if n.BFD {
				fmt.Fprintf(&b, " neighbor %s bfd\n", n.Address)
			}
			if n.RouteReflectorClient {
				fmt.Fprintf(&b, " neighbor %s route-reflector-client\n", n.Address)
			}
			if n.AllowASIn > 0 {
				fmt.Fprintf(&b, " neighbor %s allowas-in %d\n", n.Address, n.AllowASIn)
			}
			if n.RemovePrivateAS {
				fmt.Fprintf(&b, " neighbor %s remove-private-AS\n", n.Address)
			}
		}
		for _, export := range bgp.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions))
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
		bgpMaxPaths := ecmpMaxPaths
		if bgp.Multipath > 0 && bgpMaxPaths < bgp.Multipath {
			bgpMaxPaths = bgp.Multipath
		}
		if len(inet4Neighbors) > 0 || bgpMaxPaths > 1 {
			b.WriteString(" !\n address-family ipv4 unicast\n")
			if bgpMaxPaths > 1 {
				fmt.Fprintf(&b, "  maximum-paths %d\n", bgpMaxPaths)
			}
			for _, n := range inet4Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				if n.DefaultOriginate {
					fmt.Fprintf(&b, "  neighbor %s default-originate\n", n.Address)
				}
				if n.PrefixLimitInet > 0 {
					fmt.Fprintf(&b, "  neighbor %s maximum-prefix %d\n", n.Address, n.PrefixLimitInet)
				}
				for _, exp := range n.Export {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, exp)
				}
			}
			b.WriteString(" exit-address-family\n")
		}
		if len(inet6Neighbors) > 0 || bgpMaxPaths > 1 {
			b.WriteString(" !\n address-family ipv6 unicast\n")
			if bgpMaxPaths > 1 {
				fmt.Fprintf(&b, "  maximum-paths %d\n", bgpMaxPaths)
			}
			for _, n := range inet6Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				if n.DefaultOriginate {
					fmt.Fprintf(&b, "  neighbor %s default-originate\n", n.Address)
				}
				if n.PrefixLimitInet6 > 0 {
					fmt.Fprintf(&b, "  neighbor %s maximum-prefix %d\n", n.Address, n.PrefixLimitInet6)
				}
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
			b.WriteString(m.resolveRedistribute(r, policyOptions))
		}
		b.WriteString("exit\n!\n")
		// RIP per-interface authentication
		if rip.AuthKey != "" {
			for _, iface := range rip.Interfaces {
				fmt.Fprintf(&b, "interface %s\n", iface)
				if rip.AuthType == "md5" {
					b.WriteString(" ip rip authentication mode md5\n")
				} else {
					b.WriteString(" ip rip authentication mode text\n")
				}
				fmt.Fprintf(&b, " ip rip authentication string %s\n", rip.AuthKey)
				b.WriteString("exit\n!\n")
			}
		}
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
			b.WriteString(m.resolveRedistribute(export, policyOptions))
		}
		if isis.WideMetricsOnly {
			b.WriteString(" metric-style wide\n")
		}
		if isis.Overload {
			b.WriteString(" set-overload-bit\n")
		}
		if isis.AuthKey != "" {
			if isis.AuthType == "md5" {
				fmt.Fprintf(&b, " area-password md5 %s\n", isis.AuthKey)
				fmt.Fprintf(&b, " domain-password md5 %s\n", isis.AuthKey)
			} else {
				fmt.Fprintf(&b, " area-password clear %s\n", isis.AuthKey)
				fmt.Fprintf(&b, " domain-password clear %s\n", isis.AuthKey)
			}
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
			if iface.AuthKey != "" {
				if iface.AuthType == "md5" {
					fmt.Fprintf(&b, " isis password md5 %s\n", iface.AuthKey)
				} else {
					fmt.Fprintf(&b, " isis password clear %s\n", iface.AuthKey)
				}
			}
			b.WriteString("exit\n!\n")
		}
	}

	// BFD peer blocks for BGP neighbors with BFD enabled
	if bgp != nil {
		var bfdPeers []*config.BGPNeighbor
		for _, n := range bgp.Neighbors {
			if n.BFD {
				bfdPeers = append(bfdPeers, n)
			}
		}
		if len(bfdPeers) > 0 {
			b.WriteString("bfd\n")
			for _, n := range bfdPeers {
				fmt.Fprintf(&b, " peer %s\n", n.Address)
				multiplier := 3
				interval := n.BFDInterval
				if interval == 0 {
					interval = 300
				}
				fmt.Fprintf(&b, "  detect-multiplier %d\n", multiplier)
				fmt.Fprintf(&b, "  receive-interval %d\n", interval)
				fmt.Fprintf(&b, "  transmit-interval %d\n", interval)
				b.WriteString(" exit\n")
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

// GetOSPFInterface returns raw OSPF interface output.
func (m *Manager) GetOSPFInterface() (string, error) {
	return vtyshCmd("show ip ospf interface")
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

// GetBGPNeighborDetail returns detailed info for a specific BGP neighbor,
// or all neighbors if ip is empty.
func (m *Manager) GetBGPNeighborDetail(ip string) (string, error) {
	cmd := "show bgp neighbor"
	if ip != "" {
		cmd += " " + ip
	}
	return vtyshCmd(cmd)
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

	// Generate FRR community-lists from Junos community definitions
	commNames := make([]string, 0, len(po.Communities))
	for name := range po.Communities {
		commNames = append(commNames, name)
	}
	sort.Strings(commNames)
	for _, name := range commNames {
		cd := po.Communities[name]
		for _, member := range cd.Members {
			fmt.Fprintf(&b, "bgp community-list standard %s permit %s\n", name, member)
		}
	}
	if len(po.Communities) > 0 {
		b.WriteString("!\n")
	}

	// Generate FRR as-path access-lists from Junos as-path definitions
	if len(po.ASPaths) > 0 {
		aspNames := make([]string, 0, len(po.ASPaths))
		for name := range po.ASPaths {
			aspNames = append(aspNames, name)
		}
		sort.Strings(aspNames)
		for _, name := range aspNames {
			ap := po.ASPaths[name]
			fmt.Fprintf(&b, "bgp as-path access-list %s permit %s\n", name, ap.Regex)
		}
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
						// longer = strictly more specific (not the prefix itself)
						parts := strings.SplitN(rf.Prefix, "/", 2)
						if len(parts) == 2 {
							if plen, err := strconv.Atoi(parts[1]); err == nil {
								maxLen := 32
								if strings.Contains(rf.Prefix, ":") {
									maxLen = 128
								}
								matchStr = fmt.Sprintf("ge %d le %d", plen+1, maxLen)
							}
						}
					case "orlonger":
						// orlonger = this prefix or any more specific (default le 32/128)
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

			if term.PrefixList != "" {
				fmt.Fprintf(&b, " match ip address prefix-list %s\n", term.PrefixList)
			}

			if term.FromProtocol != "" {
				proto := term.FromProtocol
				if proto == "direct" {
					proto = "connected"
				}
				fmt.Fprintf(&b, " match source-protocol %s\n", proto)
			}

			if term.FromCommunity != "" {
				fmt.Fprintf(&b, " match community %s\n", term.FromCommunity)
			}

			if term.FromASPath != "" {
				fmt.Fprintf(&b, " match as-path %s\n", term.FromASPath)
			}

			// then actions
			if term.NextHop != "" {
				if term.NextHop == "peer-address" {
					// peer-address is handled by BGP neighbor config
				} else if term.NextHop == "self" {
					fmt.Fprintf(&b, " set ip next-hop peer-address\n")
				} else {
					fmt.Fprintf(&b, " set ip next-hop %s\n", term.NextHop)
				}
			}

			if term.LoadBalance != "" {
				// FRR handles ECMP load balancing via forwarding-table export
				// The route-map just needs to be a permit
			}

			if term.LocalPreference > 0 {
				fmt.Fprintf(&b, " set local-preference %d\n", term.LocalPreference)
			}
			if term.Metric > 0 {
				fmt.Fprintf(&b, " set metric %d\n", term.Metric)
			}
			if term.MetricType == 1 || term.MetricType == 2 {
				fmt.Fprintf(&b, " set metric-type type-%d\n", term.MetricType)
			}
			if term.Community != "" {
				fmt.Fprintf(&b, " set community %s\n", term.Community)
			}
			if term.Origin != "" {
				fmt.Fprintf(&b, " set origin %s\n", term.Origin)
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

// FRRRouteDetail holds detailed route information parsed from FRR's JSON output.
type FRRRouteDetail struct {
	Prefix    string
	Protocol  string
	Selected  bool
	Installed bool
	Distance  int
	Metric    int
	Uptime    string
	Table     string
	NextHops  []FRRNextHop
}

// FRRNextHop holds next-hop detail from FRR JSON.
type FRRNextHop struct {
	IP               string
	Interface        string
	DirectlyConnected bool
	Active           bool
	FIB              bool
	Recursive        bool
}

// frrRouteJSON maps the JSON output of "show ip route json".
type frrRouteJSON struct {
	Prefix    string          `json:"prefix"`
	Protocol  string          `json:"protocol"`
	Selected  bool            `json:"selected"`
	Installed bool            `json:"installed"`
	Distance  int             `json:"distance"`
	Metric    int             `json:"metric"`
	Uptime    string          `json:"uptime"`
	Table     int             `json:"table"`
	NextHops  []frrNextHopJSON `json:"nexthops"`
}

type frrNextHopJSON struct {
	IP                string `json:"ip"`
	InterfaceName     string `json:"interfaceName"`
	DirectlyConnected bool   `json:"directlyConnected"`
	Active            bool   `json:"active"`
	FIB               bool   `json:"fib"`
	Recursive         bool   `json:"recursive"`
}

// GetRouteDetailJSON queries FRR for detailed IPv4 and IPv6 routes via vtysh JSON output.
func (m *Manager) GetRouteDetailJSON() ([]FRRRouteDetail, error) {
	var all []FRRRouteDetail
	for _, cmd := range []string{"show ip route json", "show ipv6 route json"} {
		output, err := vtyshCmd(cmd)
		if err != nil {
			continue
		}
		routes, err := parseRouteJSON(output)
		if err != nil {
			continue
		}
		all = append(all, routes...)
	}
	return all, nil
}

// parseRouteJSON parses FRR's JSON route output into FRRRouteDetail entries.
func parseRouteJSON(data string) ([]FRRRouteDetail, error) {
	var raw map[string][]frrRouteJSON
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, err
	}

	// Sort prefixes for deterministic output.
	prefixes := make([]string, 0, len(raw))
	for p := range raw {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	var result []FRRRouteDetail
	for _, prefix := range prefixes {
		entries := raw[prefix]
		for _, e := range entries {
			d := FRRRouteDetail{
				Prefix:    e.Prefix,
				Protocol:  e.Protocol,
				Selected:  e.Selected,
				Installed: e.Installed,
				Distance:  e.Distance,
				Metric:    e.Metric,
				Uptime:    e.Uptime,
				Table:     strconv.Itoa(e.Table),
			}
			for _, nh := range e.NextHops {
				d.NextHops = append(d.NextHops, FRRNextHop{
					IP:                nh.IP,
					Interface:         nh.InterfaceName,
					DirectlyConnected: nh.DirectlyConnected,
					Active:            nh.Active,
					FIB:               nh.FIB,
					Recursive:         nh.Recursive,
				})
			}
			result = append(result, d)
		}
	}
	return result, nil
}

// FormatRouteDetail formats FRR route details in Junos-style output.
func FormatRouteDetail(routes []FRRRouteDetail) string {
	var b strings.Builder
	for _, r := range routes {
		active := " "
		if r.Selected {
			active = "*"
		}
		fmt.Fprintf(&b, "%s %s\n", active, r.Prefix)
		fmt.Fprintf(&b, "    Protocol: %s\n", r.Protocol)
		fmt.Fprintf(&b, "    Preference: %d/%d\n", r.Distance, r.Metric)
		if r.Uptime != "" {
			fmt.Fprintf(&b, "    Age: %s\n", r.Uptime)
		}
		if r.Installed {
			b.WriteString("    State: installed\n")
		}
		for _, nh := range r.NextHops {
			if nh.DirectlyConnected {
				fmt.Fprintf(&b, "    Next-hop: directly connected via %s\n", nh.Interface)
			} else if nh.IP != "" && nh.Interface != "" {
				fmt.Fprintf(&b, "    Next-hop: %s via %s\n", nh.IP, nh.Interface)
			} else if nh.IP != "" {
				label := "Next-hop"
				if nh.Recursive {
					label = "    Resolved"
				}
				fmt.Fprintf(&b, "    %s: %s\n", label, nh.IP)
			} else if nh.Interface != "" {
				fmt.Fprintf(&b, "    Next-hop: via %s\n", nh.Interface)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ExecVtysh runs an arbitrary vtysh command and returns the output.
func (m *Manager) ExecVtysh(command string) (string, error) {
	return vtyshCmd(command)
}

// GetBFDPeers returns BFD peer status from FRR.
func (m *Manager) GetBFDPeers() (string, error) {
	return vtyshCmd("show bfd peers")
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
