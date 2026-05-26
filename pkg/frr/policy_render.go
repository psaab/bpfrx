// policy_render.go holds protocols + policy rendering.
//
// Despite the filename "policy_render", this file owns both protocol
// rendering (OSPF/OSPFv3/BGP/RIP/ISIS) and policy-options rendering
// (prefix-lists, route-maps, communities). They share the
// resolveRedistribute helper and the BFD profile dedup machinery.
//
// File name held at "policy_render.go" per project-level file-layout
// mandate (exactly 5 sibling .go files in pkg/frr: manager,
// config_render, vtysh, status_parse, policy_render).
//
// Symbols:
//   - knownRedistProtocols, resolveRedistribute
//   - bfdProfile, bfdProfileName
//   - generateProtocols (OSPF/OSPFv3/BGP/RIP/ISIS)
//   - generatePolicyOptions (prefix-lists, route-maps, communities)
//   - ifaceNetwork (called from OSPF rendering inside generateProtocols)
package frr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

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

// bfdProfile holds a unique BFD profile (interval + multiplier).
type bfdProfile struct {
	interval   int
	multiplier int
}

// bfdProfileName returns a deterministic profile name like "xpf-300-3".
func bfdProfileName(interval, multiplier int) string {
	if interval == 0 {
		interval = 300
	}
	if multiplier == 0 {
		multiplier = 3
	}
	return fmt.Sprintf("xpf-%d-%d", interval, multiplier)
}

// generateProtocols generates FRR CLI config for OSPF, BGP, RIP, and IS-IS.
// If vrfName is non-empty, generates VRF-scoped commands.
// ecmpMaxPaths > 1 enables ECMP with the given maximum equal-cost paths.
// policyOptions is used to resolve export policy names to route-map references.
func (m *Manager) generateProtocols(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig) string {
	var b strings.Builder
	bfdProfiles := make(map[string]bfdProfile)

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
						if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
							profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
							bfdProfiles[profile] = bfdProfile{iface.BFDInterval, iface.BFDMultiplier}
							fmt.Fprintf(&b, " ip ospf bfd profile %s\n", profile)
						} else {
							b.WriteString(" ip ospf bfd\n")
						}
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
		fmt.Fprintf(&b, "router isis xpf%s\n", vrfSuffix)
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
			fmt.Fprintf(&b, " ip router isis xpf\n")
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
			if iface.BFD {
				if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
					profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
					bfdProfiles[profile] = bfdProfile{iface.BFDInterval, iface.BFDMultiplier}
					fmt.Fprintf(&b, " isis bfd profile %s\n", profile)
				} else {
					b.WriteString(" isis bfd\n")
				}
			}
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
				multiplier := n.BFDMultiplier
				if multiplier == 0 {
					multiplier = 3
				}
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

	// Emit deduplicated BFD profile stanzas
	if len(bfdProfiles) > 0 {
		// Collect and sort profile names for deterministic output
		var profileNames []string
		for name := range bfdProfiles {
			profileNames = append(profileNames, name)
		}
		sort.Strings(profileNames)
		b.WriteString("bfd\n")
		for _, name := range profileNames {
			p := bfdProfiles[name]
			interval := p.interval
			if interval == 0 {
				interval = 300
			}
			multiplier := p.multiplier
			if multiplier == 0 {
				multiplier = 3
			}
			fmt.Fprintf(&b, " profile %s\n", name)
			fmt.Fprintf(&b, "  detect-multiplier %d\n", multiplier)
			fmt.Fprintf(&b, "  receive-interval %d\n", interval)
			fmt.Fprintf(&b, "  transmit-interval %d\n", interval)
			b.WriteString(" exit\n")
		}
		b.WriteString("exit\n!\n")
	}

	return b.String()
}

// ifaceNetwork returns a placeholder network string for an interface.
// In real use FRR matches based on interface addresses. Used inside
// generateProtocols (OSPF area network rendering).
func ifaceNetwork(name string) string {
	// Use 0.0.0.0/0 as a catch-all; FRR resolves per-interface
	return "0.0.0.0/0"
}

// generatePolicyOptions emits FRR prefix-list / route-map / community-list /
// as-path-access-list config from the typed Junos policy-options.
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
					// Junos "next-hop peer-address" → FRR "set ip next-hop peer-address"
					fmt.Fprintf(&b, " set ip next-hop peer-address\n")
				} else if term.NextHop == "self" {
					// Junos "next-hop self" → FRR "set ip next-hop self" (eBGP default)
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
