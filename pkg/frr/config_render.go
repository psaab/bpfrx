// config_render.go holds the non-protocol FRR config rendering helpers:
//
//   - generateInterfaceSettings: per-interface bandwidth + point-to-point hints
//     emitted before protocol config so OSPF auto-cost picks up bandwidth.
//   - generateStaticRoute:       per-prefix `ip route` / `ipv6 route` emission
//     with RETH name translation and IPv6 next-hop
//     interface resolution.
//   - renderGenerateRoutes:      blackhole static routes for `generate` routes.
//   - renderDHCPDefaults:        DHCP-learned default routes (AD 200), with
//     suppression when explicit static defaults exist.
//   - renderBackupRouter:        backup-router default (AD 250).
//   - renderClusterModeDefaults: cluster-mode blackhole defaults (AD 250).
//   - resolveECMP:               forwarding-table export policy → ecmpMaxPaths
//     and (side effect) fc.ConsistentHash.
package frr

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// generateInterfaceSettings emits FRR interface blocks for bandwidth and
// point-to-point network type. These are emitted before protocol config so
// OSPF auto-cost picks up the correct bandwidth.
func (m *Manager) generateInterfaceSettings(fc *FullConfig) string {
	if len(fc.InterfaceBandwidths) == 0 && len(fc.InterfacePointToPoint) == 0 {
		return ""
	}

	// Build set of interfaces that have explicit OSPF NetworkType so we don't override.
	ospfNetworkType := make(map[string]bool)
	if fc.OSPF != nil {
		for _, area := range fc.OSPF.Areas {
			for _, iface := range area.Interfaces {
				if iface.NetworkType != "" {
					ospfNetworkType[iface.Name] = true
				}
			}
		}
	}

	// Collect all interface names that need settings.
	ifaces := make(map[string]bool)
	for name := range fc.InterfaceBandwidths {
		ifaces[name] = true
	}
	for name := range fc.InterfacePointToPoint {
		if fc.InterfacePointToPoint[name] && !ospfNetworkType[name] {
			ifaces[name] = true
		}
	}

	// Sort for deterministic output.
	names := make([]string, 0, len(ifaces))
	for name := range ifaces {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "interface %s\n", name)
		if bw, ok := fc.InterfaceBandwidths[name]; ok && bw > 0 {
			// FRR bandwidth command takes kbps
			kbps := bw / 1000
			if kbps == 0 {
				kbps = 1
			}
			fmt.Fprintf(&b, " bandwidth %d\n", kbps)
		}
		if fc.InterfacePointToPoint[name] && !ospfNetworkType[name] {
			b.WriteString(" ip ospf network point-to-point\n")
		}
		b.WriteString("exit\n!\n")
	}
	return b.String()
}

// generateStaticRoute produces FRR static route commands.
// Multiple next-hops produce one line each (FRR creates ECMP).
// Routes with NextTable are handled via ip rule (policy routing), not FRR.
func (m *Manager) generateStaticRoute(sr *config.StaticRoute, vrfName string, rethMap map[string]string, ipv6NextHopInterfaces map[string]map[string]string) string {
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
		if isV6 && ifName == "" && nh.Address != "" {
			ifName = ipv6NextHopInterfaces[vrfName][nh.Address]
		}
		if strings.HasSuffix(ifName, ".0") {
			ifName = ifName[:len(ifName)-2]
		}
		// Resolve RETH names to physical member names (e.g. "reth0.50" → "ge-0-0-1.50").
		// FRR needs kernel interface names, not Junos RETH names.
		if len(rethMap) > 0 && ifName != "" {
			parts := strings.SplitN(ifName, ".", 2)
			if phys, ok := rethMap[parts[0]]; ok {
				phys = config.LinuxIfName(phys)
				if len(parts) == 2 {
					ifName = phys + "." + parts[1]
				} else {
					ifName = phys
				}
			}
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

// renderGenerateRoutes emits one blackhole static route per generate-route
// (Junos `routing-options generate route X`). v4 vs v6 is picked by the
// presence of ":" in the prefix.
func renderGenerateRoutes(b *strings.Builder, fc *FullConfig) {
	if len(fc.GenerateRoutes) == 0 {
		return
	}
	for _, gr := range fc.GenerateRoutes {
		if strings.Contains(gr.Prefix, ":") {
			fmt.Fprintf(b, "ipv6 route %s blackhole\n", gr.Prefix)
		} else {
			fmt.Fprintf(b, "ip route %s blackhole\n", gr.Prefix)
		}
	}
	b.WriteString("!\n")
}

// renderDHCPDefaults emits DHCP-learned default routes at admin distance 200.
// Suppressed when an explicit static default route exists for the same
// address family so the management interface's DHCP gateway doesn't compete
// with configured routes.
func renderDHCPDefaults(b *strings.Builder, fc *FullConfig) {
	if len(fc.DHCPRoutes) == 0 {
		return
	}
	hasV4Default := false
	for _, sr := range fc.StaticRoutes {
		if sr.Destination == "0.0.0.0/0" {
			hasV4Default = true
			break
		}
	}
	hasV6Default := false
	for _, sr := range fc.Inet6StaticRoutes {
		if sr.Destination == "::/0" {
			hasV6Default = true
			break
		}
	}
	wrote := false
	for _, dr := range fc.DHCPRoutes {
		if dr.IsIPv6 && hasV6Default {
			continue
		}
		if !dr.IsIPv6 && hasV4Default {
			continue
		}
		if dr.IsIPv6 {
			if dr.Interface != "" {
				fmt.Fprintf(b, "ipv6 route ::/0 %s %s 200\n", dr.Gateway, dr.Interface)
			} else {
				fmt.Fprintf(b, "ipv6 route ::/0 %s 200\n", dr.Gateway)
			}
		} else {
			fmt.Fprintf(b, "ip route 0.0.0.0/0 %s 200\n", dr.Gateway)
		}
		wrote = true
	}
	if wrote {
		b.WriteString("!\n")
	}
}

// renderBackupRouter emits the system backup-router as a fallback default
// gateway with admin distance 250.
func renderBackupRouter(b *strings.Builder, fc *FullConfig) {
	if fc.BackupRouter == "" {
		return
	}
	dst := fc.BackupRouterDst
	if dst == "" {
		dst = "0.0.0.0/0"
	}
	prefix := "ip"
	if strings.Contains(dst, ":") {
		prefix = "ipv6"
	}
	fmt.Fprintf(b, "%s route %s %s 250\n", prefix, dst, fc.BackupRouter)
	b.WriteString("!\n")
}

// renderClusterModeDefaults emits cluster-mode blackhole default routes
// (admin distance 250) for both address families. When the WAN VIP moves to
// the peer and FRR withdraws the real default, this blackhole makes
// bpf_fib_lookup return BLACKHOLE (not NOT_FWDED), triggering zone-encoded
// fabric redirect for new connections. AD=250 ensures real defaults (AD=5,
// DHCP AD=200) take priority.
func renderClusterModeDefaults(b *strings.Builder, fc *FullConfig) {
	if !fc.ClusterMode {
		return
	}
	fmt.Fprintf(b, "ip route 0.0.0.0/0 Null0 250\n")
	fmt.Fprintf(b, "ipv6 route ::/0 Null0 250\n")
	b.WriteString("!\n")
}

// resolveECMP inspects the forwarding-table export policy referenced by
// fc.ForwardingTableExport and returns the ecmpMaxPaths value that should
// be applied to BGP/OSPF.
//
// Side effect: sets fc.ConsistentHash to true when the policy uses
// "load-balance consistent-hash". The daemon reads fc.ConsistentHash after
// ApplyFull returns to decide whether to flip
// net.ipv4.fib_multipath_hash_policy=1 for L4 ECMP hashing. Audited callers
// of ApplyFull read fc.ConsistentHash only after ApplyFull returns, so the
// mid-call mutation is safe.
func resolveECMP(fc *FullConfig) int {
	ecmpMaxPaths := 0
	if fc.ForwardingTableExport == "" || fc.PolicyOptions == nil {
		return ecmpMaxPaths
	}
	ps, ok := fc.PolicyOptions.PolicyStatements[fc.ForwardingTableExport]
	if !ok {
		return ecmpMaxPaths
	}
	for _, term := range ps.Terms {
		if term.LoadBalance != "" {
			ecmpMaxPaths = 64
		}
		if term.LoadBalance == "consistent-hash" {
			fc.ConsistentHash = true
		}
	}
	return ecmpMaxPaths
}
