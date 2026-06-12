package userspace

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func buildTunnelEndpointSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []TunnelEndpointSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	ifaceByName := make(map[string]InterfaceSnapshot, len(interfaces))
	rgByAddress := make(map[string]int)
	for _, iface := range interfaces {
		if iface.Name == "" || iface.Ifindex <= 0 {
			continue
		}
		ifaceByName[iface.Name] = iface
		if iface.RedundancyGroup <= 0 {
			continue
		}
		for _, addr := range iface.Addresses {
			ip, _, err := net.ParseCIDR(addr.Address)
			if err != nil || ip == nil {
				continue
			}
			rgByAddress[ip.String()] = iface.RedundancyGroup
		}
	}
	if len(ifaceByName) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]TunnelEndpointSnapshot, 0)
	// #1873: ids are content-derived (config.StableTunnelEndpointID of
	// the unit-qualified interface name), NOT positional — adding or
	// removing one tunnel can never renumber another, and both HA
	// nodes compute identical ids from identical config. usedIDs is
	// the fail-closed belt-and-braces behind the commit-time collision
	// gate (validateTunnelEndpointIDCollisionAST): a snapshot must
	// never carry two rows with one id, so the later-sorting collider
	// is dropped loudly. Iteration is sorted (names + unit numbers),
	// so the drop is deterministic.
	usedIDs := make(map[uint16]string)
	addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
		if tunnel == nil {
			return
		}
		// WireGuard endpoints carry the peer in WgEndpoint and need no
		// Source/Destination (#1432 S2a); a WG endpoint configured with
		// only WgEndpoint must not be dropped by the GRE source/dest gate.
		isWireguard := tunnel.Mode == "wireguard"
		if !isWireguard && (tunnel.Source == "" || tunnel.Destination == "") {
			return
		}
		iface, ok := ifaceByName[ifName]
		if !ok {
			return
		}
		outerFamily := "inet"
		transportTable := "inet.0"
		if dst := net.ParseIP(tunnel.Destination); dst != nil && dst.To4() == nil {
			outerFamily = "inet6"
			transportTable = "inet6.0"
		} else if src := net.ParseIP(tunnel.Source); src != nil && src.To4() == nil {
			outerFamily = "inet6"
			transportTable = "inet6.0"
		}
		if tunnel.RoutingInstance != "" {
			if outerFamily == "inet6" {
				transportTable = tunnel.RoutingInstance + ".inet6.0"
			} else {
				transportTable = tunnel.RoutingInstance + ".inet.0"
			}
		}
		redundancyGroup := iface.RedundancyGroup
		if redundancyGroup <= 0 {
			if src := net.ParseIP(tunnel.Source); src != nil {
				redundancyGroup = rgByAddress[src.String()]
			}
		}
		// For WG the outer family follows the peer endpoint address
		// (the Source/Destination heuristic above sees empty strings).
		if isWireguard && tunnel.WgEndpoint != "" {
			if host, _, err := net.SplitHostPort(tunnel.WgEndpoint); err == nil {
				if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
					outerFamily = "inet6"
				}
			}
		}
		id := config.StableTunnelEndpointID(ifName)
		if owner, taken := usedIDs[id]; taken {
			slog.Error("tunnel endpoint id collision — dropping later-sorting tunnel (#1873)",
				"kept", owner, "dropped", ifName, "id", id)
			return
		}
		snap := TunnelEndpointSnapshot{
			ID:              id,
			Interface:       ifName,
			LinuxName:       iface.LinuxName,
			Ifindex:         iface.Ifindex,
			Zone:            iface.Zone,
			RedundancyGroup: redundancyGroup,
			MTU:             iface.MTU,
			Mode:            tunnel.Mode,
			OuterFamily:     outerFamily,
			Source:          tunnel.Source,
			Destination:     tunnel.Destination,
			Key:             tunnel.Key,
			TTL:             tunnel.TTL,
			TransportTable:  transportTable,
		}
		if isWireguard {
			snap.WgListenPort = tunnel.WgListenPort
			snap.WgLocalPrivkeyHex = tunnel.WgLocalPrivkeyHex
			snap.WgPeerPubkeyHex = tunnel.WgPeerPubkeyHex
			snap.WgAllowedIPs = tunnel.WgAllowedIPs
			snap.WgEndpoint = tunnel.WgEndpoint
			snap.WgKeepaliveSecs = tunnel.WgKeepaliveSecs
		}
		out = append(out, snap)
		usedIDs[id] = ifName
	}
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if iface.Tunnel != nil {
			if len(iface.Units) == 0 {
				addEndpoint(name, iface.Tunnel)
				continue
			}
			unitNums := make([]int, 0, len(iface.Units))
			for unitNum := range iface.Units {
				unitNums = append(unitNums, unitNum)
			}
			sort.Ints(unitNums)
			if iface.Tunnel.Mode == "wireguard" {
				// Interface-level WireGuard is ONE persistent TUN with
				// ONE listen port shared by every unit (#1910 r2 Codex
				// High): now that TunnelNameMap resolves every unit ref
				// of an interface-level wg to the base device, per-unit
				// emission would produce N live endpoints with the SAME
				// ifindex + listen port — the Rust side overwrites
				// tunnel_endpoint_by_ifindex with the later id and the
				// second control thread tombstones on the duplicate UDP
				// bind, so routes can select an engine whose control
				// thread never came up. Emit exactly one endpoint,
				// keyed by the lowest unit ref that has a snapshot row
				// (so the common single-unit-0 shape keeps its existing
				// stable id, and a missing/nil low unit falls through
				// to the next one exactly like per-unit emission did).
				for _, unitNum := range unitNums {
					ref := fmt.Sprintf("%s.%d", name, unitNum)
					if _, ok := ifaceByName[ref]; !ok {
						continue
					}
					addEndpoint(ref, iface.Tunnel)
					break
				}
				continue
			}
			for _, unitNum := range unitNums {
				addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), iface.Tunnel)
			}
			continue
		}
		if len(iface.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
		}
	}
	return out
}

// wgEndpointSetSummary returns a canonical "id:iface:port@ifindex"
// summary of the snapshot's WireGuard endpoint set (#1866 D3). Used by
// logWgEndpointSetTransitionLocked to emit a publish-boundary log line
// whenever the WG endpoint set the helper is being given changes —
// paired with the Rust-side apply-boundary log, one journal capture
// disambiguates "Go published a stale set" from "Rust skipped the
// prune" if a teardown leak ever recurs.
func wgEndpointSetSummary(snap *ConfigSnapshot) string {
	if snap == nil {
		return ""
	}
	parts := make([]string, 0, len(snap.TunnelEndpoints))
	for _, ep := range snap.TunnelEndpoints {
		if ep.Mode != "wireguard" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d:%s:%d@%d", ep.ID, ep.Interface, ep.WgListenPort, ep.Ifindex))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// logWgEndpointSetTransitionLocked logs (Info, state-transition-only)
// when the WG endpoint set of an outgoing snapshot differs from the
// previously published one, then records the new set. Call after a
// SUCCESSFUL apply_snapshot publish so the recorded set tracks what the
// helper actually accepted. Caller must hold m.mu.
func (m *Manager) logWgEndpointSetTransitionLocked(snap *ConfigSnapshot, path string) {
	set := wgEndpointSetSummary(snap)
	if set == m.lastPublishedWgEndpoints {
		return
	}
	slog.Info("userspace: WG endpoint set changed in published snapshot",
		"path", path,
		"old", m.lastPublishedWgEndpoints,
		"new", set)
	m.lastPublishedWgEndpoints = set
}
