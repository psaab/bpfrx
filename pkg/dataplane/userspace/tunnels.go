package userspace

import (
	"fmt"
	"net"
	"sort"

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
	var nextID uint16 = 1
	addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
		if tunnel == nil || tunnel.Source == "" || tunnel.Destination == "" || nextID == 0 {
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
		out = append(out, TunnelEndpointSnapshot{
			ID:              nextID,
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
		})
		nextID++
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
