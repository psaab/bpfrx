package cli

import (
	"fmt"
	"net"
	"strings"

	"github.com/psaab/bpfrx/pkg/config"
)

type sessionIfaceKey struct {
	ifindex uint32
	vlanID  uint16
}

// sessionDisplayVLANID resolves the VLAN identity that session display should
// use when mapping fib_ifindex/fib_vlan_id back to a config interface name.
// For routed subinterfaces, unit number and vlan-id are often the same, but
// the config may only populate one of them depending on how the interface was
// defined.
func sessionDisplayVLANID(unit *config.InterfaceUnit) uint16 {
	if unit == nil {
		return 0
	}
	if unit.VlanID > 0 {
		return uint16(unit.VlanID)
	}
	if unit.Number > 0 {
		return uint16(unit.Number)
	}
	return 0
}

func buildSessionEgressIfaces(cfg *config.Config) map[sessionIfaceKey]string {
	return buildSessionEgressIfacesWithLookup(cfg, func(name string) (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return iface.Index, nil
	})
}

func buildSessionEgressIfacesWithLookup(cfg *config.Config, lookupIfindex func(string) (int, error)) map[sessionIfaceKey]string {
	egressIfaces := make(map[sessionIfaceKey]string)
	if cfg == nil {
		return egressIfaces
	}
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		resolvedParent := config.LinuxIfName(strings.SplitN(cfg.ResolveReth(ifName), ".", 2)[0])
		parentIfindex, err := lookupIfindex(resolvedParent)
		if err != nil {
			continue
		}
		for _, unit := range ifc.Units {
			displayName := ifName
			if unit.Number != 0 || unit.VlanID != 0 {
				displayName = fmt.Sprintf("%s.%d", ifName, unit.Number)
			}
			key := sessionIfaceKey{
				ifindex: uint32(parentIfindex),
				vlanID:  sessionDisplayVLANID(unit),
			}
			if _, exists := egressIfaces[key]; !exists {
				egressIfaces[key] = displayName
			}
		}
	}
	return egressIfaces
}
