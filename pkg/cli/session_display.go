package cli

import (
	"fmt"
	"net"
	"strings"

	"github.com/psaab/xpf/pkg/config"
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
	// #7153: the WIRE VID, and only the wire VID. Session rows carry
	// SessionValue.IngressVlanID as the helper stamped it off the frame, so a
	// key built from anything else cannot match one.
	//
	// The old `unit.Number` fallback could never match. When `vlan-id` is unset
	// the unit is UNTAGGED on the wire: pkg/dataplane/compiler_iface.go takes
	// `vlanID = unit.VlanID` (0 here), and buildInterfaceNetworkdModels creates
	// a `.N` sub-interface only when `unit.VlanID > 0` — so no sub-interface
	// exists, the address lands on the parent netdev, and frames arrive with VID
	// 0. Keying such a unit under its NUMBER produced {ifindex, N} while every
	// session row for it keys {ifindex, 0}: a permanent miss for any untagged
	// unit N > 0.
	//
	// The shape the fallback was written for does not need it. The loss cluster's
	// reth0.50 / reth0.80 set `vlan-id 50` / `vlan-id 80` explicitly
	// (docs/ha-cluster-userspace.conf), so VlanID is populated and this returns
	// it. The fallback's own test synthesized units with Number set and VlanID
	// unset — a config the compiler treats as untagged — and asserted the map
	// shape rather than whether a session row could ever match it.
	//
	// Two units with no vlan-id on one interface now collide on {ifindex, 0},
	// which is correct: only one can own the untagged traffic. The caller
	// resolves that to the LOWEST unit explicitly — RangeUnits ranges a map, so
	// leaving it to first-write-wins would pick by Go's randomized map order.
	return uint16(unit.VlanID)
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
	// RangeInterfaces/RangeUnits skip present-but-nil InterfaceConfig/
	// InterfaceUnit slots admitted by the tolerant load / HA config-sync path
	// (#3494/#5068). A raw range over the tolerant config nil-derefs here and
	// panics the in-process daemon during a routine session display (#5813).
	config.RangeInterfaces(cfg, func(ifName string, ifc *config.InterfaceConfig) {
		resolvedParent := config.LinuxIfName(strings.SplitN(cfg.ResolveReth(ifName), ".", 2)[0])
		parentIfindex, err := lookupIfindex(resolvedParent)
		if err != nil {
			return
		}
		// #7153: two units with no `vlan-id` on one interface both key on wire
		// VID 0 — correct, since only one can own the untagged traffic. The
		// winner is the LOWEST unit number, chosen explicitly rather than by
		// first-write-wins: config.RangeUnits ranges a map, so first-write-wins
		// resolves by Go's randomized map order and the displayed name would
		// differ between two runs on one config. A test asserting stability
		// across iterations catches that; a single-shot assertion does not.
		winner := make(map[sessionIfaceKey]int)
		config.RangeUnits(ifc, func(_ int, unit *config.InterfaceUnit) {
			displayName := ifName
			if unit.Number != 0 || unit.VlanID != 0 {
				displayName = fmt.Sprintf("%s.%d", ifName, unit.Number)
			}
			key := sessionIfaceKey{
				ifindex: uint32(parentIfindex),
				vlanID:  sessionDisplayVLANID(unit),
			}
			if held, exists := winner[key]; exists && held <= unit.Number {
				return
			}
			winner[key] = unit.Number
			egressIfaces[key] = displayName
		})
	})
	return egressIfaces
}
