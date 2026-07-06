package userspace

import (
	"net"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func buildFabricSnapshots(cfg *config.Config) []FabricSnapshot {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	cc := cfg.Chassis.Cluster
	type fabricInput struct {
		name string
		peer string
	}
	inputs := []fabricInput{
		{name: cc.FabricInterface, peer: cc.FabricPeerAddress},
		{name: cc.Fabric1Interface, peer: cc.Fabric1PeerAddress},
	}
	var out []FabricSnapshot
	seen := make(map[string]struct{}, len(inputs))
	for _, in := range inputs {
		if in.name == "" {
			continue
		}
		if _, ok := seen[in.name]; ok {
			continue
		}
		seen[in.name] = struct{}{}
		ifCfg := cfg.Interfaces.Interfaces[in.name]
		if ifCfg == nil {
			continue
		}
		parentName := ifCfg.LocalFabricMember
		parentLinux := config.LinuxIfName(parentName)
		parentIfindex, _, parentMAC, _ := buildLinkSnapshot(parentLinux)
		overlayLinux := config.LinuxIfName(in.name)
		overlayIfindex, _, _, _ := buildLinkSnapshot(overlayLinux)
		rxQueues := 0
		if parentLinux != "" {
			rxQueues = userspaceRXQueueCount(parentLinux)
		}
		peerMAC := buildFabricPeerMAC(overlayIfindex, parentIfindex, in.peer)
		out = append(out, FabricSnapshot{
			Name:            in.name,
			ParentInterface: parentName,
			ParentLinuxName: parentLinux,
			ParentIfindex:   parentIfindex,
			OverlayLinux:    overlayLinux,
			OverlayIfindex:  overlayIfindex,
			RXQueues:        rxQueues,
			PeerAddress:     in.peer,
			LocalMAC:        parentMAC,
			PeerMAC:         peerMAC,
			Up:              fabricParentUp(parentLinux),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// fabricParentUp reports whether the fabric parent link's carrier/oper state is
// usable for forwarding (#4082). The cross-chassis redirect egresses over the
// parent ifindex, so a DOWN parent means the redirect would blackhole; the Rust
// selection prefers a fabric whose parent reports up. Detection fails toward
// "up": only a definite kernel down state (admin-down, oper-down, or
// lower-layer-down) returns false. Many virtual/overlay parents report
// OperUnknown even with a live carrier, and mis-marking a healthy fabric down
// would wrongly divert a dual-fabric cluster to its secondary — so an
// indeterminate oper-state is treated as up. An empty name or a link that fails
// to resolve returns false (the fabric is skipped in Rust on ifindex<=0 anyway).
func fabricParentUp(linuxName string) bool {
	if linuxName == "" {
		return false
	}
	link, err := netlink.LinkByName(linuxName)
	if err != nil || link == nil {
		return false
	}
	attrs := link.Attrs()
	// An administratively-down parent can never forward.
	if attrs.Flags&net.FlagUp == 0 {
		return false
	}
	switch attrs.OperState {
	case netlink.OperDown, netlink.OperLowerLayerDown, netlink.OperNotPresent:
		return false
	default:
		// OperUp, OperUnknown, OperDormant, OperTesting: treat as up. Fail
		// toward "up" at the detection layer (the Rust selection also fails
		// open when no fabric reports up).
		return true
	}
}

func buildFabricPeerMAC(overlayIfindex, parentIfindex int, peer string) string {
	ip := net.ParseIP(peer)
	if ip == nil {
		return ""
	}
	family := netlink.FAMILY_V4
	if ip.To4() == nil {
		family = netlink.FAMILY_V6
	}
	for _, ifindex := range []int{overlayIfindex, parentIfindex} {
		if ifindex <= 0 {
			continue
		}
		neighs, err := netlink.NeighList(ifindex, family)
		if err != nil {
			continue
		}
		for _, neigh := range neighs {
			if neigh.IP == nil || !neigh.IP.Equal(ip) || neigh.HardwareAddr == nil {
				continue
			}
			return neigh.HardwareAddr.String()
		}
	}
	return ""
}
