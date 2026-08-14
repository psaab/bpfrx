package userspace

import (
	"net"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// buildFabricSnapshots builds the fabric rows against a FRESH kernel xfrm
// sample. buildSnapshot uses buildFabricSnapshotsFrom instead, so the interface
// rows and the fabric parents are judged against ONE sample; SyncFabricState
// (manager_ha.go) has no interface rows to agree with and uses this form.
func buildFabricSnapshots(cfg *config.Config) []FabricSnapshot {
	return buildFabricSnapshotsFrom(cfg, sampleLiveXfrmNetdevs())
}

func buildFabricSnapshotsFrom(cfg *config.Config, liveXfrm map[string]bool) []FabricSnapshot {
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
			Name:             in.name,
			ParentInterface:  parentName,
			ParentLinuxName:  parentLinux,
			ParentIfindex:    parentIfindex,
			ParentUnbindable: fabricParentUnbindable(cfg, parentName, parentLinux, liveXfrm),
			OverlayLinux:     overlayLinux,
			OverlayIfindex:   overlayIfindex,
			RXQueues:         rxQueues,
			PeerAddress:      in.peer,
			LocalMAC:         parentMAC,
			PeerMAC:          peerMAC,
			Up:               fabricParentUp(parentLinux),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// fabricParentUnbindable is the device-level verdict for a fabric parent
// netdev: may the userspace dataplane bind an AF_XDP socket to it?
//
// #6691 round 10, and it exists because A FABRIC MEMBER NEEDS NO INTERFACE
// STANZA. `set interfaces fab0 fabric-options member-interfaces ge-0/0/0` names
// ge-0/0/0 without creating a row for it, so the parent netdev can reach the
// ingress-adjudication map and the RSS allowlist — the fabric loops push it
// there — while no InterfaceSnapshot owns it. userspaceRefusedNetdevs is built
// from ROWS, so it had no evidence about such a netdev and, being a
// unanimity rule over an empty bucket, returned "not refused". Round 9 read
// that as an ADMISSION and let an unbindable ownerless parent through both
// loops on both planes.
//
// The fix is not a fourth conjunct on the tally. It is that AN EMITTED FABRIC
// PARENT IS AN OWNER OF ITS NETDEV: the fabric contributes that netdev to the
// same sets a row does, on its own account, so it must carry a verdict and be
// counted like any other owner (buildUserspaceRefusedNetdevs). This function is
// that verdict, and it is deliberately computed by handing a synthetic row to
// userspaceUnbindableNetdev rather than by restating the classes — the class
// table stays the single authority on what makes a netdev unbindable, so a
// class added there covers fabric parents without anyone remembering to.
//
// The synthetic row carries exactly the fields the class table reads:
//
//   - Name — the CONFIG name (`ge-0/0/0`), which is what the fxp/em/fab/lo0
//     arms shape-test. A fabric parent is never itself `fab*`; the fab arm
//     refuses the OVERLAY, which is a different netdev.
//   - Tunnel — the parent's interface-level `tunnel` stanza, mirroring what the
//     BASE row would carry. A UNIT-level tunnel is deliberately not read: it
//     makes the unit row unbindable and leaves the base row bindable, and the
//     fabric binds the base netdev.
//   - SecureTunnel — snapshotSecureTunnel against the SHARED sample, so an
//     ownerless parent gets both halves of the evidence a row would get: an
//     IPsec bind-interface naming it, OR kernel link kind `xfrm`. The kernel
//     half is the reachable one here, and it is why this cannot be answered
//     from config alone: a slot-shaped netdev created out of band is both a
//     legal fabric member and a refused device.
//
// An empty parent name is bindable-by-default: nothing is emitted for it (the
// fabric loops guard on the name/ifindex), so there is no netdev to judge.
func fabricParentUnbindable(cfg *config.Config, parentName, parentLinux string, liveXfrm map[string]bool) bool {
	if parentLinux == "" {
		return false
	}
	parentTunnel := false
	if cfg != nil {
		if parentCfg := cfg.Interfaces.Interfaces[parentName]; parentCfg != nil {
			parentTunnel = parentCfg.Tunnel != nil
		}
	}
	return userspaceUnbindableNetdev(InterfaceSnapshot{
		Name:         parentName,
		LinuxName:    parentLinux,
		Tunnel:       parentTunnel,
		SecureTunnel: snapshotSecureTunnel(cfg, parentName, parentLinux, liveXfrm),
	})
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
