package userspace

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/linuxsock"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (m *Manager) bootstrapNAPIQueuesAsyncLocked(reason string) {
	now := time.Now()
	if !m.lastNAPIBootstrap.IsZero() && now.Sub(m.lastNAPIBootstrap) < 2*time.Second {
		return
	}
	m.lastNAPIBootstrap = now
	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.proc == nil || m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
			return
		}
		slog.Info("userspace: bootstrapping NAPI queues", "reason", reason)
		m.bootstrapNAPIQueuesLocked()
	}()
}

// bootstrapNAPIQueuesLocked sends UDP probe packets to each managed
// interface to trigger hardware RX events on all NIC queues. This is
// needed for mlx5 zero-copy: the driver only consumes XSK fill ring
// entries during NAPI poll, and NAPI only runs when there are HW RX
// events. Without at least one packet per queue, the fill ring stays
// unconsumed and XDP_REDIRECT silently drops packets.
//
// The probes are sent while ctrl is disabled, so only the local/control
// boundary reaches the kernel; transit remains fail-closed.
func (m *Manager) bootstrapNAPIQueuesLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Send UDP probes and an ICMP echo on each managed interface to create
	// hardware RX events and neighbor resolution. This triggers mlx5 NAPI,
	// which processes the XSK fill ring and posts WQEs for zero-copy packet
	// reception. Without at least one HW RX event per queue, the fill ring
	// entries added after socket bind are never consumed by the driver's pool.
	for _, linuxName := range userspaceBootstrapProbeInterfaces(m.lastSnapshot.Config) {
		// Send many parallel pings to hit all RSS queues. Each ping
		// process gets a different ICMP echo ID from the kernel, causing
		// RSS to distribute replies across different NIC queues. This
		// triggers NAPI on each queue, which posts fill ring WQEs for
		// zero-copy XSK packet reception.
		link, err := netlink.LinkByName(linuxName)
		if err != nil || link == nil {
			continue
		}
		// Find a target: gateway or any neighbor
		var target string
		routes, _ := netlink.RouteList(link, netlink.FAMILY_V4)
		for _, r := range routes {
			if r.Gw != nil && r.Gw.To4() != nil {
				target = r.Gw.String()
				break
			}
		}
		if target == "" {
			neighs, _ := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
			for _, n := range neighs {
				if n.IP != nil && n.IP.To4() != nil && n.HardwareAddr != nil &&
					n.State != netlink.NUD_FAILED {
					target = n.IP.String()
					break
				}
			}
		}
		if target == "" {
			continue
		}
		// Send multiple ICMP probes with different ICMP echo IDs to
		// trigger NAPI on ALL NIC queues. mlx5 RSS distributes replies
		// across queues based on hash(src, dst, proto, id). Sending
		// ~2× the queue count with varying IDs makes it very likely
		// that every queue sees at least one hardware RX event, which
		// posts XSK fill ring WQEs for zero-copy packet reception.
		targetIP := net.ParseIP(target)
		if targetIP != nil {
			// ICMP RSS hashes on (src, dst, proto) only — varying
			// ICMP ID doesn't change the target queue. Use UDP probes
			// with varying ports: mlx5 RSS hashes (src, dst, sport,
			// dport) for UDP, distributing across all queues.
			// Send 30 probes across port range 40000-40029.
			for i := 0; i < 30; i++ {
				sendUDPProbeForNAPI(linuxName, targetIP, uint16(40000+i))
				if i%6 == 5 {
					time.Sleep(time.Millisecond)
				}
			}
			// Also send one ICMP probe for neighbor resolution.
			sendICMPProbeFromManager(linuxName, targetIP)
		}
	}
}

// proactiveNeighborResolveLocked reads the kernel neighbor table and
// pings any STALE/FAILED entries to force re-resolution. Also pings
// the default gateway on each managed interface. This ensures the
// helper has fresh neighbor entries when ctrl is enabled.
func (m *Manager) proactiveNeighborResolveLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Collect all managed interface names
	seen := make(map[string]bool)
	var ifaces []string
	for ifName, ifc := range m.lastSnapshot.Config.Interfaces.Interfaces {
		base := config.LinuxIfName(ifName)
		if !seen[base] {
			seen[base] = true
			ifaces = append(ifaces, base)
		}
		for _, unit := range ifc.Units {
			if unit.VlanID > 0 {
				vlanName := fmt.Sprintf("%s.%d", base, unit.VlanID)
				if !seen[vlanName] {
					seen[vlanName] = true
					ifaces = append(ifaces, vlanName)
				}
			}
		}
	}
	// For each interface, read neighbors and ping any that need resolution
	var resolved int
	for _, ifName := range ifaces {
		link, err := netlink.LinkByName(ifName)
		if err != nil || link == nil {
			continue
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			neighs, err := netlink.NeighList(link.Attrs().Index, family)
			if err != nil {
				continue
			}
			for _, n := range neighs {
				if n.IP == nil || n.IP.IsLinkLocalUnicast() {
					continue
				}
				// Trigger ARP/NDP resolution for STALE/FAILED/absent entries.
				if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
					n.State == netlink.NUD_STALE || n.State == netlink.NUD_DELAY ||
					n.State == netlink.NUD_PROBE || n.State == netlink.NUD_FAILED {
					sendICMPProbeFromManager(ifName, n.IP)
					resolved++
				}
			}
		}
	}
	// Also resolve route next-hops that aren't in the neighbor table yet.
	// After VRRP election, the kernel may not have ARP for destinations
	// like .200 that were previously known but got purged on restart.
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_ALL)
	for _, r := range routes {
		if r.Gw == nil || r.Gw.IsLinkLocalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link == nil {
			continue
		}
		ifName := link.Attrs().Name
		if !seen[ifName] {
			continue // only managed interfaces
		}
		// Check if this gateway is already in neighbor table
		existing, _ := netlink.NeighList(r.LinkIndex, netlink.FAMILY_ALL)
		found := false
		for _, n := range existing {
			if n.IP.Equal(r.Gw) && n.HardwareAddr != nil && len(n.HardwareAddr) > 0 &&
				n.State != netlink.NUD_FAILED {
				found = true
				break
			}
		}
		if !found {
			sendICMPProbeFromManager(ifName, r.Gw)
			resolved++
		}
	}
	if resolved > 0 {
		slog.Info("userspace: proactive neighbor resolution",
			"resolved", resolved, "interfaces", len(ifaces))
	}
}

// sendICMPProbeFromManager sends a single raw ICMP/ICMPv6 echo request
// bound to the given interface. Triggers kernel ARP/NDP resolution
// without shelling out to ping. Non-blocking.
func sendICMPProbeFromManager(iface string, target net.IP) {
	sendICMPProbeWithID(iface, target, 0)
}

// sendICMPProbeWithID sends a single ICMP echo request with a specific echo
// ID. Varying the ID causes RSS to distribute replies across different NIC
// queues, triggering NAPI on each queue for zero-copy fill ring processing.
func sendICMPProbeWithID(iface string, target net.IP, id uint16) {
	if target.To4() != nil {
		fd, err := linuxsock.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMP Echo: type=8, code=0, checksum(auto), id, seq=1
		icmp := [8]byte{8, 0, 0, 0, byte(id >> 8), byte(id), 0, 1}
		// Compute checksum
		var sum uint32
		for i := 0; i < 8; i += 2 {
			sum += uint32(icmp[i])<<8 | uint32(icmp[i+1])
		}
		sum = (sum >> 16) + (sum & 0xffff)
		sum += sum >> 16
		cs := uint16(^sum)
		icmp[2] = byte(cs >> 8)
		icmp[3] = byte(cs)
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, icmp[:], unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := linuxsock.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
		// ICMPv6 Echo: type=128, code=0, checksum(kernel), id, seq=1
		icmp6 := [8]byte{128, 0, 0, 0, byte(id >> 8), byte(id), 0, 1}
		sa6 := &unix.SockaddrInet6{}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
	}
}

// sendUDPProbeForNAPI sends a single UDP packet to the target on the given
// port. The packet is sent via a raw UDP socket bound to the interface.
// The destination is unlikely to respond, but the important thing is that
// the REPLY (ICMP port unreachable) or even the outgoing packet's DMA
// completion triggers NAPI on the NIC queue determined by RSS hash of
// (src_ip, dst_ip, src_port, dst_port). Different ports → different queues.
func sendUDPProbeForNAPI(iface string, target net.IP, port uint16) {
	if target.To4() != nil {
		fd, err := linuxsock.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		sa := &unix.SockaddrInet4{Port: int(port)}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, []byte("napi"), unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := linuxsock.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		sa6 := &unix.SockaddrInet6{Port: int(port)}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, []byte("napi"), unix.MSG_DONTWAIT, sa6)
	}
}

// proactiveNeighborResolveAsyncLocked is the non-blocking version that
// fires probes in background goroutines. Used by the status loop.
func (m *Manager) proactiveNeighborResolveAsyncLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	cfg := m.lastSnapshot.Config
	go proactiveNeighborResolveAsync(cfg)
}

type neighborProbeTarget struct {
	iface string
	ip    string
}

func proactiveNeighborResolveAsync(cfg *config.Config) {
	seen := make(map[string]bool)
	targetSet := make(map[string]struct{})
	var targets []neighborProbeTarget
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		base := config.LinuxIfName(ifName)
		seen[base] = true // include base interface for route-GW probing
		for _, unit := range ifc.Units {
			linuxName := base
			if unit.VlanID > 0 {
				linuxName = fmt.Sprintf("%s.%d", base, unit.VlanID)
			}
			seen[linuxName] = true
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				neighs, err := netlink.NeighList(link.Attrs().Index, family)
				if err != nil {
					continue
				}
				for _, n := range neighs {
					if n.IP == nil || n.IP.IsLinkLocalUnicast() {
						continue
					}
					if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
						n.State == netlink.NUD_STALE || n.State == netlink.NUD_FAILED {
						key := linuxName + "|" + n.IP.String()
						if _, ok := targetSet[key]; ok {
							continue
						}
						targetSet[key] = struct{}{}
						targets = append(targets, neighborProbeTarget{iface: linuxName, ip: n.IP.String()})
					}
				}
			}
		}
	}
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_ALL)
	for _, r := range routes {
		if r.Gw == nil || r.Gw.IsLinkLocalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link == nil {
			continue
		}
		ifName := link.Attrs().Name
		if !seen[ifName] {
			continue
		}
		existing, _ := netlink.NeighList(r.LinkIndex, netlink.FAMILY_ALL)
		found := false
		for _, n := range existing {
			if n.IP.Equal(r.Gw) && n.HardwareAddr != nil && len(n.HardwareAddr) > 0 &&
				n.State != netlink.NUD_FAILED {
				found = true
				break
			}
		}
		if found {
			continue
		}
		key := ifName + "|" + r.Gw.String()
		if _, ok := targetSet[key]; ok {
			continue
		}
		targetSet[key] = struct{}{}
		targets = append(targets, neighborProbeTarget{iface: ifName, ip: r.Gw.String()})
	}
	for _, t := range targets {
		go func(iface, ip string) {
			targetIP := net.ParseIP(ip)
			if targetIP != nil {
				sendICMPProbeFromManager(iface, targetIP)
			}
		}(t.iface, t.ip)
	}
}
