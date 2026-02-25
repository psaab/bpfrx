package dataplane

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProxyARPAdded describes a newly added proxy ARP entry (for GARP).
type ProxyARPAdded struct {
	Ifindex int
	IP      net.IP
	Iface   string
}

// ReconcileProxyARP reconciles proxy ARP neighbor entries for NAT addresses.
// It adds NTF_PROXY neighbor entries for configured addresses and removes
// stale ones from managed interfaces. Returns newly added entries so the
// caller can send GARPs (avoids import cycle with cluster package).
func ReconcileProxyARP(cfg *config.Config, ifaceMap map[string]int) ([]ProxyARPAdded, error) {
	type proxyKey struct {
		ifindex int
		ip      netip.Addr
	}

	// Build desired set from config.
	desired := make(map[proxyKey]struct{})
	var managedIfindexes []int

	for _, entry := range cfg.Security.NAT.ProxyARP {
		ifindex, ok := ifaceMap[entry.Interface]
		if !ok {
			slog.Warn("proxy-arp: interface not found", "iface", entry.Interface)
			continue
		}
		managedIfindexes = append(managedIfindexes, ifindex)
		for _, cidr := range entry.Addresses {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				slog.Warn("proxy-arp: invalid address", "addr", cidr, "err", err)
				continue
			}
			desired[proxyKey{ifindex, prefix.Addr()}] = struct{}{}
		}
	}

	// Collect existing NTF_PROXY entries on managed interfaces.
	existing := make(map[proxyKey]struct{})
	managedSet := make(map[int]bool)
	for _, idx := range managedIfindexes {
		managedSet[idx] = true
	}

	for idx := range managedSet {
		neighs, err := netlink.NeighList(idx, unix.AF_INET)
		if err != nil {
			slog.Warn("proxy-arp: failed to list neighbors", "ifindex", idx, "err", err)
			continue
		}
		for _, n := range neighs {
			if n.Flags&unix.NTF_PROXY == 0 {
				continue
			}
			if n.IP == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(n.IP.To4())
			if !ok {
				continue
			}
			existing[proxyKey{idx, addr}] = struct{}{}
		}
	}

	// Add missing entries.
	var added []ProxyARPAdded
	for key := range desired {
		if _, ok := existing[key]; ok {
			continue
		}
		neigh := &netlink.Neigh{
			LinkIndex: key.ifindex,
			IP:        key.ip.AsSlice(),
			Flags:     unix.NTF_PROXY,
			Family:    unix.AF_INET,
		}
		if err := netlink.NeighSet(neigh); err != nil {
			return nil, fmt.Errorf("proxy-arp: add %s on ifindex %d: %w", key.ip, key.ifindex, err)
		}
		ifaceName := ""
		if link, err := netlink.LinkByIndex(key.ifindex); err == nil {
			ifaceName = link.Attrs().Name
		}
		added = append(added, ProxyARPAdded{
			Ifindex: key.ifindex,
			IP:      net.IP(key.ip.AsSlice()),
			Iface:   ifaceName,
		})
	}

	// Remove stale entries on managed interfaces.
	var removed int
	for key := range existing {
		if _, ok := desired[key]; ok {
			continue
		}
		neigh := &netlink.Neigh{
			LinkIndex: key.ifindex,
			IP:        key.ip.AsSlice(),
			Flags:     unix.NTF_PROXY,
			Family:    unix.AF_INET,
		}
		if err := netlink.NeighDel(neigh); err != nil {
			slog.Warn("proxy-arp: failed to remove stale entry",
				"ip", key.ip, "ifindex", key.ifindex, "err", err)
		} else {
			removed++
		}
	}

	if len(added) > 0 || removed > 0 {
		slog.Info("proxy-arp reconciled", "added", len(added), "removed", removed)
	}

	return added, nil
}
