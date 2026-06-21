package dataplane

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProxyARPAdded describes a newly added proxy ARP entry (for GARP).
type ProxyARPAdded struct {
	Ifindex int
	IP      net.IP
	Iface   string
}

// proxyARPSysctlSeam wraps the per-interface procfs writes that enable the
// kernel's proxy-responder for the families we install neighbor entries for.
// It exists as a package var so unit tests can capture the writes without
// touching real procfs (the production writer is a best-effort os.WriteFile).
//
// #2160: installing an NTF_PROXY neighbor entry is necessary but, depending
// on the route topology of the proxied address, often not sufficient. The
// Linux kernel has two distinct ARP-proxy reply paths (net/ipv4/arp.c):
//
//   1. the pneigh (NTF_PROXY) reply branch (arp.c:863-868), which fires when
//      forwarding is on, the target's addr_type is RTN_UNICAST, and the route
//      to the target leaves a *different* device than the one the request
//      arrived on (rt.dst.dev != dev) — this branch does NOT consult the
//      per-interface proxy_arp sysctl; and
//   2. the arp_fwd_proxy path, which is gated by net.ipv4.conf.<if>.proxy_arp
//      (and answers for any forwarded-out-a-different-iface target, not only
//      installed pneigh entries).
//
// So whether enabling the sysctl is load-bearing is route-topology dependent:
// for an external address that is on the SAME L2 subnet as the ingress
// interface (rt.dst.dev == dev) neither path answers, and for an address
// routed OUT a different interface the pneigh branch may already answer
// without the sysctl. The empirical #2160 observation (sysctl=0 → no reply
// for the static-NAT external address) is real, so enabling the sysctl is the
// correct fix; we set net.ipv4.conf.<if>.proxy_arp (ARP) and
// net.ipv6.conf.<if>.proxy_ndp (NDP) on every interface with a desired proxy
// entry to guarantee a reply regardless of the topology.
//
// Breadth tradeoff: with the default medium_id=0, per-interface proxy_arp=1
// makes the kernel (path 2 above) answer ARP on that interface for ANY target
// IP that routes out a DIFFERENT interface — not only the configured
// static-NAT external address. This is BROADER than Junos `proxy-arp`, which
// proxies only the listed addresses. It is an operator-opted-in tradeoff (they
// configured proxy-arp on this interface), but the breadth matters on a
// WAN/untrust interface. Narrowing to per-address (Junos parity) is tracked in
// follow-up #2197.
var proxyARPSysctlSeam = writeProxyResponderSysctl

// writeProxyResponderSysctl enables the kernel proxy responder for the given
// interface and address family. Best-effort: a failure (read-only procfs,
// interface vanished) is logged by the caller, never fatal — matching the
// surrounding proxy-ARP reconcile's best-effort posture.
func writeProxyResponderSysctl(iface string, family int) error {
	var path string
	switch family {
	case unix.AF_INET:
		path = fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", iface)
	case unix.AF_INET6:
		path = fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface)
	default:
		return fmt.Errorf("proxy-arp: unsupported family %d", family)
	}
	return os.WriteFile(path, []byte("1"), 0644)
}

// enableProxyResponders enables the per-interface proxy responder sysctl for
// every (interface, family) pair that has at least one desired proxy entry.
// Pure decision logic over the resolved iface-name→family set so it is unit
// testable; the actual procfs writes go through proxyARPSysctlSeam. Returns
// the number of writes that succeeded.
//
// ifaceFamilies maps an interface NAME (the kernel/procfs name, matching the
// interface the neighbor entry is installed on) to the set of address
// families that have a desired proxy entry on that interface. The sysctl is
// enabled idempotently (the kernel no-ops a write of the already-set value),
// so we always write rather than read-modify-write. A deterministic key sort
// keeps logging stable.
func enableProxyResponders(ifaceFamilies map[string]map[int]struct{}) int {
	enabled := 0
	names := make([]string, 0, len(ifaceFamilies))
	for iface := range ifaceFamilies {
		names = append(names, iface)
	}
	sort.Strings(names)
	for _, iface := range names {
		fams := ifaceFamilies[iface]
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			if _, ok := fams[family]; !ok {
				continue
			}
			if err := proxyARPSysctlSeam(iface, family); err != nil {
				slog.Warn("proxy-arp: failed to enable proxy responder sysctl",
					"iface", iface, "family", family, "err", err)
				continue
			}
			enabled++
		}
	}
	return enabled
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

	// ifindexFamilies records, per interface ifindex, the set of address
	// families that have at least one desired proxy entry. Used to enable
	// the per-interface kernel proxy responder sysctl (#2160). The NTF_PROXY
	// neighbor entry alone answers only via the kernel's pneigh reply branch,
	// which is route-topology dependent (it requires the target to route out a
	// different device than the request arrived on — see the proxyARPSysctlSeam
	// doc); setting net.ipv4.conf.<if>.proxy_arp / proxy_ndp guarantees a reply
	// regardless of topology, which is what #2160 needed.
	// Keyed by ifindex so the procfs interface name resolves from the same
	// link the neighbor entry is installed on (handles VLAN sub-interface
	// renaming consistently with the install).
	ifindexFamilies := make(map[int]map[int]struct{})
	recordFamily := func(ifindex, family int) {
		fams := ifindexFamilies[ifindex]
		if fams == nil {
			fams = make(map[int]struct{})
			ifindexFamilies[ifindex] = fams
		}
		fams[family] = struct{}{}
	}

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
			addr := prefix.Addr()
			if addr.Is6() && !addr.Is4In6() {
				// IPv6 proxy entry — needs proxy_ndp on the ingress
				// interface. The NTF_PROXY neighbor install below is
				// IPv4-only (the kernel proxy-NDP table is managed
				// separately); record the family so the v6 responder
				// sysctl still gets enabled.
				recordFamily(ifindex, unix.AF_INET6)
				continue
			}
			desired[proxyKey{ifindex, addr}] = struct{}{}
			recordFamily(ifindex, unix.AF_INET)
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

	// Enable the per-interface kernel proxy responder sysctl for every
	// interface that has a desired proxy entry (#2160). The pneigh entry
	// installed above only answers via a route-topology-dependent kernel path
	// (see proxyARPSysctlSeam); the sysctl guarantees a reply. Resolve the
	// procfs interface name from the same ifindex the neighbor entry was
	// installed on so VLAN sub-interface naming stays consistent with the
	// install.
	ifaceFamilies := make(map[string]map[int]struct{}, len(ifindexFamilies))
	for ifindex, fams := range ifindexFamilies {
		link, err := netlink.LinkByIndex(ifindex)
		if err != nil {
			slog.Warn("proxy-arp: cannot resolve interface name for proxy responder sysctl",
				"ifindex", ifindex, "err", err)
			continue
		}
		ifaceFamilies[link.Attrs().Name] = fams
	}
	enableProxyResponders(ifaceFamilies)

	if len(added) > 0 || removed > 0 {
		slog.Info("proxy-arp reconciled", "added", len(added), "removed", removed)
	}

	return added, nil
}
