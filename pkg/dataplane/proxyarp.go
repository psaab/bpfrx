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

// ProxyARPAdded describes a newly added proxy ARP/NDP entry (for GARP).
//
// Family is the address family of the installed entry (unix.AF_INET or
// unix.AF_INET6). The caller uses it to gate the gratuitous-ARP send:
// SendGratuitousARP is IPv4-only, so a v6 (AF_INET6) added entry must not be
// handed to it (#2197 item 1, risk R1). The v6 proxy-NDP responder works
// without an unsolicited Neighbor Advertisement, so v6 entries simply skip the
// GARP step rather than emitting a v6 equivalent.
type ProxyARPAdded struct {
	Ifindex int
	IP      net.IP
	Iface   string
	Family  int
}

// netlink seams. The neighbor list/set/del operations are wrapped in package
// vars so unit tests can exercise the family-correct install/stale-removal
// logic (#2197 item 1) without CAP_NET_ADMIN. Production wiring is the real
// vishvananda/netlink calls; the kernel handles both AF_INET and AF_INET6
// NTF_PROXY entries through the same RTM_NEWNEIGH/RTM_DELNEIGH (Family-aware,
// To4()/To16() serialized), so no library-side family branching is required.
var (
	neighListSeam = netlink.NeighList
	neighSetSeam  = netlink.NeighSet
	neighDelSeam  = netlink.NeighDel
)

// proxyARPSysctlSeam wraps the per-interface procfs writes that toggle the
// kernel's proxy-responder for the families we install neighbor entries for.
// It exists as a package var so unit tests can capture the writes without
// touching real procfs (the production writer is a best-effort os.WriteFile).
// The enable bool selects the value written: true → "1" (enable), false →
// "0" (disable). The disable direction is the #2475 teardown cleanup — a
// day-2 commit removing proxy-arp from an interface must drive the leaked
// sysctl back to 0, mirroring the enable path.
//
// #2160: installing an NTF_PROXY neighbor entry is necessary but, depending
// on the route topology of the proxied address, often not sufficient. The
// Linux kernel has two distinct ARP-proxy reply paths (net/ipv4/arp.c):
//
//  1. the pneigh (NTF_PROXY) reply branch (arp.c:863-868), which fires when
//     forwarding is on, the target's addr_type is RTN_UNICAST, and the route
//     to the target leaves a *different* device than the one the request
//     arrived on (rt.dst.dev != dev) — this branch does NOT consult the
//     per-interface proxy_arp sysctl; and
//  2. the arp_fwd_proxy path, which is gated by net.ipv4.conf.<if>.proxy_arp
//     (and answers for any forwarded-out-a-different-iface target, not only
//     installed pneigh entries).
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

// writeProxyResponderSysctl toggles the kernel proxy responder for the given
// interface and address family. enable selects the written value: true → "1",
// false → "0". Best-effort: a failure (read-only procfs, interface vanished)
// is logged by the caller, never fatal — matching the surrounding proxy-ARP
// reconcile's best-effort posture.
func writeProxyResponderSysctl(iface string, family int, enable bool) error {
	var path string
	switch family {
	case unix.AF_INET:
		path = fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", iface)
	case unix.AF_INET6:
		path = fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface)
	default:
		return fmt.Errorf("proxy-arp: unsupported family %d", family)
	}
	val := []byte("0")
	if enable {
		val = []byte("1")
	}
	return os.WriteFile(path, val, 0644)
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
	return toggleProxyResponders(ifaceFamilies, true)
}

// disableProxyResponders writes "0" to the per-interface proxy responder
// sysctl for every (interface, family) pair in ifaceFamilies. It is the
// #2475 teardown cleanup: a day-2 commit that removes proxy-arp from an
// interface must drive net.ipv4.conf.<if>.proxy_arp /
// net.ipv6.conf.<if>.proxy_ndp back to 0, otherwise the kernel keeps
// proxy-ARPing for any target routed out a different interface (an
// over-broad responder leaked across config changes — see the
// proxyARPSysctlSeam breadth note). It mirrors enableProxyResponders
// exactly (same iteration, same best-effort/never-fatal posture, same
// deterministic v4-before-v6 order) so the disable is symmetric with the
// enable. Returns the number of writes that succeeded.
func disableProxyResponders(ifaceFamilies map[string]map[int]struct{}) int {
	return toggleProxyResponders(ifaceFamilies, false)
}

// toggleProxyResponders is the shared body of enableProxyResponders /
// disableProxyResponders: it writes the proxy responder sysctl (value chosen
// by enable) for every (interface, family) pair, in a deterministic
// interface-name order with v4 before v6. A per-write failure is logged and
// skipped (best-effort) without aborting the remaining writes.
func toggleProxyResponders(ifaceFamilies map[string]map[int]struct{}, enable bool) int {
	count := 0
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
			if err := proxyARPSysctlSeam(iface, family, enable); err != nil {
				verb := "enable"
				if !enable {
					verb = "disable"
				}
				slog.Warn("proxy-arp: failed to "+verb+" proxy responder sysctl",
					"iface", iface, "family", family, "err", err)
				continue
			}
			count++
		}
	}
	return count
}

// ReconcileProxyARP reconciles proxy ARP neighbor entries for NAT addresses.
// It adds NTF_PROXY neighbor entries for configured addresses and removes
// stale ones from managed interfaces.
//
// Returns:
//   - the newly added entries so the caller can send GARPs (avoids an import
//     cycle with the cluster package);
//   - the (interface name → enabled families) set the per-interface proxy
//     responder sysctl was enabled for this pass. The caller (the daemon)
//     remembers this set across commits and disables the sysctl on any
//     interface that drops out of it on a later commit — the #2475 teardown
//     cleanup. ReconcileProxyARP itself is stateless across calls (it only
//     sees the current config), so the enabled set is the seam the stateful
//     disable-on-removal is built on.
func ReconcileProxyARP(cfg *config.Config, ifaceMap map[string]int) ([]ProxyARPAdded, map[string]map[int]struct{}, error) {
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
			// #2197 item 1: install an NTF_PROXY neighbor entry for v6
			// addresses too (the v6 analogue of `ip -6 neigh add proxy
			// <addr> dev <if>`). Unlike v4 — where the broad arp_fwd_proxy
			// path can answer without a pneigh entry — IPv6 proxy-NDP is
			// gated on pneigh_lookup itself (net/ipv6/ndisc.c): the kernel
			// answers a v6 NS only if a matching v6 pneigh entry exists
			// (plus forwarding + proxy_ndp). So the v6 install is the
			// necessary-and-sufficient piece per listed address, and there
			// is no v6 over-answer breadth (the #2197 narrowing follow-up is
			// v4-only). A ::ffff:0:0/96 v4-mapped literal classifies as v4
			// (Is4In6) so it takes the v4 install path, never a v6 NeighSet.
			family := unix.AF_INET
			if addr.Is6() && !addr.Is4In6() {
				family = unix.AF_INET6
			}
			desired[proxyKey{ifindex, addr}] = struct{}{}
			recordFamily(ifindex, family)
		}
	}

	// Collect existing NTF_PROXY entries on managed interfaces.
	existing := make(map[proxyKey]struct{})
	managedSet := make(map[int]bool)
	for _, idx := range managedIfindexes {
		managedSet[idx] = true
	}

	// keyFamily derives the netlink address family for a key from its IP so
	// the add/remove netlink.Neigh carries the correct family. A v4-mapped v6
	// literal (Is4In6) is treated as v4 — consistent with the desired-set
	// classification above.
	keyFamily := func(ip netip.Addr) int {
		if ip.Is6() && !ip.Is4In6() {
			return unix.AF_INET6
		}
		return unix.AF_INET
	}

	// List existing NTF_PROXY entries for BOTH families on each managed
	// interface. The netip.Addr key keeps v4 and v6 disjoint, and each
	// NeighList(family) pass already only returns that family's entries, so a
	// v4-mapped form cannot be double-counted (#2197 item 1, risk R2).
	for idx := range managedSet {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			neighs, err := neighListSeam(idx, family)
			if err != nil {
				slog.Warn("proxy-arp: failed to list neighbors",
					"ifindex", idx, "family", family, "err", err)
				continue
			}
			for _, n := range neighs {
				if n.Flags&unix.NTF_PROXY == 0 {
					continue
				}
				if n.IP == nil {
					continue
				}
				var addr netip.Addr
				var ok bool
				if family == unix.AF_INET6 {
					// Skip v4-mapped entries surfaced on the v6 pass; the
					// v4 pass owns them via To4().
					if n.IP.To4() != nil {
						continue
					}
					addr, ok = netip.AddrFromSlice(n.IP.To16())
				} else {
					addr, ok = netip.AddrFromSlice(n.IP.To4())
				}
				if !ok {
					continue
				}
				existing[proxyKey{idx, addr}] = struct{}{}
			}
		}
	}

	// Add missing entries (family derived from the key — v4 and v6 share the
	// same NTF_PROXY install path; #2197 item 1).
	var added []ProxyARPAdded
	for key := range desired {
		if _, ok := existing[key]; ok {
			continue
		}
		family := keyFamily(key.ip)
		neigh := &netlink.Neigh{
			LinkIndex: key.ifindex,
			IP:        key.ip.AsSlice(),
			Flags:     unix.NTF_PROXY,
			Family:    family,
		}
		if err := neighSetSeam(neigh); err != nil {
			return nil, nil, fmt.Errorf("proxy-arp: add %s on ifindex %d: %w", key.ip, key.ifindex, err)
		}
		ifaceName := ""
		if link, err := netlink.LinkByIndex(key.ifindex); err == nil {
			ifaceName = link.Attrs().Name
		}
		added = append(added, ProxyARPAdded{
			Ifindex: key.ifindex,
			IP:      net.IP(key.ip.AsSlice()),
			Iface:   ifaceName,
			Family:  family,
		})
	}

	// Remove stale entries on managed interfaces (both families now listed).
	var removed int
	for key := range existing {
		if _, ok := desired[key]; ok {
			continue
		}
		neigh := &netlink.Neigh{
			LinkIndex: key.ifindex,
			IP:        key.ip.AsSlice(),
			Flags:     unix.NTF_PROXY,
			Family:    keyFamily(key.ip),
		}
		if err := neighDelSeam(neigh); err != nil {
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

	return added, ifaceFamilies, nil
}

// DisableProxyResponders writes "0" to the per-interface proxy responder
// sysctl for every (interface name → families) pair in ifaceFamilies. It is
// the exported #2475 teardown entry point the daemon calls for interfaces
// that had the sysctl enabled on a prior commit but are no longer in the
// desired set (proxy-arp removed from that interface). Best-effort and
// never fatal, matching ReconcileProxyARP. Returns the number of successful
// writes.
func DisableProxyResponders(ifaceFamilies map[string]map[int]struct{}) int {
	return disableProxyResponders(ifaceFamilies)
}
