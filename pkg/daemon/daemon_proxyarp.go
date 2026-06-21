package daemon

import (
	"log/slog"
	"net"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// ifaceIndexByName resolves a Linux interface name to its kernel ifindex. It
// is a package var so the RETH-resolution unit test can drive
// proxyARPIfaceMap without real interfaces; production wiring is
// net.InterfaceByName.
var ifaceIndexByName = func(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// proxyARPIfaceMap maps each configured proxy-arp interface name to its kernel
// ifindex, resolving a RETH name to its physical member (the #2195 fix:
// cfg.RethToPhysical() + config.LinuxIfName). A VLAN sub-interface name
// (reth0.50) is split on "." so the base interface is resolved/renamed, then
// the unit-qualified key is preserved. An unresolvable interface is logged and
// skipped (best-effort, matching the reconcile's posture). Extracted so the
// RETH resolution stays unit-testable independently of the netlink install
// (regression guard against dropping it in the apply-path extraction).
func proxyARPIfaceMap(cfg *config.Config) map[string]int {
	ifaceMap := make(map[string]int)
	rethToPhys := cfg.RethToPhysical()
	for _, entry := range cfg.Security.NAT.ProxyARP {
		if _, ok := ifaceMap[entry.Interface]; ok {
			continue
		}
		parts := strings.SplitN(entry.Interface, ".", 2)
		baseName := parts[0]
		if phys, ok := rethToPhys[baseName]; ok {
			baseName = phys
		}
		linuxName := config.LinuxIfName(baseName)
		idx, err := ifaceIndexByName(linuxName)
		if err != nil {
			slog.Warn("proxy-arp: interface not found", "iface", entry.Interface, "linux", linuxName, "err", err)
			continue
		}
		ifaceMap[entry.Interface] = idx
	}
	return ifaceMap
}

// reconcileProxyARP reconciles the kernel proxy-ARP/NDP responder state
// (NTF_PROXY neighbor entries + the per-interface proxy_arp/proxy_ndp sysctls)
// for the configured `security nat proxy-arp` addresses. It is a no-op when no
// proxy-arp entries are configured.
//
// This is the apply-path reconcile (formerly inline in applyConfigLocked step
// 2.6c) extracted so the always-on periodic loop can re-run the identical
// reconcile after a non-commit link cycle (#2197 item 2). The reconcile is
// idempotent (it diffs desired vs existing entries and re-writes the sysctl,
// which the kernel no-ops when already set) and best-effort (a netlink/sysctl
// failure is logged and never fatal), so re-running it on a steady config
// causes no churn.
//
// The RETH interface resolution (proxy-arp on a reth name resolves to the
// physical member ifindex via cfg.RethToPhysical() + config.LinuxIfName) is
// the #2195 fix; it is preserved here verbatim — losing it would re-break
// proxy-arp on RETH interfaces.
func (d *Daemon) reconcileProxyARP(cfg *config.Config) {
	if cfg == nil || len(cfg.Security.NAT.ProxyARP) == 0 {
		return
	}

	ifaceMap := proxyARPIfaceMap(cfg)

	added, err := dataplane.ReconcileProxyARP(cfg, ifaceMap)
	if err != nil {
		slog.Warn("failed to reconcile proxy ARP", "err", err)
	}
	for _, a := range added {
		// SendGratuitousARP is IPv4-only; a v6 (AF_INET6) proxy-NDP entry
		// needs no unsolicited NA to start answering, so skip the GARP for
		// v6 added entries (#2197 item 1).
		if a.Iface != "" && a.Family != unix.AF_INET6 {
			if err := cluster.SendGratuitousARP(a.Iface, a.IP, 1); err != nil {
				slog.Warn("proxy-arp: GARP failed", "ip", a.IP, "iface", a.Iface, "err", err)
			}
		}
	}
}
