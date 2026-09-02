package daemon

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// #8297 — a proxy-ARP responder for a NAT pool address must follow REDUNDANCY
// GROUP ownership, exactly as the DHCP relay and DDNS writer gates already do.
//
// THE DEFECT, measured on loss:xpf-userspace-fw0/fw1. Both nodes installed the
// NTF_PROXY entry for a pool address regardless of which one owned the RG:
//
//	fw0  primary         -> 172.16.80.7 dev ge-0-0-2.80 proxy
//	fw1  secondary-hold  -> 172.16.80.7 dev ge-7-0-2.80 proxy
//
// and both answered, with their distinct per-node RETH virtual MACs
// (02:bf:72:16:01:00 and ...:01). The upstream sees one IP at two MACs, and
// pool-mode TCP never completes a handshake. The discriminating control: from
// one host in one second, a source matching the interface-mode rule reached
// 5.95 Gbit/s while a source matching the pool rule timed out; ICMP through the
// same pool worked, which clears translation, routing and the reverse path.
//
// WHY THIS IS THE RIGHT LAYER. Answering ARP for a pool address is claiming a
// VIP-adjacent identity, which is the same question VRRP already answers for
// the VIPs themselves — and it answers it by NOT HOLDING the address rather
// than by filtering replies. Tying the proxy entry to RG ownership puts both on
// one rule instead of two mechanisms that can disagree.
//
// THE ARM MOST LIKELY TO BE GOT WRONG is the one with the widest blast radius:
// a box with NO redundancy groups must never be gated. Gating there would break
// pool-mode NAT on every standalone deployment, which is the larger population
// by far, and it would pass every cluster test. Both escape hatches below are
// therefore checked BEFORE ownership is consulted, and each has its own cell.

// proxyARPInterfaceRG resolves the redundancy group owning the proxy-ARP
// interface named ifaceName, or 0 when it is not RG-owned.
//
// Mirrors relayInterfaceRG (#2456), which mirrors rgForInterfaces (#2664):
// strip the unit suffix, look the base interface up in the config table, read
// RedundancyGroup. A nil config or unknown interface yields 0, i.e. never gate.
func proxyARPInterfaceRG(cfg *config.Config, ifaceName string) int {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return 0
	}
	base := ifaceName
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if ifc, ok := cfg.Interfaces.Interfaces[base]; ok && ifc != nil && ifc.RedundancyGroup > 0 {
		return ifc.RedundancyGroup
	}
	return 0
}

// proxyARPOwnsInterface reports whether THIS node may answer proxy-ARP on
// ifaceName. Decision order mirrors relayMasterGateOpen:
//
//   - standalone (d.cluster == nil): always yes;
//   - not RG-owned (RG 0): always yes — a non-HA segment has no duplicate
//     responder to be;
//   - RG-owned: yes IFF this node is currently MASTER for that RG, read from
//     the live rgStateMachine, the same source the DHCP relay / DDNS gates use.
func (d *Daemon) proxyARPOwnsInterface(cfg *config.Config, ifaceName string) bool {
	if d == nil || d.cluster == nil {
		return true
	}
	rg := proxyARPInterfaceRG(cfg, ifaceName)
	if rg == 0 {
		return true
	}
	return d.isRethMasterState(rg)
}

// proxyARPOwnedEntries filters cfg's proxy-arp entries to those this node may
// answer for. `owns` is injected so the filter is testable without a daemon,
// a cluster, or netlink.
//
// An entry that is filtered OUT simply drops from the desired set, and the
// #4955 teardown in reconcileProxyARP then sweeps its NTF_PROXY entries and
// drives the per-interface sysctl back down. That is why this change needs no
// removal path of its own: losing ownership is expressed as "no longer
// desired", which the reconcile already knows how to act on.
func proxyARPOwnedEntries(cfg *config.Config, owns func(string) bool) []*config.ProxyARPEntry {
	if cfg == nil {
		return nil
	}
	out := make([]*config.ProxyARPEntry, 0, len(cfg.Security.NAT.ProxyARP))
	for _, e := range cfg.Security.NAT.ProxyARP {
		if owns == nil || owns(e.Interface) {
			out = append(out, e)
		}
	}
	return out
}

// proxyARPOwnershipFingerprint summarises the ownership decision for every
// configured proxy-arp interface, so the reassert loop can notice a CHANGE
// without taking the apply semaphore on every tick.
//
// The 30s unconditional beat is too slow on its own: after a failover the
// demoted node would keep answering for up to 30 seconds, and an upstream that
// cached its MAC in that window sends pool return traffic to a node that no
// longer owns the address. Fingerprinting is cheap — a config map lookup and an
// rgStateMachine read per entry — so it can run on a short ticker and reconcile
// only when the answer actually moved.
func (d *Daemon) proxyARPOwnershipFingerprint(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	var b strings.Builder
	for _, e := range cfg.Security.NAT.ProxyARP {
		fmt.Fprintf(&b, "%s=%t;", e.Interface, d.proxyARPOwnsInterface(cfg, e.Interface))
	}
	return b.String()
}
