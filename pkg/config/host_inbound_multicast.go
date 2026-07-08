package config

import (
	"sort"
	"strings"
)

// host_inbound_multicast.go is the protocol -> well-known multicast-group
// catalog for host-bound routing multicast (#4455, HI-1).
//
// VERIFY-FIRST CONTEXT (current master). The kernel `xpf_hostinbound`
// `chain input` (pkg/daemon/daemon_nft.go, buildHostInboundFilterPayload) runs
// `type filter hook input ... policy accept` and matches host-local UNICAST
// destination addresses only — every per-zone rule is scoped by
// `<fam> daddr <zone-addrs>`. A host-bound packet addressed to a well-known
// routing MULTICAST group (OSPF 224.0.0.5/6, VRRP 224.0.0.18, PIM 224.0.0.13,
// ...) matches NO per-zone `daddr` set, so it falls through the chain's
// `policy accept` to the host stack WITHOUT any per-zone
// `host-inbound-traffic protocols` scoping. The Rust AF_XDP classifier
// (host_inbound_admits, userspace-dp/src/afxdp/forwarding/host_inbound.rs) keys
// only on (zone, protocol, dst_port, family, icmp_type) — it has NO
// destination-address dimension — so it does not gate host-bound multicast
// either.
//
// This is FAIL-OPEN-BUT-BOUNDED, a Junos-parity/hardening gap rather than an
// open door: the host kernel delivers multicast only to groups a configured
// daemon actually joined (a routing daemon the operator enabled), and the
// always-on control set (IPv6 ND, PMTUD/error ICMP, ESP/AH) is already globally
// accepted. So OSPF/VRRP/PIM do NOT break today; the parity gap is that the
// admission is PACKET-WIDE (on every ingress interface) instead of scoped to
// the zone whose `host-inbound-traffic protocols` opted in.
//
// This catalog is the design artifact that settles decision (2) of the deferred
// enforcement (#4455): the protocol -> multicast-group enumeration the eventual
// per-zone `iifname`-scoped nft set and the Rust address dimension will admit.
// TODAY it backs ONLY the commit-time advisory
// (validateHostInboundMulticastWarnings) — it makes NO forwarding decision. The
// full enforcement (a new `iifname` predicate on BOTH surfaces, the #1960
// migration gating because enforcement is fail-CLOSED on revert of today's
// accept, and the kernel/Rust lockstep) remains DEFERRED. See
// docs/host-inbound-multicast.md for the four coupled decisions.

// HostInboundMulticastGroups is the well-known multicast groups a routing
// protocol's host-bound control traffic is addressed to, split by family. A
// dual-family protocol (pim, vrrp) populates both; a family-specific protocol
// (ospf/rip/igmp/router-discovery are IPv4, ospf3/ripng are IPv6) populates
// only its family, matching HostInboundProtocolFamily.
type HostInboundMulticastGroups struct {
	V4    []string // well-known IPv4 groups (nil for an IPv6-only protocol)
	V6    []string // well-known IPv6 groups (nil for an IPv4-only protocol)
	Label string   // short human label for the advisory / doc (e.g. "OSPFv2")
}

// hostInboundMulticastCatalog maps a `host-inbound-traffic protocols` token to
// its well-known multicast groups. Only protocols whose host-bound CONTROL
// traffic rides a well-known multicast group are listed — unicast routing
// control (bgp/ldp/msdp/nhrp: TCP/UDP to a peer address; bfd: UDP to the peer)
// is deliberately absent, and L2/non-IP protocols (isis) never reach the IP
// input chain. `all` is handled by the callers via
// HostInboundAllExpansionProtocols (it expands to this set's members plus the
// unicast ones). Family split mirrors HostInboundProtocolFamily.
var hostInboundMulticastCatalog = map[string]HostInboundMulticastGroups{
	// OSPFv2 AllSPFRouters / AllDRouters (IP proto 89, IPv4).
	"ospf": {V4: []string{"224.0.0.5", "224.0.0.6"}, Label: "OSPFv2"},
	// OSPFv3 AllSPFRouters / AllDRouters (IP proto 89, IPv6).
	"ospf3": {V6: []string{"ff02::5", "ff02::6"}, Label: "OSPFv3"},
	// RIPv2 (UDP 520, IPv4).
	"rip": {V4: []string{"224.0.0.9"}, Label: "RIPv2"},
	// RIPng (UDP 521, IPv6).
	"ripng": {V6: []string{"ff02::9"}, Label: "RIPng"},
	// PIM ALL-PIM-ROUTERS (IP proto 103, dual-family).
	"pim": {V4: []string{"224.0.0.13"}, V6: []string{"ff02::d"}, Label: "PIM"},
	// IGMP all-hosts / IGMPv3 membership reports (IP proto 2, IPv4 only).
	"igmp": {V4: []string{"224.0.0.1", "224.0.0.22"}, Label: "IGMP"},
	// DVMRP ALL-DVMRP-ROUTERS — carried inside IGMP (IP proto 2), IPv4 only.
	"dvmrp": {V4: []string{"224.0.0.4"}, Label: "DVMRP"},
	// VRRP (IP proto 112, dual-family; ff02::12 is the IPv6 VRRP group).
	"vrrp": {V4: []string{"224.0.0.18"}, V6: []string{"ff02::12"}, Label: "VRRP"},
	// ICMP router discovery (IRDP): advertisements to 224.0.0.1 (all-hosts),
	// solicitations to 224.0.0.2 (all-routers). IPv4 only — the IPv6 equivalent
	// is Neighbor Discovery RS/RA, already in the always-accepted ND set.
	"router-discovery": {V4: []string{"224.0.0.1", "224.0.0.2"}, Label: "router-discovery (IRDP)"},
}

// HostInboundMulticastProtocol reports whether a `host-inbound-traffic
// protocols` token is a MULTICAST routing protocol (its host-bound control
// traffic is addressed to a well-known multicast group) and returns its groups.
// Unicast routing-control tokens (bgp/ldp/msdp/nhrp/bfd), L2 tokens (isis), and
// the `all` meta-token return ok=false — callers expand `all` via
// HostInboundAllExpansionProtocols before consulting this.
func HostInboundMulticastProtocol(token string) (HostInboundMulticastGroups, bool) {
	g, ok := hostInboundMulticastCatalog[strings.ToLower(token)]
	return g, ok
}

// HostInboundMulticastProtocolTokens returns the multicast routing-protocol
// tokens (catalog keys) in sorted order, for deterministic advisory/doc output.
func HostInboundMulticastProtocolTokens() []string {
	out := make([]string, 0, len(hostInboundMulticastCatalog))
	for tok := range hostInboundMulticastCatalog {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// hostInboundMulticastTokensPresent returns the sorted set of MULTICAST
// routing-protocol tokens implied by a zone/interface `host-inbound-traffic
// protocols` list, expanding the `all` meta-token to its routing-protocol set
// (#3199, HostInboundAllExpansionProtocols) first. Unicast/L2 tokens are
// dropped. Returns nil when the list admits no multicast protocol.
func hostInboundMulticastTokensPresent(protocols []string) []string {
	seen := map[string]bool{}
	var add func(tok string)
	add = func(tok string) {
		tok = strings.ToLower(tok)
		if tok == "all" {
			for _, p := range HostInboundAllExpansionProtocols() {
				add(p)
			}
			return
		}
		if _, ok := hostInboundMulticastCatalog[tok]; ok {
			seen[tok] = true
		}
	}
	for _, p := range protocols {
		add(p)
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for tok := range seen {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// hostInboundMulticastGroupSummary renders a compact, deterministic
// "PROTOCOL group[/group...]" summary for the given multicast tokens, for the
// commit-time advisory text — e.g. "OSPFv2 224.0.0.5/224.0.0.6, PIM
// 224.0.0.13/ff02::d". Tokens must already be filtered to catalog members
// (hostInboundMulticastTokensPresent) and sorted.
func hostInboundMulticastGroupSummary(tokens []string) string {
	parts := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		g, ok := hostInboundMulticastCatalog[tok]
		if !ok {
			continue
		}
		groups := make([]string, 0, len(g.V4)+len(g.V6))
		groups = append(groups, g.V4...)
		groups = append(groups, g.V6...)
		parts = append(parts, g.Label+" "+strings.Join(groups, "/"))
	}
	return strings.Join(parts, ", ")
}
