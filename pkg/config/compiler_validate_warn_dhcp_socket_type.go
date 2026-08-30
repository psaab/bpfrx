package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateDHCPSocketTypeWarnings warns when `system services dhcp-local-server
// dhcp-socket-type udp` is selected (#7318).
//
// WARN-ONLY, ZERO DATAPLANE SURFACE. It returns advisory strings and no error,
// matching the #1960 no-brick doctrine the sibling DHCP advisories follow: a
// configuration that selects `udp` still commits, because for a relay-only
// deployment it is the correct choice and is the whole point of the leaf.
//
// Why this advisory is the load-bearing half of the feature. Selecting `udp`
// is not a tuning knob with a small blast radius — it changes WHICH CLIENTS
// THE SERVER WILL ANSWER AT ALL, and it does so silently. Kea's own
// documentation states it plainly:
//
//	"Using UDP sockets automatically disables the reception of broadcast
//	 packets from directly connected clients. This effectively means that
//	 UDP sockets can be used for relayed traffic only."
//
// So on a firewall serving its own directly-attached LAN, `udp` stops new
// clients getting an address — a DHCPDISCOVER is a broadcast, and nothing is
// listening for it any more. Existing clients appear fine for a while, because
// a RENEWING client unicasts to the server address and is still served, so the
// breakage surfaces at lease-acquisition time rather than at commit: exactly
// the shape that gets blamed on something else. The operator must be told the
// trade in the terms they will observe it in, which is why this message names
// the client populations rather than saying "sets dhcp-socket-type".
//
// The gateability the operator BUYS is real and is why the leaf exists. On
// `raw`, Kea receives on an AF_PACKET socket delivered at ptype_all, before
// ip_rcv, so no netfilter rule can gate DHCPv4 — measured on a live node, an
// INPUT drop at priority -100 counted the packet on BOTH the 255.255.255.255
// and the interface-unicast destination and Kea answered regardless. The drop
// is not skipped; it lands on a copy Kea never reads. On `udp` the server's
// traffic is ordinary unicast to a zone address, so the per-zone host-inbound
// rules match it and `host-inbound-traffic system-services dhcp` becomes
// load-bearing for the server path.
func validateDHCPSocketTypeWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.DHCPServer.DHCPLocalServer == nil {
		return nil
	}
	srv := cfg.System.DHCPServer.DHCPLocalServer
	if srv.SocketType != DHCPSocketTypeUDP {
		return nil
	}

	// Name the interfaces the operator will actually see this on. Sorted so
	// the advisory is deterministic across commits (#2668 discipline).
	var ifaces []string
	seen := map[string]bool{}
	for _, g := range srv.Groups {
		if g == nil {
			continue
		}
		for _, in := range g.Interfaces {
			if in != "" && !seen[in] {
				seen[in] = true
				ifaces = append(ifaces, in)
			}
		}
	}
	sort.Strings(ifaces)

	where := "the dhcp-local-server groups"
	if len(ifaces) > 0 {
		where = strings.Join(ifaces, ", ")
	}

	return []string{fmt.Sprintf(
		"system services dhcp-local-server dhcp-socket-type udp: DHCPv4 on %s will "+
			"serve RELAYED and RENEWING clients only. Directly-attached clients that "+
			"have no address yet will STOP being served, because Kea on a UDP socket "+
			"does not receive the broadcast DHCPDISCOVER they send; already-leased "+
			"clients keep renewing, so this surfaces when a new client asks for an "+
			"address, not at commit. Choose udp only for a relay-only deployment. "+
			"In exchange, DHCPv4 now traverses the netfilter input hook, so this "+
			"zone's `host-inbound-traffic system-services dhcp` governs the server "+
			"path (on the default `raw` it cannot: Kea receives on an AF_PACKET "+
			"socket delivered before that hook, and no nft rule can gate it)",
		where)}
}
