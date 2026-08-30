package config

// Kea `dhcp-socket-type` values (#7318). These are the SINGLE source of the
// spelling: the setSchema leaf's validator, the compiler, the commit-time
// advisory and the Kea renderer (pkg/dhcpserver) all read these constants
// rather than repeating string literals, so the accepted value and the
// rendered value cannot drift apart.
const (
	// DHCPSocketTypeRaw is Kea's documented default. Dhcp4 receives on an
	// AF_PACKET socket, which is delivered before the netfilter input hook.
	DHCPSocketTypeRaw = "raw"
	// DHCPSocketTypeUDP puts Dhcp4 on an ordinary UDP socket that traverses
	// the input hook. Relayed/renewing traffic only — see the trade below.
	DHCPSocketTypeUDP = "udp"
)

// WHY THE LEAF EXISTS, AND WHY IT IS OPT-IN.
//
// The raw socket is delivered at ptype_all, BEFORE ip_rcv, so no netfilter
// rule can gate DHCPv4. Measured on a live node: an INPUT drop at priority
// -100 COUNTED the packet — both the 255.255.255.255 and the
// interface-unicast destination — and Kea answered anyway. The netfilter
// verdict is not skipped; it lands on a copy Kea never reads. Selecting
// DHCPSocketTypeUDP moves Dhcp4 onto an ordinary UDP socket that does
// traverse the input hook.
//
// The trade is NOT free, and it is the whole reason this is opt-in rather
// than a default flip. Per Kea's own documentation, "Using UDP sockets
// automatically disables the reception of broadcast packets from directly
// connected clients. This effectively means that UDP sockets can be used for
// relayed traffic only." So `udp` serves relayed and RENEWING (unicast)
// clients and stops serving directly-attached clients that have no address
// yet — the ordinary DISCOVER case. It is correct only for a relay-only
// deployment, and validateDHCPSocketTypeWarnings names that trade at commit.
//
// There is no v6 analogue: Kea's Dhcp6 has no raw mode and already receives
// on UDP, so the leaf is not modeled under dhcpv6-local-server.

// dhcpSocketTypes is the accepted value set for the `dhcp-socket-type` leaf.
var dhcpSocketTypes = []string{DHCPSocketTypeRaw, DHCPSocketTypeUDP}
