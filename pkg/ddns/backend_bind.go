package ddns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// backend_bind.go: source / interface / VRF binding for the RFC 2136 UPDATE
// transport (#2691 P1b / #2665, plan §5.7). In a multi-WAN or VRF deployment a
// DNS UPDATE must egress from a specific source IP, a specific interface,
// and/or a specific routing-instance (VRF) — otherwise it leaves via the
// default table / kernel-chosen source and is dropped by source-IP-keyed ACLs
// (authoritative servers commonly ACL on source IP in addition to TSIG) or
// sent to the wrong upstream.
//
// The binding is built into the *dns.Client's transport via a custom
// net.Dialer:
//   - source-address       → Dialer.LocalAddr (bind the socket's source IP).
//   - destination-interface → Dialer.Control → SO_BINDTODEVICE (pin egress).
//   - routing-instance     → Dialer.Control → SO_BINDTODEVICE on the VRF
//     master device (Linux binds a socket into a VRF by binding to the vrf
//     device, which shares the routing-instance name — pkg/routing). When both
//     a destination-interface and a routing-instance are set, the
//     destination-interface wins for SO_BINDTODEVICE (the more specific pin);
//     a VRF-only config binds to the VRF device.
//
// FAIL-OPEN at runtime: a malformed source-address is rejected at construction
// (the manager falls back to a no-op for that family and counts it, never a
// crash); a SO_BINDTODEVICE failure surfaces as a dial error on the exchange,
// which the reconciler logs + retries next cycle (it never wedges DHCP). This
// matches the existing update-server / TSIG fail-open posture.

// bindConfig is the resolved source/interface/VRF binding for one family's
// backend (#2665). The zero value (all empty) means "no binding — default
// table / kernel source selection", today's behaviour byte-for-byte.
type bindConfig struct {
	sourceAddr  netip.Addr // bound source IP; zero ⇒ none
	bindDevice  string     // SO_BINDTODEVICE target (dest-interface or VRF dev)
	routingInst string     // routing-instance name (informational / VRF dev)
}

// resolveBindConfig builds a bindConfig from a DDNS policy's source-binding
// leaves (#2665). An empty config yields the zero bindConfig (no binding). A
// non-empty source-address that does not parse is a hard error so the manager
// falls back to no-op for that family (and counts it) rather than emitting
// UPDATEs from the wrong source.
func resolveBindConfig(c *config.DHCPDynamicDNSConfig) (bindConfig, error) {
	if c == nil {
		return bindConfig{}, nil
	}
	var b bindConfig
	if c.SourceAddress != "" {
		a, err := netip.ParseAddr(c.SourceAddress)
		if err != nil {
			return bindConfig{}, fmt.Errorf("ddns: invalid source-address %q: %w", c.SourceAddress, err)
		}
		b.sourceAddr = a.Unmap()
	}
	// destination-interface is the more specific SO_BINDTODEVICE pin; a VRF
	// (routing-instance) binds to its VRF master device, which shares the
	// routing-instance name. Prefer the explicit destination-interface.
	b.routingInst = c.RoutingInstance
	switch {
	case c.DestinationInterface != "":
		b.bindDevice = c.DestinationInterface
	case c.RoutingInstance != "":
		b.bindDevice = c.RoutingInstance
	}
	return b, nil
}

// isSet reports whether the bindConfig requests any binding.
func (b bindConfig) isSet() bool {
	return b.sourceAddr.IsValid() || b.bindDevice != ""
}

// dialer builds the net.Dialer the *dns.Client uses for both the UDP-first and
// the TCP-retry exchange, applying the source-address bind AND the
// interface/VRF SO_BINDTODEVICE in a SINGLE Dialer.Control hook.
//
// Both binds are done in Control (not via Dialer.LocalAddr) deliberately: the
// SAME dialer is reused for a "udp" dial (the primary path) and a "tcp" dial
// (the truncation retry, see exchange()), and net.Dialer.LocalAddr is
// network-typed (a *net.UDPAddr LocalAddr makes a "tcp" dial fail with an
// address-type mismatch). Binding the source IP with unix.Bind inside Control —
// where the socket fd is already open but not yet connected — works for BOTH
// networks with no type coupling. Port 0 lets the kernel pick the source port.
//
// Returns nil when no binding is requested (the *dns.Client then uses its
// default dialer — today's behaviour byte-for-byte).
//
// Dual-stack family gate (#2901): the source-bind is applied only when the
// source-address family MATCHES the dial socket's address family. The dialer is
// shared by the RFC 2136 backend AND, via newHTTPClientBound (#2846), every HTTP
// DDNS backend + the checkip probe — dialing endpoints that may resolve to both
// A and AAAA records. When Go's Happy-Eyeballs dials the family that does NOT
// match the configured source-address, calling unix.Bind with a SockaddrInet4 on
// an AF_INET6 socket (or the reverse) fails EAFNOSUPPORT/EINVAL and aborts the
// whole connection instead of letting it proceed. We therefore key off the
// Dialer.Control "network" argument ("tcp4"/"tcp6"/"udp4"/"udp6") and SKIP the
// source-bind on a family mismatch — the mismatched-family dial proceeds with
// the kernel-chosen source rather than hard-failing. SO_BINDTODEVICE is
// family-agnostic and is always applied. A configured source-address still
// constrains the matching family to the operator's source; the unmatched family
// (which the operator did not provide a source for) simply uses the default
// source. When network is empty/unsuffixed (no family hint), the bind is applied
// by source family as before.
func (b bindConfig) dialer(timeout time.Duration) *net.Dialer {
	if !b.isSet() {
		return nil
	}
	src := b.sourceAddr
	dev := b.bindDevice
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				if dev != "" {
					// SO_BINDTODEVICE pins egress to the named device; for a VRF
					// the device is the VRF master (Linux's VRF socket-binding
					// model), matching pkg/grpcapi's VRF-bind pattern. It is
					// family-agnostic, so it applies on every dial.
					if e := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev); e != nil {
						serr = e
						return
					}
				}
				if src.IsValid() && sourceMatchesDialFamily(src, network) {
					// Bind the source IP (ephemeral port). unix.Bind on the raw fd
					// before connect sets the socket's local address for both UDP
					// and TCP. Only reached when the source family matches the dial
					// socket's family, so the Sockaddr type can never mismatch the
					// socket (no EAFNOSUPPORT on a dual-stack lookup, #2901).
					var sa unix.Sockaddr
					if src.Is4() {
						sa = &unix.SockaddrInet4{Addr: src.As4()}
					} else {
						sa = &unix.SockaddrInet6{Addr: src.As16()}
					}
					if e := unix.Bind(int(fd), sa); e != nil {
						serr = e
						return
					}
				}
			}); err != nil {
				return err
			}
			return serr
		},
	}
}

// sourceMatchesDialFamily reports whether the source-address family is
// compatible with the dial socket's address family, as named by the
// Dialer.Control "network" argument ("tcp4"/"tcp6"/"udp4"/"udp6"). A "4" suffix
// is an AF_INET socket; a "6" suffix is an AF_INET6 socket. When the network
// carries no family suffix (e.g. a bare "tcp"/"udp" — the dial family is then
// chosen by the resolved address and not surfaced here) we cannot prove a
// mismatch, so we permit the bind and rely on the source family selecting the
// correct Sockaddr type (pre-#2901 behaviour for the no-hint case).
func sourceMatchesDialFamily(src netip.Addr, network string) bool {
	switch {
	case strings.HasSuffix(network, "4"):
		return src.Is4()
	case strings.HasSuffix(network, "6"):
		return src.Is6()
	default:
		return true
	}
}
