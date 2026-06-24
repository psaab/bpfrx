// icmp.go implements the real ICMP/ICMPv6 echo prober (#1827 PR-1a).
//
// The pre-#1827 icmp-ping probe never sent an echo: it raw-IP dialed the
// target (a local route-existence check) and fell back to a UDP
// connect() that also put no packet on the wire, so icmp-ping "always
// passed" while the path was dead. This file replaces it with a genuine
// ICMP echo request/reply exchange with id/seq matching and a per-probe
// timeout. xpfd runs as root, so raw ICMP sockets are available.
//
// The socket is opened through an injectable seam (icmpListenFunc) so
// unit tests can exercise the echo build/match/timeout logic without
// raw-socket privileges or network access.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	icmpProtocolIPv4 = 1  // iana.ProtocolICMP
	icmpProtocolIPv6 = 58 // iana.ProtocolIPv6ICMP

	// icmpProbeTimeout bounds a single echo exchange, matching the
	// pre-#1827 icmp-ping dial timeout.
	icmpProbeTimeout = 3 * time.Second
)

// probeSockOpts carries the per-test socket options shared by all three
// probe types: the egress device pin (SO_BINDTODEVICE — from
// destination-interface, falling back to the routing-instance VRF
// device) and the probe fwmark (SO_MARK — set for next-hop-pinned tests
// so the probe follows its reserved per-test routing table).
type probeSockOpts struct {
	BindDevice string
	Mark       uint32
}

// icmpListenFunc opens an ICMP packet socket. network is "ip4:icmp" or
// "ip6:ipv6-icmp"; laddr is the optional source address. Production
// uses realICMPListen (raw socket via net.ListenConfig with the socket
// options applied at fd level); tests substitute an in-memory fake.
type icmpListenFunc func(network, laddr string, opts probeSockOpts) (net.PacketConn, error)

// realICMPListen opens a raw ICMP socket with SO_BINDTODEVICE / SO_MARK
// applied before bind.
func realICMPListen(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var cerr error
			err := c.Control(func(fd uintptr) {
				if opts.BindDevice != "" {
					cerr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET,
						unix.SO_BINDTODEVICE, opts.BindDevice)
					if cerr != nil {
						return
					}
				}
				if opts.Mark != 0 {
					cerr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET,
						unix.SO_MARK, int(opts.Mark))
				}
			})
			if err != nil {
				return err
			}
			return cerr
		},
	}
	return lc.ListenPacket(context.Background(), network, laddr)
}

// echoIDCounter feeds per-exchange echo identifiers so concurrent tests
// on the same raw socket family never cross-match replies.
var echoIDCounter atomic.Uint32

// ErrProbeSetup marks ENVIRONMENT/capability failures — the probe
// never reached the wire (raw socket open denied, e.g. CAP_NET_RAW
// dropped; message marshal). These are NOT path-health signals: the
// probe loop holds the test's current state (no SuccFail counting, no
// status change, no events, no Transition callback), so ip-monitoring
// can never inject or withdraw preferred routes off a capability
// regression (AGY review on PR #1843, finding F2). A sustained setup
// failure surfaces via the rate-limited Warn log and the stalled
// LastProbeAt/TotalSent in `show services rpm`, never via route
// actuation. Send/receive/timeout errors stay genuine probe failures.
//
// Covers all three probe types: raw-socket open + marshal for
// icmp-ping (here), and probeDialer socket-control failures
// (SO_BINDTODEVICE / SO_MARK) for tcp-ping and http-get (Codex PR
// #1843 HIGH-2). Genuine dial outcomes — refused, timeout,
// unreachable — stay path signals; ambiguous dial errnos deliberately
// default to PATH (conservative for detection).
var ErrProbeSetup = errors.New("probe setup failed")

// probeICMP sends one ICMP (or ICMPv6) echo request to the test target
// and waits for the matching reply. Returns the measured RTT.
func (m *Manager) probeICMP(ctx context.Context, test *config.RPMTest, opts probeSockOpts) (time.Duration, error) {
	resolve := m.resolveTarget
	if resolve == nil {
		resolve = resolveProbeTarget
	}
	dstAddr, err := resolve(test.Target)
	if err != nil {
		return 0, err
	}
	dst := dstAddr.IP
	zone := dstAddr.Zone
	isV6 := dst.To4() == nil

	// #2494: an IPv6 link-local target must carry a scope (zone) or the
	// kernel cannot pick the egress link — the echo goes to the wrong
	// link or fails. Honor an explicit `%zone` from the target literal
	// (normalize Junos slash form to the kernel name); otherwise default
	// the zone to the resolved egress device the data socket binds via
	// SO_BINDTODEVICE (opts.BindDevice — already the kernel ifname). The
	// commit-time gate (validateRPMLinkLocalZoneStrict) rejects a bare
	// link-local with neither a zone nor a destination-interface, so by
	// the time a probe runs one of the two is present (or the test was
	// loaded leniently and HOLDS via the same missing-zone error below).
	if isV6 && dst.IsLinkLocalUnicast() {
		if zone != "" {
			zone = config.LinuxIfName(zone)
		} else {
			zone = opts.BindDevice
		}
		if zone == "" {
			return 0, fmt.Errorf("%w: icmp link-local target %s needs a zone "+
				"(%%zone or destination-interface)", ErrProbeSetup, dst)
		}
	}

	network := "ip4:icmp"
	proto := icmpProtocolIPv4
	var echoType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if isV6 {
		network = "ip6:ipv6-icmp"
		proto = icmpProtocolIPv6
		echoType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}

	listen := m.icmpListen
	if listen == nil {
		listen = realICMPListen
	}
	conn, err := listen(network, test.SourceAddress, opts)
	if err != nil {
		// Capability/environment failure — the echo never reached the
		// wire. Marked ErrProbeSetup so the probe loop holds state
		// instead of transitioning to FAILED (AGY PR #1843 F2).
		return 0, fmt.Errorf("%w: icmp socket: %v", ErrProbeSetup, err)
	}
	defer conn.Close()

	id := int(uint16(os.Getpid()) ^ uint16(echoIDCounter.Add(1)))
	const seq = 1
	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("xpf-rpm-probe")},
	}
	// Marshal computes the IPv4 ICMP checksum; for ICMPv6 the kernel
	// fills the checksum on raw IPPROTO_ICMPV6 sockets.
	wire, err := msg.Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("%w: icmp marshal: %v", ErrProbeSetup, err)
	}

	start := time.Now()
	// Carry the zone so a link-local destination is scoped to the right
	// egress link (#2494). For global addresses zone is "" and this is
	// the same &net.IPAddr{IP: dst} as before.
	if _, err := conn.WriteTo(wire, &net.IPAddr{IP: dst, Zone: zone}); err != nil {
		return 0, fmt.Errorf("icmp send: %w", err)
	}

	deadline := start.Add(icmpProbeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return 0, fmt.Errorf("icmp deadline: %w", err)
		}
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, fmt.Errorf("icmp echo to %s timed out: %w", dst, err)
		}
		// Raw ICMP sockets receive every ICMP message on the host:
		// match reply type, echo id/seq, and the probed peer address.
		parsed, perr := icmp.ParseMessage(proto, buf[:n])
		if perr != nil {
			continue
		}
		if parsed.Type != replyType {
			continue
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok || echo.ID != id || echo.Seq != seq {
			continue
		}
		// Reply-match compares the peer IP only, not the zone (#2494):
		// the kernel may or may not populate the reply's IPAddr.Zone, and
		// id/seq already disambiguate this exchange. The send-side zone is
		// the correctness fix (the echo leaves the right link); the
		// reply-match stays zone-agnostic by design.
		if peerIP, ok := peer.(*net.IPAddr); ok && !peerIP.IP.Equal(dst) {
			continue
		}
		return time.Since(start), nil
	}
}

// resolveProbeTarget parses or resolves the test target into an address,
// preserving the IPv6 link-local zone (#2494). net.ParseIP rejects a
// zoned literal (`fe80::1%ge-0-0-3`), so a zoned target falls through to
// net.ResolveIPAddr, which parses the scope id into IPAddr.Zone — the
// zone must survive to the send path so a link-local echo is steered to
// the right link. A plain IP literal short-circuits ParseIP (no DNS, no
// zone); a hostname resolves through net.ResolveIPAddr.
func resolveProbeTarget(target string) (*net.IPAddr, error) {
	if target == "" {
		return nil, fmt.Errorf("no target specified")
	}
	if ip := net.ParseIP(target); ip != nil {
		return &net.IPAddr{IP: ip}, nil
	}
	addr, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		return nil, fmt.Errorf("resolve target %q: %w", target, err)
	}
	return addr, nil
}
