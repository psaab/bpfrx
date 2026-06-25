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
	"github.com/psaab/xpf/pkg/routing"
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

// applyVRFBind applies the per-test VRF/path pin to a raw socket fd:
// SO_BINDTODEVICE for the egress device and SO_MARK for the probe
// fwmark. It is the single source of truth for the bind so the probe
// DATA socket (realICMPListen / probeDialer) and the hostname-resolution
// DNS socket (resolveProbeTarget's bound resolver, #2614) pin to exactly
// the same scope — a hostname target in a VRF therefore resolves through
// the VRF's DNS instead of the process-default table. A zero device and
// zero mark is a no-op (default-context probe, unchanged).
func applyVRFBind(fd int, device string, mark uint32) error {
	if device != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET,
			unix.SO_BINDTODEVICE, device); err != nil {
			return err
		}
	}
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET,
			unix.SO_MARK, int(mark)); err != nil {
			return err
		}
	}
	return nil
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
				cerr = applyVRFBind(int(fd), opts.BindDevice, opts.Mark)
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
	dstAddr, err := resolve(ctx, test.Target, opts)
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
	// the zone to the egress device derived from destination-interface
	// (the same routing.ResolveProbeInterface mapping probeOpts uses for
	// SO_BINDTODEVICE — RETH → physical member, slashes → dashes). NOTE:
	// we deliberately do NOT fall back to opts.BindDevice here — that can
	// hold the routing-instance VRF device ("vrf-<ri>") from probeOpts,
	// which is NOT an egress link for fe80:: . A routing-instance-only
	// link-local (no destination-interface, no %zone) is rejected by the
	// strict commit gate (validateRPMLinkLocalZoneStrict), but can still
	// reach here on the lenient load / peer-sync path; defaulting it to
	// "vrf-<ri>" would let it SEND (counted as path loss) instead of
	// HOLDING state, breaking the #1960 hold-state doctrine. Only a real
	// destination-interface satisfies the link-local scope; with neither
	// we fail closed with ErrProbeSetup so the test HOLDS.
	if isV6 && dst.IsLinkLocalUnicast() {
		if zone != "" {
			zone = config.LinuxIfName(zone)
		} else {
			m.mu.RLock()
			rethMap := m.rethMap
			m.mu.RUnlock()
			zone = routing.ResolveProbeInterface(test.DestinationInterface, rethMap)
		}
		if zone == "" {
			return 0, fmt.Errorf("%w: icmp link-local target %s needs a zone "+
				"(%%zone or destination-interface; a routing-instance VRF is not an egress link)",
				ErrProbeSetup, dst)
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
// preserving the IPv6 link-local zone (#2494) and resolving a hostname
// IN THE PROBE'S VRF/path SCOPE (#2614).
//
// A plain IP literal short-circuits ParseIP (no DNS, no zone). A zoned
// literal (`fe80::1%ge-0-0-3`) is rejected by net.ParseIP, so it falls
// through to the resolver, which parses the scope id into IPAddr.Zone —
// the zone must survive to the send path so a link-local echo is steered
// to the right link.
//
// A hostname is resolved through a net.Resolver. When the test carries a
// scope (opts.BindDevice / opts.Mark — set for routing-instance /
// destination-interface / next-hop tests), the resolver uses PreferGo
// (the pure-Go DNS client) with a Dial whose Control applies the SAME
// applyVRFBind (SO_BINDTODEVICE + SO_MARK) the probe DATA socket uses, so
// the DNS query egresses the probe's VRF and hits the VRF's DNS servers
// instead of the process-default table. Without this, a hostname target
// inside an isolated VRF resolved through the main table / default DNS —
// wrong address, or a resolution failure when DNS is reachable only
// inside the VRF (#2614). An unscoped test (no device, no mark) uses the
// default resolver, bit-identical to the pre-#2614 net.ResolveIPAddr
// path.
//
// The lookup runs under the probe-cycle ctx (#2647) so a stuck DNS query
// for a hostname target honors the cycle's cancellation/deadline (config
// reload, service stop) instead of escaping it via context.Background() —
// matching the ctx-bound TCP/HTTP probe paths. A literal-IP target
// returns before the lookup, so ctx never gates it. The ctx flows into
// the (possibly VRF-bound, #2614) resolver's LookupIPAddr, and into the
// bound resolver's Dial via the standard net.Resolver plumbing.
// lookupIPAddr is the DNS-lookup seam used by resolveProbeTarget. Production
// calls the (possibly VRF-bound, #2614) resolver's LookupIPAddr, threading the
// probe-cycle ctx (#2647). It is a package var so a unit test can substitute a
// resolver whose Dial genuinely blocks until ctx is done — the fail-on-revert
// gate for the ctx threading (a hostname lookup honors cancellation instead of
// hanging under context.Background()).
var lookupIPAddr = func(ctx context.Context, r *net.Resolver, target string) ([]net.IPAddr, error) {
	return r.LookupIPAddr(ctx, target)
}

func resolveProbeTarget(ctx context.Context, target string, opts probeSockOpts) (*net.IPAddr, error) {
	if target == "" {
		return nil, fmt.Errorf("no target specified")
	}
	if ip := net.ParseIP(target); ip != nil {
		return &net.IPAddr{IP: ip}, nil
	}
	ips, err := lookupIPAddr(ctx, resolverForOpts(opts), target)
	if err != nil {
		return nil, fmt.Errorf("resolve target %q: %w", target, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve target %q: no addresses", target)
	}
	// Preserve net.ResolveIPAddr("ip", ...) semantics: first address,
	// carrying any IPv6 zone the resolver populated.
	return &net.IPAddr{IP: ips[0].IP, Zone: ips[0].Zone}, nil
}

// resolverForOpts selects the DNS resolver for a probe (#2614): the
// default resolver for an unscoped probe (no device, no mark —
// bit-identical to the pre-#2614 process-default lookup), or a
// VRF/path-bound resolver when the probe carries a scope. Split out so a
// unit test can assert the scoped probe gets a bound resolver and the
// unscoped probe gets the default — the live VRF DNS query is lab-bound,
// so this selection is the gate.
func resolverForOpts(opts probeSockOpts) *net.Resolver {
	if opts.BindDevice != "" || opts.Mark != 0 {
		return vrfBoundResolver(opts)
	}
	return net.DefaultResolver
}

// vrfBoundResolver builds a net.Resolver that issues DNS queries from a
// socket pinned to the probe's VRF/path scope (#2614). PreferGo selects
// the pure-Go DNS client so the Dial hook is honored (the cgo resolver
// path ignores it); the Dialer's Control applies the same applyVRFBind
// (SO_BINDTODEVICE / SO_MARK) as the probe DATA socket, so the query
// leaves the VRF and resolves against the VRF's DNS.
func vrfBoundResolver(opts probeSockOpts) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Control: func(_, _ string, c syscall.RawConn) error {
					var cerr error
					err := c.Control(func(fd uintptr) {
						cerr = applyVRFBind(int(fd), opts.BindDevice, opts.Mark)
					})
					if err != nil {
						return err
					}
					return cerr
				},
			}
			return d.DialContext(ctx, network, address)
		},
	}
}
