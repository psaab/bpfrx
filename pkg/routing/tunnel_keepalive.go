package routing

import (
	"crypto/rand"
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ProbeResult is the typed outcome of a single tunnel keepalive probe
// (#1918, Axis B1). It carries the "could not probe" signal the old
// bool return destroyed: a route-existence check is NOT a liveness
// check, and the loop must distinguish "confirmed dead" from "unable to
// probe" so it can hold-on-unknown instead of defaulting to up.
type ProbeResult int

const (
	// ProbeAlive: an ICMP echo reply matching THIS probe (Seq + nonce)
	// was received within the deadline.
	ProbeAlive ProbeResult = iota
	// ProbeDead: the echo was sent but no matching reply arrived before
	// the deadline. This is a real liveness signal and counts toward
	// MaxRetries.
	ProbeDead
	// ProbeUnsupported: the probe could not be performed at all (socket
	// could not be opened/bound, marshal failure, etc.). The loop applies
	// hold-on-unknown (§6 Axis C, C1) — it never tears the link down
	// purely because the daemon cannot probe.
	ProbeUnsupported
)

// UnsupportedKind sub-classifies a ProbeUnsupported result (#1918 Axis
// C). Structural = a configuration/capability problem (missing
// ping_group_range, bound source not local) that holds indefinitely
// with a one-shot warning. Transient = a local resource problem
// (FD/memory exhaustion) that holds but escalates to a loud status +
// slog.Error after a sustained window so a real peer death is never
// silently masked by a local resource storm.
type UnsupportedKind int

const (
	// UnsupportedNone is the zero value used when the result is not
	// ProbeUnsupported.
	UnsupportedNone UnsupportedKind = iota
	// UnsupportedStructural: config/capability error — hold indefinitely,
	// one-shot Warn.
	UnsupportedStructural
	// UnsupportedTransient: local resource error — hold but escalate after
	// a sustained-unknown window.
	UnsupportedTransient
)

// tunnelProber performs one ICMP echo round-trip to a tunnel's underlay
// peer. The production implementation is icmpProber; tests inject a
// deterministic fake on tunnelManager.prober.
//
// source is the tunnel's local endpoint IP (TunnelConfig.Source) bound
// as the ICMP listen address (§5c) so the echo egresses from the tunnel
// endpoint; "" → wildcard bind. dst is the underlay Destination, routed
// in the GLOBAL/underlay FIB exactly like the tunnel's encapsulated
// traffic (§5b — NO overlay-VRF bind). seq + nonce uniquely key the
// reply to THIS probe (§5a — NOT the ICMP ID, which datagram sockets
// rewrite to the socket source port).
type tunnelProber interface {
	Probe(source, dst string, seq int, nonce []byte, deadline time.Duration) (ProbeResult, UnsupportedKind)
}

// icmpProber is the production tunnelProber. It uses unprivileged
// datagram ICMP ("udp4"/"udp6" via x/net/icmp), the same mechanism as
// the tested pkg/cluster/monitor.go precedent, with the precedent's two
// gaps fixed: reply matching on Seq + Data-nonce (§5a) and binding to
// the tunnel source IP (§5c). No SO_BINDTODEVICE — the probe routes in
// the global/underlay table (§5b).
type icmpProber struct{}

// probeConn is the narrow ICMP socket surface icmpProber needs, so tests
// can substitute a fake without real network I/O. Mirrors
// pkg/cluster/monitor.go's icmpConn.
type probeConn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// listenICMP opens a datagram ICMP socket bound to source (or wildcard
// when source==""). Indirection point for tests of the production
// prober.
var listenICMP = func(network, source string) (probeConn, error) {
	c, err := icmp.ListenPacket(network, source)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Probe sends one ICMP echo to dst and reports the typed result.
func (icmpProber) Probe(source, dst string, seq int, nonce []byte, deadline time.Duration) (ProbeResult, UnsupportedKind) {
	ip := net.ParseIP(dst)
	if ip == nil {
		// A non-parseable destination is a configuration error, not a
		// transient resource problem: hold-on-unknown structural.
		return ProbeUnsupported, UnsupportedStructural
	}

	isIPv6 := ip.To4() == nil
	var (
		network   string
		echoType  icmp.Type
		replyType icmp.Type
		proto     int
		listen    string
	)
	if isIPv6 {
		network, echoType, replyType, proto = "udp6", ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, 58
		listen = "::"
	} else {
		network, echoType, replyType, proto = "udp4", ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, 1
		listen = "0.0.0.0"
	}
	// §5c: bind to the tunnel source IP so the echo egresses from the
	// tunnel endpoint and the reply routes back to it. Empty source →
	// wildcard (auto-selected tunnels). A family-mismatched source (e.g.
	// a v4 Source against a v6 dst) would EAFNOSUPPORT/EADDRNOTAVAIL on
	// ListenPacket → classified structural below; that is correct (a
	// misconfigured source pair cannot probe).
	if source != "" {
		listen = source
	}

	conn, err := listenICMP(network, listen)
	if err != nil {
		return ProbeUnsupported, classifyListenErr(err)
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			// ID is advisory only: datagram sockets overwrite it with the
			// socket source port (§5a). The authoritative match is Seq +
			// Data-nonce.
			ID:   0,
			Seq:  seq,
			Data: nonce,
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		// Marshal of a fixed-shape echo should never fail; treat a failure
		// as a structural (non-flapping) unknown.
		return ProbeUnsupported, UnsupportedStructural
	}

	abs := time.Now().Add(deadline)
	if err := conn.SetReadDeadline(abs); err != nil {
		return ProbeUnsupported, classifyListenErr(err)
	}
	if _, err := conn.WriteTo(b, &net.UDPAddr{IP: ip}); err != nil {
		// A write error after a successful socket open is most plausibly a
		// path/route problem (ENETUNREACH/EHOSTUNREACH/no route): that IS a
		// liveness signal, so report Dead rather than Unsupported. Resource
		// errnos on write are rare; bucketing them Dead at worst costs one
		// retry, never a silent forever-hold.
		return ProbeDead, UnsupportedNone
	}

	reply := make([]byte, 1500)
	for {
		// R4: re-check the absolute deadline each iteration so a datagram
		// flood cannot extend a probe past its budget.
		if remaining := time.Until(abs); remaining <= 0 {
			return ProbeDead, UnsupportedNone
		}
		n, _, err := conn.ReadFrom(reply)
		if err != nil {
			// Deadline exceeded or read error → no matching reply → Dead.
			return ProbeDead, UnsupportedNone
		}
		parsed, perr := icmp.ParseMessage(proto, reply[:n])
		if perr != nil || parsed.Type != replyType {
			continue // not an echo reply we recognize; keep reading
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		// §5a authoritative match: Seq AND Data-nonce. ID is ignored
		// (kernel-substituted on datagram sockets).
		if echo.Seq == seq && bytesEqual(echo.Data, nonce) {
			return ProbeAlive, UnsupportedNone
		}
		// A stale/foreign reply (different probe) — keep reading until the
		// deadline.
	}
}

// bytesEqual is a small constant-shape comparison (the nonce is ~8
// bytes); avoids importing bytes for one call.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// classifyListenErr buckets a ListenPacket/socket errno into structural
// (config/capability — hold indefinitely, one-shot Warn) vs transient
// (local resource — hold but escalate after the sustained-unknown
// window). The default for any UNRECOGNIZED errno is TRANSIENT (§6 Axis
// C, Codex r2 NF4): a resource storm must never be silently mis-bucketed
// as a held structural.
func classifyListenErr(err error) UnsupportedKind {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		// Non-errno error (e.g. a parse/address-format error from the
		// library before the syscall) → treat as a config problem.
		return UnsupportedStructural
	}
	switch errno {
	case syscall.EPERM, syscall.EACCES,
		syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT,
		syscall.EPROTOTYPE, syscall.EADDRNOTAVAIL:
		// Capability / configuration: no ping_group_range or cap, wrong
		// family, or the bound tc.Source is not a local address.
		return UnsupportedStructural
	case syscall.EMFILE, syscall.ENFILE,
		syscall.ENOBUFS, syscall.ENOMEM, syscall.EINTR:
		return UnsupportedTransient
	default:
		// Total default — UNRECOGNIZED → TRANSIENT (escalate).
		return UnsupportedTransient
	}
}

// makeNonce returns a fresh per-probe random nonce (§5a). 8 bytes is
// small enough that responders echo it faithfully (R3) yet wide enough
// to make a cross-probe collision negligible.
func makeNonce() []byte {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is effectively impossible on Linux; fall back
		// to a fixed marker so the probe still has a stable Data field.
		copy(b, []byte("xpf-ka00"))
	}
	return b
}
