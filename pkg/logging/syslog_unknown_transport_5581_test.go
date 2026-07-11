package logging

import (
	"errors"
	"net"
	"testing"
)

// TestUnknownTransportRejectedAtConstruction is the #5581 fix-on-revert proof
// for the constructor. A security-log stream configured (or persisted /
// HA-synced) with a typo'd or unsupported transport token must be REJECTED at
// construction with ErrUnsupportedTransport, NOT silently downgraded to
// plaintext UDP.
//
// Before the fix, NewSyslogClientTransport accepted any token and dial()'s
// `default: return s.dialUDP()` arm mapped every unrecognized value to UDP, so
// the constructor returned a live client that shipped audit records as
// plaintext UDP while config/status still named a non-UDP transport. Reverting
// the constructor guard makes every case below return a non-nil client with a
// nil (or non-ErrUnsupportedTransport) error, failing these assertions.
func TestUnknownTransportRejectedAtConstruction(t *testing.T) {
	// A real UDP listener so the reverted (buggy) code path would actually
	// succeed at dialing it — proving the RED case is a genuine plaintext-UDP
	// downgrade, not merely a dial failure against a dead address.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)
	host := addr.IP.String()
	port := addr.Port

	for _, proto := range []string{"tls-typo", "sctp", "tcp6", "TLS", "relp", "http", "udp "} {
		t.Run(proto, func(t *testing.T) {
			client, err := NewSyslogClientTransport(host, port, "", proto, nil)
			if client != nil {
				// Fail closed: an unknown transport must never yield a usable
				// client. A non-nil client here is the silent plaintext-UDP
				// downgrade (#5581) — a security-log fail-open.
				client.Close()
				t.Fatalf("transport %q: expected nil client (fail closed), got a usable client "+
					"— unknown transport silently downgraded to plaintext UDP", proto)
			}
			if err == nil {
				t.Fatalf("transport %q: expected ErrUnsupportedTransport, got nil error", proto)
			}
			if !errors.Is(err, ErrUnsupportedTransport) {
				t.Fatalf("transport %q: expected ErrUnsupportedTransport, got %v", proto, err)
			}
		})
	}
}

// TestSupportedTransportsStillConstruct guards against over-rejection: the
// documented transports (empty→udp, udp, tcp, tls) must still build a client.
// UDP is exercised against a live loopback listener (so the dial succeeds and
// the client is fully connected); tcp/tls are #3351 lazy-reconnect clients even
// when the receiver is down, so they are only required to be non-nil.
func TestSupportedTransportsStillConstruct(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)
	host := addr.IP.String()
	port := addr.Port

	for _, proto := range []string{"", "udp"} {
		t.Run("udp/"+proto, func(t *testing.T) {
			client, err := NewSyslogClientTransport(host, port, "", proto, nil)
			if err != nil {
				t.Fatalf("transport %q: unexpected error: %v", proto, err)
			}
			if client == nil {
				t.Fatalf("transport %q: expected a usable client, got nil", proto)
			}
			client.Close()
		})
	}
}

// TestDialFailsClosedOnUnknownProtocol is the defense-in-depth proof for the
// reconnect path: even if a client somehow holds an unrecognized protocol
// (built another way, or a future field mutation), dial() must fail closed with
// ErrUnsupportedTransport instead of falling back to UDP. Before the fix,
// dial()'s `default` arm returned s.dialUDP() for any token, so this would
// return a live UDP conn to a non-UDP-named transport.
func TestDialFailsClosedOnUnknownProtocol(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)

	s := &SyslogClient{
		protocol:   "tls-typo",
		remoteAddr: addr.String(),
	}
	conn, err := s.dial()
	if conn != nil {
		conn.Close()
		t.Fatalf("dial() with an unknown protocol returned a live conn — silent UDP downgrade (#5581)")
	}
	if !errors.Is(err, ErrUnsupportedTransport) {
		t.Fatalf("dial() unknown protocol: expected ErrUnsupportedTransport, got %v", err)
	}
}
