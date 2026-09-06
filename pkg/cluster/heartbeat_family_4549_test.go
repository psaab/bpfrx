package cluster

import (
	"net"
	"testing"
)

// connIsIPv6 reports whether a bound UDP conn's local address is an IPv6
// (non-v4-mapped) socket. A v4 UDPConn has LocalAddr().IP.To4() != nil.
func connIsIPv6(t *testing.T, c *net.UDPConn) bool {
	t.Helper()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr is %T, want *net.UDPAddr", c.LocalAddr())
	}
	return ua.IP.To4() == nil
}

// TestHeartbeatUDPNetwork pins the family selection: a v6 literal maps to
// "udp6", a v4 literal to "udp4", and an unparseable value falls back to the
// historical "udp4" default.
func TestHeartbeatUDPNetwork(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"127.0.0.1", "udp4"},
		{"10.99.0.1", "udp4"},
		{"::1", "udp6"},
		{"fd00::1", "udp6"},
		{"2001:559:8585::8", "udp6"},
		{"", "udp4"},          // empty → historical default
		{"not-an-ip", "udp4"}, // unparseable → historical default
	}
	for _, c := range cases {
		if got := heartbeatUDPNetwork(c.addr); got != c.want {
			t.Errorf("heartbeatUDPNetwork(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// TestStartHeartbeatIPv6ControlLink pins the #4549 F9 fix: an IPv6 control-link
// address resolves and binds. The daemon can hand StartHeartbeat an IPv6 local
// + peer address (selectClusterBindAddr returns an IPv6 candidate when the
// configured peer is IPv6), so the sockets must follow the address family.
//
// On revert (StartHeartbeat hardcodes "udp4" + builds the address with the
// bare "%s:%d" format instead of net.JoinHostPort), this goes RED:
// net.ResolveUDPAddr("udp4", "::1:4784") fails with "too many colons in
// address" (no brackets, wrong family), so StartHeartbeat returns an error and
// never binds v6 sockets.
func TestStartHeartbeatIPv6ControlLink(t *testing.T) {
	m := NewManager(0, 1)
	defer m.StopHeartbeat()

	// SO_REUSEADDR+SO_REUSEPORT (vrfListenConfig) allows the loopback rebind.
	if err := m.StartHeartbeat("::1", "::1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat with IPv6 control link: %v", err)
	}

	m.mu.RLock()
	s := m.hbSender
	r := m.hbReceiver
	m.mu.RUnlock()
	if s == nil || r == nil {
		t.Fatal("StartHeartbeat installed nil sender/receiver for IPv6 control link")
	}

	if !connIsIPv6(t, r.conn) {
		t.Errorf("receiver conn LocalAddr = %v, want an IPv6-bound socket", r.conn.LocalAddr())
	}
	if !connIsIPv6(t, s.conn) {
		t.Errorf("sender conn LocalAddr = %v, want an IPv6-bound socket", s.conn.LocalAddr())
	}

	// The peer address the sender dials must also be IPv6.
	if s.peerAddr == nil || s.peerAddr.IP.To4() != nil {
		t.Errorf("sender peerAddr = %v, want an IPv6 peer", s.peerAddr)
	}
}

// TestStartHeartbeatIPv4ControlLinkUnchanged pins that the near-universal IPv4
// control link is bit-for-bit unchanged by the family-agnostic fix: a v4
// address still binds v4 sockets.
func TestStartHeartbeatIPv4ControlLinkUnchanged(t *testing.T) {
	m := NewManager(0, 1)
	defer m.StopHeartbeat()

	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat with IPv4 control link: %v", err)
	}

	m.mu.RLock()
	s := m.hbSender
	r := m.hbReceiver
	m.mu.RUnlock()
	if s == nil || r == nil {
		t.Fatal("StartHeartbeat installed nil sender/receiver for IPv4 control link")
	}

	if connIsIPv6(t, r.conn) {
		t.Errorf("receiver conn LocalAddr = %v, want an IPv4-bound socket", r.conn.LocalAddr())
	}
	if connIsIPv6(t, s.conn) {
		t.Errorf("sender conn LocalAddr = %v, want an IPv4-bound socket", s.conn.LocalAddr())
	}
}
