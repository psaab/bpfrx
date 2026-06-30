package logging

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// freeRefusedAddr binds a loopback TCP listener to grab a free port, then closes
// it so a subsequent dial to that host:port is refused immediately. This keeps
// the dial failure local and deterministic — no external network, no DNS, no
// timeout wait (connection-refused on loopback is instant).
func freeRefusedAddr(t *testing.T) (host string, port int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	a := l.Addr().(*net.TCPAddr)
	host = a.IP.String()
	port = a.Port
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return host, port
}

// TestNewStreamClientLazyOnDialFailure is the #3351 fix-on-revert proof for the
// constructor: a TCP (and TLS) receiver that is down at construction must NOT
// drop the stream. The constructor returns a usable, unconnected client (conn
// nil, cooldown armed) PLUS the dial error so the caller can log it. Reverting
// the fix makes NewSyslogClientTransport return (nil, err) for TCP/TLS, so the
// `client == nil` assertions below fail.
func TestNewStreamClientLazyOnDialFailure(t *testing.T) {
	host, port := freeRefusedAddr(t)

	for _, proto := range []string{"tcp", "tls"} {
		t.Run(proto, func(t *testing.T) {
			client, err := NewSyslogClientTransport(host, port, "", proto, nil)
			if err == nil {
				t.Fatalf("%s: expected a dial error against a refused port, got nil", proto)
			}
			if client == nil {
				t.Fatalf("%s: receiver down at apply must yield a reconnecting client, "+
					"got nil (stream permanently disabled — #3351)", proto)
			}
			if client.conn != nil {
				t.Errorf("%s: lazy client must have no connection yet, conn != nil", proto)
			}
			// Cooldown must be armed so the first reconnect honours the window
			// instead of dialing under s.mu on the very next event.
			if client.lastReconnectFailure.IsZero() {
				t.Errorf("%s: lazy client must arm the reconnect cooldown", proto)
			}
		})
	}
}

// TestNewUDPClientStillFailsOnDialError pins the UDP contract: UDP has no live
// peer to connect to, so a UDP dial failure remains an unrecoverable
// construction error returning (nil, err) — the lazy/reconnecting behavior is
// TCP/TLS-only. An unresolvable host forces the UDP dial to fail.
func TestNewUDPClientStillFailsOnDialError(t *testing.T) {
	client, err := NewSyslogClientTransport("no-such-host.invalid.", 514, "", "udp", nil)
	if err == nil {
		t.Skip("udp dial to an unresolvable host unexpectedly succeeded (resolver quirk)")
	}
	if client != nil {
		t.Fatalf("UDP dial failure must return a nil client (lazy connect is TCP/TLS-only), got non-nil")
	}
}

// TestLazyStreamReconnectsAndDelivers is the behavioral #3351 proof: a stream
// installed in the reconnecting state (no conn yet, cooldown armed at boot)
// delivers once the receiver returns. The first Send fast-drops on the cooldown
// (no dial); after the cooldown window elapses, the next Send reconnects and the
// message lands on the freshly-dialed conn. Reverting the lazy-connect /
// reconnect-from-nil-conn behavior leaves the stream permanently dead, so the
// delivered-write assertion fails.
func TestLazyStreamReconnectsAndDelivers(t *testing.T) {
	var nowMu sync.Mutex
	now := time.Unix(0, 0)
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		now = now.Add(d)
		nowMu.Unlock()
	}

	var dialCount int32
	server := &recordingConn{}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.51:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: time.Second,
		nowFn:             clock,
		// Lazy state exactly as NewSyslogClientTransport leaves it when the
		// receiver is down at apply: no connection, cooldown armed at t=0.
		conn:                 nil,
		lastReconnectFailure: clock(),
		dialFn: func() (net.Conn, error) {
			atomic.AddInt32(&dialCount, 1)
			return server, nil // receiver is back: dial succeeds
		},
	}

	// First event at t=0: inside the cooldown window → fast-drop, no dial, no
	// delivery. The stream is not yet connected but is NOT permanently dead.
	if err := c.Send(SyslogInfo, "while receiver down"); err == nil {
		t.Fatal("expected the first send to drop while the receiver is down")
	}
	if d := atomic.LoadInt32(&dialCount); d != 0 {
		t.Fatalf("first send must fast-drop on cooldown, not dial; got %d dials", d)
	}
	if w := atomic.LoadInt32(&server.writes); w != 0 {
		t.Fatalf("nothing should be delivered while down, got %d writes", w)
	}
	if c.DroppedCooldown() == 0 {
		t.Error("expected a cooldown drop to be counted")
	}

	// Receiver returns; advance past the cooldown. The next event must reconnect
	// and deliver — proving the stream recovers rather than staying disabled.
	advance(time.Second + time.Millisecond)
	if err := c.Send(SyslogInfo, "after receiver returns"); err != nil {
		t.Fatalf("send after recovery must succeed, got %v", err)
	}
	if d := atomic.LoadInt32(&dialCount); d != 1 {
		t.Fatalf("expected exactly one reconnect dial after recovery, got %d", d)
	}
	if w := atomic.LoadInt32(&server.writes); w != 1 {
		t.Fatalf("expected the recovered stream to deliver the message, got %d writes", w)
	}
	// A fully successful reconnect clears the cooldown clock.
	if !c.lastReconnectFailure.IsZero() {
		t.Error("a fully recovered reconnect must clear the cooldown clock")
	}
}

// TestLazyStreamBinaryReconnectsAndDelivers mirrors the above for SendBinary
// (the RT_FLOW binary path), which shares the reconnect-from-nil-conn logic.
func TestLazyStreamBinaryReconnectsAndDelivers(t *testing.T) {
	var nowMu sync.Mutex
	now := time.Unix(0, 0)
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}

	server := &recordingConn{}
	dialErr := errors.New("still refused")
	var down atomic.Bool
	down.Store(true)
	c := &SyslogClient{
		hostname:             "test",
		remoteAddr:           "203.0.113.52:514",
		protocol:             "tls",
		Facility:             FacilityLocal0,
		writeTimeout:         defaultWriteTimeout,
		reconnectCooldown:    time.Second,
		nowFn:                clock,
		conn:                 nil,
		lastReconnectFailure: clock(),
		dialFn: func() (net.Conn, error) {
			if down.Load() {
				return nil, dialErr
			}
			return server, nil
		},
	}

	// Move past the cooldown while still down: dial is attempted but fails, so
	// the message drops and the stream stays unconnected (not permanently dead).
	nowMu.Lock()
	now = now.Add(time.Second + time.Millisecond)
	nowMu.Unlock()
	if err := c.SendBinary([]byte("binary-while-down")); err == nil {
		t.Fatal("expected SendBinary to fail while the receiver is down")
	}
	if w := atomic.LoadInt32(&server.writes); w != 0 {
		t.Fatalf("nothing should be delivered while down, got %d writes", w)
	}

	// Receiver returns; advance past the cooldown again and re-send.
	down.Store(false)
	nowMu.Lock()
	now = now.Add(time.Second + time.Millisecond)
	nowMu.Unlock()
	if err := c.SendBinary([]byte("binary-after-return")); err != nil {
		t.Fatalf("SendBinary after recovery must succeed, got %v", err)
	}
	if w := atomic.LoadInt32(&server.writes); w != 1 {
		t.Fatalf("expected the recovered binary stream to deliver, got %d writes", w)
	}
}
