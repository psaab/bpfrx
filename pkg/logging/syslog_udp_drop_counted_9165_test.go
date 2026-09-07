package logging

import (
	"errors"
	"net"
	"testing"
	"time"
)

// #9165: UDP is the DEFAULT syslog transport, and a UDP write failure was
// neither counted nor warned. On a box whose collector is down, `droppedWrites`
// stayed 0 and the rate-limited "syslog message dropped" warning never fired —
// while the same box on TCP reported both. Every instrument read healthy at
// once: no counter movement, no warning, and a `show` still rendering the
// configured collector as present.
//
// #9025 had counted the UDP DEADLINE EXPIRY it introduced, which is why this
// looked covered. That is one failure mode; the one an operator actually hits
// is a dead collector, and on a CONNECTED datagram socket Linux reports that as
// ECONNREFUSED, not as a timeout.

// udpClientTo builds a real UDP SyslogClient pointed at addr.
func udpClientTo(t *testing.T, addr string) *SyslogClient {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial udp %s: %v", addr, err)
	}
	c := &SyslogClient{
		hostname:     "test",
		remoteAddr:   addr,
		protocol:     "udp",
		Facility:     FacilityLocal0,
		writeTimeout: defaultWriteTimeout,
		conn:         conn,
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// closedCollectorAddr returns the address of a UDP port that WAS bound and is
// now closed — a dead collector, reproduced exactly.
func closedCollectorAddr(t *testing.T) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.LocalAddr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// THE DEFECT, on a real socket: a dead collector on the default transport must
// move the drop counter.
func TestUDPDeadCollectorAdvancesTheDropCounter9165(t *testing.T) {
	c := udpClientTo(t, closedCollectorAddr(t))

	// A connected UDP socket learns the port is dead from the ICMP
	// port-unreachable the FIRST datagram provokes, so the refusal surfaces on
	// a subsequent write. Bounded, so a platform that never reports it fails
	// the cell rather than hanging it.
	deadline := time.Now().Add(3 * time.Second)
	for c.DroppedWrites() == 0 && time.Now().Before(deadline) {
		_ = c.Send(6, "collector is gone")
		time.Sleep(2 * time.Millisecond)
	}

	if c.DroppedWrites() == 0 {
		t.Fatalf("a dead collector on the DEFAULT transport moved no counter: "+
			"writes=%d dials=%d cooldown=%d. Every syslog message is going "+
			"nowhere and no instrument says so (#9165)",
			c.DroppedWrites(), c.DroppedDials(), c.DroppedCooldown())
	}
	// A datagram socket has no connection to re-establish, so the reconnect
	// counters must stay still — the fix must not have grown a stream arm.
	if c.DroppedDials() != 0 || c.DroppedCooldown() != 0 {
		t.Errorf("UDP took a reconnect path it has no connection for: dials=%d cooldown=%d",
			c.DroppedDials(), c.DroppedCooldown())
	}
}

// CONTROL — a LIVE collector must move NOTHING. Without this row, "count every
// write" is satisfied by a client that reports a drop on every message, which
// would make the counter useless and fire the warning continuously.
func TestUDPLiveCollectorDropsNothing9165(t *testing.T) {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	c := udpClientTo(t, l.LocalAddr().String())
	for i := 0; i < 50; i++ {
		if err := c.Send(6, "collector is up"); err != nil {
			t.Fatalf("send %d to a live collector failed: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Prove the control is not vacuous: the datagrams really arrived. A
	// send that silently went nowhere would satisfy the counter assertion
	// below just as well.
	_ = l.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	if _, _, err := l.ReadFrom(buf); err != nil {
		t.Fatalf("the live collector received nothing, so this control is not "+
			"measuring a healthy path: %v", err)
	}
	if c.DroppedWrites() != 0 || c.DroppedDials() != 0 || c.DroppedCooldown() != 0 {
		t.Errorf("a HEALTHY collector recorded drops: writes=%d dials=%d cooldown=%d",
			c.DroppedWrites(), c.DroppedDials(), c.DroppedCooldown())
	}
}

// errConn fails every write with a non-timeout error, the shape a dead peer
// produces on any transport.
type errConn9165 struct{ net.Conn }

func (errConn9165) Write([]byte) (int, error) { return 0, errors.New("connection refused") }
func (errConn9165) Close() error              { return nil }
func (errConn9165) SetWriteDeadline(time.Time) error {
	return nil
}

// A cell PER TRANSPORT, as the issue asked. The asymmetry was the whole defect:
// tcp and tls reported a failed write and udp did not, so a table that omits
// udp — or that tests only udp — cannot see it.
func TestEveryTransportCountsAWriteFailure9165(t *testing.T) {
	for _, proto := range []string{"udp", "tcp", "tls"} {
		t.Run(proto, func(t *testing.T) {
			c := &SyslogClient{
				hostname:          "test",
				remoteAddr:        "203.0.113.1:514",
				protocol:          proto,
				Facility:          FacilityLocal0,
				writeTimeout:      defaultWriteTimeout,
				reconnectCooldown: defaultReconnectCooldown,
				conn:              errConn9165{},
				// The stream arm reconnects on a non-timeout error; a dead
				// collector refuses that dial too.
				dialFn: func() (net.Conn, error) { return nil, errors.New("connection refused") },
			}
			if err := c.Send(6, "hello"); err == nil {
				t.Fatal("a failing write returned no error")
			}
			total := c.DroppedWrites() + c.DroppedDials() + c.DroppedCooldown()
			if total == 0 {
				t.Fatalf("%s: a failed write moved no drop counter (writes=%d dials=%d cooldown=%d)",
					proto, c.DroppedWrites(), c.DroppedDials(), c.DroppedCooldown())
			}
			// udp must land specifically on the WRITE counter — it has no
			// dial or cooldown to attribute a drop to, and attributing one
			// there would misreport the failure.
			if proto == "udp" && c.DroppedWrites() == 0 {
				t.Errorf("udp counted a drop somewhere other than writes: dials=%d cooldown=%d",
					c.DroppedDials(), c.DroppedCooldown())
			}
		})
	}
}

// SendBinary carries the RT_FLOW records — the security log — through a second
// copy of the same arm. Fixing only Send would leave the records an operator
// most needs uncounted.
func TestSendBinaryAlsoCountsAUDPWriteFailure9165(t *testing.T) {
	c := &SyslogClient{
		hostname:     "test",
		remoteAddr:   "203.0.113.1:514",
		protocol:     "udp",
		Facility:     FacilityLocal0,
		writeTimeout: defaultWriteTimeout,
		conn:         errConn9165{},
	}
	rec := make([]byte, 32)
	rec[3], rec[4] = 0, 32
	if err := c.SendBinary(rec); err == nil {
		t.Fatal("a failing binary write returned no error")
	}
	if c.DroppedWrites() == 0 {
		t.Fatal("SendBinary's UDP arm counted nothing — the security-log path " +
			"is still silent on a dead collector (#9165)")
	}
}

// THE SECOND HALF: a counter with no reader is the same as no counter. The
// EventReader snapshot is the seam the Prometheus family reads through, so it
// must report what the client counted.
func TestDropStatsSnapshotReportsWhatTheClientCounted9165(t *testing.T) {
	c := &SyslogClient{
		hostname:     "test",
		remoteAddr:   "203.0.113.9:514",
		protocol:     "udp",
		Facility:     FacilityLocal0,
		writeTimeout: defaultWriteTimeout,
		conn:         errConn9165{},
	}
	_ = c.Send(6 /* info */, "one")

	er := &EventReader{}
	er.SetSyslogClients([]*SyslogClient{c})

	stats := er.SyslogDropStats()
	if len(stats) != 1 {
		t.Fatalf("SyslogDropStats returned %d rows, want 1", len(stats))
	}
	got := stats[0]
	if got.RemoteAddr != "203.0.113.9:514" || got.Protocol != "udp" {
		t.Errorf("row identifies the wrong collector: %+v", got)
	}
	if got.Writes != c.DroppedWrites() {
		t.Errorf("snapshot Writes=%d, client DroppedWrites=%d", got.Writes, c.DroppedWrites())
	}
	if got.Writes == 0 {
		t.Error("the snapshot reports zero drops for a client that dropped a message")
	}
}

// A nil client in the set must not panic the scrape path: ReplaceSyslogClients
// is driven from commit, and a metrics scrape runs concurrently with it.
func TestDropStatsSkipsNilClients9165(t *testing.T) {
	er := &EventReader{}
	er.SetSyslogClients([]*SyslogClient{nil})
	if got := er.SyslogDropStats(); len(got) != 0 {
		t.Errorf("nil client produced %d rows, want 0", len(got))
	}
}
