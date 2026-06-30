package logging

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// closeCountConn counts Close calls; no real network (#3579).
type closeCountConn struct {
	closes atomic.Int32
}

func (c *closeCountConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c *closeCountConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *closeCountConn) Close() error                       { c.closes.Add(1); return nil }
func (c *closeCountConn) LocalAddr() net.Addr                { return ccAddr{} }
func (c *closeCountConn) RemoteAddr() net.Addr               { return ccAddr{} }
func (c *closeCountConn) SetDeadline(_ time.Time) error      { return nil }
func (c *closeCountConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *closeCountConn) SetWriteDeadline(_ time.Time) error { return nil }

type ccAddr struct{}

func (ccAddr) Network() string { return "fake" }
func (ccAddr) String() string  { return "fake" }

func clientWithConn(c net.Conn) *SyslogClient {
	return &SyslogClient{protocol: "tcp", conn: c, Facility: FacilityLocal0}
}

// TestReplaceSyslogClientsClosesOldSetExactlyOnce locks the contract the daemon
// #3579 fix relies on: ReplaceSyslogClients installs the new set AND closes
// every client in the superseded old set exactly once (no leak, no
// double-close). The control immediately below proves SetSyslogClients does NOT
// close — that is the non-closing behavior the daemon used to call and the bug
// the fix removes.
func TestReplaceSyslogClientsClosesOldSetExactlyOnce(t *testing.T) {
	er := NewEventReader(nil, nil)

	o1 := &closeCountConn{}
	o2 := &closeCountConn{}
	er.SetSyslogClients([]*SyslogClient{clientWithConn(o1), clientWithConn(o2)})

	// New set is freshly-built (distinct objects) — the supersede case the
	// daemon always hits.
	n1 := &closeCountConn{}
	er.ReplaceSyslogClients([]*SyslogClient{clientWithConn(n1)})

	if got := o1.closes.Load(); got != 1 {
		t.Fatalf("old client #1 must be Closed exactly once, got %d", got)
	}
	if got := o2.closes.Load(); got != 1 {
		t.Fatalf("old client #2 must be Closed exactly once, got %d", got)
	}
	if got := n1.closes.Load(); got != 0 {
		t.Fatalf("newly-installed client must NOT be closed, got %d", got)
	}
	if got := er.SyslogClientCount(); got != 1 {
		t.Fatalf("expected 1 installed client after replace, got %d", got)
	}
}

// TestSetSyslogClientsDoesNotCloseOldSet is the contrast that pins down WHY the
// daemon had to switch to ReplaceSyslogClients: SetSyslogClients swaps the
// slice without closing the superseded clients, leaking their connections.
func TestSetSyslogClientsDoesNotCloseOldSet(t *testing.T) {
	er := NewEventReader(nil, nil)
	old := &closeCountConn{}
	er.SetSyslogClients([]*SyslogClient{clientWithConn(old)})

	er.SetSyslogClients([]*SyslogClient{clientWithConn(&closeCountConn{})})

	if got := old.closes.Load(); got != 0 {
		t.Fatalf("SetSyslogClients must not close the superseded client "+
			"(documents the #3579 leak); got %d", got)
	}
}
