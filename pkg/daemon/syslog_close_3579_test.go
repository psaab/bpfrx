package daemon

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// closeRecordingConn is a net.Conn fake whose only job is to count Close calls.
// It uses no real network so the daemon syslog-apply close path can be observed
// deterministically (#3579).
type closeRecordingConn struct {
	closes atomic.Int32
}

func (c *closeRecordingConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c *closeRecordingConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *closeRecordingConn) Close() error                       { c.closes.Add(1); return nil }
func (c *closeRecordingConn) LocalAddr() net.Addr                { return dummyCloseAddr{} }
func (c *closeRecordingConn) RemoteAddr() net.Addr               { return dummyCloseAddr{} }
func (c *closeRecordingConn) SetDeadline(_ time.Time) error      { return nil }
func (c *closeRecordingConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *closeRecordingConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *closeRecordingConn) Closes() int32 { return c.closes.Load() }

type dummyCloseAddr struct{}

func (dummyCloseAddr) Network() string { return "fake" }
func (dummyCloseAddr) String() string  { return "fake" }

// TestApplySyslogConfigClosesSupersededStreamClients is the RED-on-revert proof
// for #3579: applySyslogConfig rebuilds the syslog client set from config on
// every apply, so a re-apply that changes or drops a CONNECTED TCP/TLS stream
// fully supersedes the prior client set. The daemon MUST close the superseded
// clients' connections (it now uses the closing ReplaceSyslogClients), or the
// old sockets leak — one fd per re-apply, accumulating over many commits.
//
// Reverting the fix (er.ReplaceSyslogClients(clients) -> the non-closing
// er.SetSyslogClients(clients)) leaves the prior connections open, so Closes()
// stays 0 and this test fails.
func TestApplySyslogConfigClosesSupersededStreamClients(t *testing.T) {
	er := logging.NewEventReader(nil, nil)

	// Two prior stream clients with observable connections. Because the daemon
	// rebuilds the entire client set from config on every apply, on re-apply
	// BOTH are superseded by-object and BOTH connections must be torn down —
	// this is the "old set fully closed" control for a path that never reuses a
	// client object across applies.
	c1 := &closeRecordingConn{}
	c2 := &closeRecordingConn{}
	prior1 := logging.NewSyslogClientWithConn(c1, "tcp")
	prior2 := logging.NewSyslogClientWithConn(c2, "tcp")
	er.SetSyslogClients([]*logging.SyslogClient{prior1, prior2})
	if got := er.SyslogClientCount(); got != 2 {
		t.Fatalf("setup: expected 2 installed clients, got %d", got)
	}

	// Re-apply: stream mode with a single (different) stream. The constructed
	// client is a fresh UDP client to a loopback address — built without any
	// live peer, so no real network is exercised.
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"s1": {Name: "s1", Host: "127.0.0.1", Port: 514},
	}

	d.applySyslogConfig(er, cfg)

	if got := c1.Closes(); got != 1 {
		t.Fatalf("superseded stream client #1 must be Closed exactly once on "+
			"re-apply; got %d (0 = fd leak / reverted to SetSyslogClients; "+
			">1 = double-close)", got)
	}
	if got := c2.Closes(); got != 1 {
		t.Fatalf("superseded stream client #2 must be Closed exactly once "+
			"(old set fully torn down); got %d", got)
	}
	if got := er.SyslogClientCount(); got != 1 {
		t.Fatalf("expected the single freshly-built client installed, got %d", got)
	}
}

// TestApplySyslogConfigEventModeClosesStreamClients verifies the event-mode
// transition also closes prior stream clients. Switching security log mode
// from stream to event removes all remote forwarding; a leftover open
// connection to the prior receiver would be an fd leak (#3579). RED on revert
// of the event-mode er.ReplaceSyslogClients(nil) back to SetSyslogClients(nil).
func TestApplySyslogConfigEventModeClosesStreamClients(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	rc := &closeRecordingConn{}
	prior := logging.NewSyslogClientWithConn(rc, "tls")
	er.SetSyslogClients([]*logging.SyslogClient{prior})

	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "event"
	// applyAggregator is a no-op (Report false); NewLocalLogWriter may fail to
	// open /var/log/xpf on a bare test host, which is fine — the syslog client
	// teardown happens before that and is what we assert.

	d.applySyslogConfig(er, cfg)

	if got := rc.Closes(); got != 1 {
		t.Fatalf("event-mode apply must Close the superseded stream client "+
			"exactly once; got %d", got)
	}
	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("event mode must leave zero remote syslog clients, got %d", got)
	}
}
