// #9326: applying a config synchronously dialed every configured syslog stream
// on the commit path, with no idempotence gate and no aggregate bound.
//
// Re-derived before fixing anything, driving the real applySyslogConfig:
//
//	one apply, 3 unreachable TCP streams   -> 15.01s   (3 x the 5s dialer timeout)
//	three more applies, IDENTICAL config   -> a fresh dial per stream, every time
//
// A commit is the operator's control loop. Blocking it on whether a third-party
// collector happens to be up couples config change to someone else's uptime,
// and on a cluster it widens the window in which the two nodes disagree about
// the committed config.
//
// THESE CELLS ASSERT DIAL COUNT, NOT WALL TIME, which the issue asks for and
// which matters: a wall-time assertion passes on a fast machine, on a host whose
// resolver answers quickly, or whenever the target happens to REFUSE rather than
// blackhole — so it would go green while the coupling it is meant to forbid is
// still there. The count is the property.

package daemon

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// streamCfg9326 builds an N-stream stanza on the given transport, with hosts in
// RFC 5737 TEST-NET-1 so a real dial can never succeed by accident.
func streamCfg9326(t *testing.T, proto string, n int) *config.Config {
	t.Helper()
	lines := []string{"set security log mode stream"}
	for i := 1; i <= n; i++ {
		lines = append(lines,
			fmt.Sprintf("set security log stream s%d host 192.0.2.%d", i, 10+i),
			fmt.Sprintf("set security log stream s%d transport protocol %s", i, proto))
	}
	store := testStoreWithSetConfig(t, lines)
	cfg := store.ActiveConfig()
	if got := len(cfg.Security.Log.Streams); got != n {
		t.Fatalf("FIXTURE: expected %d streams, got %d — every count below would be "+
			"measuring the wrong config", n, got)
	}
	return cfg
}

// applier9326 runs applies while counting how many clients the daemon actually
// hands to the (suppressed) warm — the observable that stands in for "how many
// connections this apply set up".
type applier9326 struct {
	d      *Daemon
	er     *logging.EventReader
	warmed int
	passes int
}

func newApplier9326(t *testing.T) *applier9326 {
	t.Helper()
	a := &applier9326{er: logging.NewEventReader(nil, nil)}
	a.d = &Daemon{}
	// Suppress the async warm and COUNT it instead. Suppressing matters twice
	// over: it keeps a background dial out of the test, and it makes "the
	// commit path did not dial" observable rather than merely fast.
	a.d.syslogWarmFn = func(cs []*logging.SyslogClient) {
		a.warmed += len(cs)
		a.passes++
	}
	return a
}

func (a *applier9326) apply(cfg *config.Config) { a.d.applySyslogConfig(a.er, cfg) }

// ACCEPTANCE 1: an unchanged stanza performs zero client rebuilds.
func TestUnchangedSyslogStanzaRebuildsNothing9326(t *testing.T) {
	cfg := streamCfg9326(t, "tcp", 5)
	a := newApplier9326(t)

	a.apply(cfg)
	first := a.warmed
	if first != 5 {
		t.Fatalf("NON-VACUITY: the first apply must build all 5 clients; built %d. "+
			"Without that the zero-rebuild assertion below passes for a config that "+
			"never installed anything.", first)
	}

	for i := 0; i < 3; i++ {
		a.apply(cfg)
	}
	if a.warmed != first {
		t.Errorf("#9326: three further applies of an IDENTICAL 5-stream stanza rebuilt "+
			"%d more clients (total %d, want %d).\n"+
			"applySyslogConfig runs on EVERY commit, so an unrelated stanza's change "+
			"tore down and re-established every syslog connection. Measured before "+
			"the fix: 20 dials for 4 applies.", a.warmed-first, a.warmed, first)
	}
}

// POSITIVE CONTROL for acceptance 1 — without it, a gate that never rebuilt
// anything would pass the cell above.
func TestChangedSyslogStanzaDoesRebuild9326(t *testing.T) {
	a := newApplier9326(t)
	a.apply(streamCfg9326(t, "tcp", 2))
	afterFirst := a.warmed

	// A DIFFERENT stanza: one more stream.
	a.apply(streamCfg9326(t, "tcp", 3))
	if a.warmed == afterFirst {
		t.Fatal("CONTROL FAILED: a CHANGED stanza must rebuild. A hash gate that " +
			"never rebuilds satisfies the idempotence cell and silently pins the " +
			"daemon to the first syslog config it ever saw.")
	}
}

// The gate must not survive a teardown: re-adding the same stanza after all
// streams are removed has to install clients again, or the hash matches a set
// that was closed and the operator's streams silently stay down.
func TestSyslogGateForgottenOnTeardown9326(t *testing.T) {
	cfg := streamCfg9326(t, "tcp", 2)
	a := newApplier9326(t)
	a.apply(cfg)
	before := a.warmed

	// Remove every stream, then re-add the identical stanza.
	a.apply(testStoreWithSetConfig(t, []string{"set security log mode stream"}).ActiveConfig())
	a.apply(cfg)
	if a.warmed <= before {
		t.Errorf("#9326: after a teardown, re-applying the SAME stanza installed "+
			"nothing (warmed %d -> %d). The fingerprint must be forgotten when the "+
			"client set is closed, or it hash-matches a set that no longer exists.",
			before, a.warmed)
	}
}

// ACCEPTANCE 2: an unreachable stream does not dial on the commit path at all.
// This is the count-based statement of "does not block": the pre-fix path spent
// 5s per stream here, and it spent it because it dialed.
func TestCommitPathDoesNotDialStreams9326(t *testing.T) {
	cfg := streamCfg9326(t, "tcp", 3)
	a := newApplier9326(t)
	a.apply(cfg)

	if a.passes != 1 || a.warmed != 3 {
		t.Fatalf("NON-VACUITY: expected one warm pass over 3 clients; got %d passes, "+
			"%d clients", a.passes, a.warmed)
	}
	// The clients reached the warm at all, which is the structural evidence
	// that the dial was moved there: before #9326 there was no warm, because
	// the constructor had already dialed. The timing-free proof that
	// construction no longer dials lives one layer down, in
	// TestDeferredConstructionDoesNotDial9326 — a dial that HAPPENS to an
	// unreachable host reports an error, and one that never happens cannot.
}

// ACCEPTANCE 3: UDP still dials at construction, and that is deliberate.
//
// A deferred UDP client would NEVER connect: Send -> writeMsg fails on a nil
// conn and the UDP path does not reconnect, unlike TCP/TLS. So UDP keeps its
// construction dial (cheap — a UDP dial binds rather than handshakes) and is
// bounded by dialUDP's own 5s dialer instead. This cell pins the asymmetry so a
// future "make it symmetric" change has to confront it.
func TestUDPStreamsAreNotDeferred9326(t *testing.T) {
	if _, err := logging.NewSyslogClientDeferred("192.0.2.10", 514, "", "udp", nil); err == nil {
		t.Fatal("#9326: NewSyslogClientDeferred must REFUSE udp. A deferred UDP " +
			"client never connects — writeMsg fails on a nil conn and the UDP path " +
			"has no reconnect branch — so it would silently forward nothing for the " +
			"life of the config.")
	}
	// CONTROL: tcp and tls ARE deferrable, or the refusal above is vacuous.
	for _, proto := range []string{"tcp", "tls"} {
		c, err := logging.NewSyslogClientDeferred("192.0.2.10", 514, "", proto, nil)
		if err != nil || c == nil {
			t.Errorf("CONTROL: %s must be deferrable; got client=%v err=%v", proto, c, err)
		}
	}
}

// THE WIRING, and the cell the first mutation pass showed was missing.
//
// Measured: reverting applySyslogConfig to the DIALING constructor for TCP —
// the defect itself — SURVIVED every cell above. They count how many clients
// reach the warm, and the warm receives them either way; the library cells
// prove the deferred constructor does not dial and say nothing about whether
// the daemon uses it. Binding a constructor is not binding the call site.
//
// The observable has to distinguish "did not dial" from "dialed and failed",
// which an unreachable host cannot: both end unconnected. So this dials at a
// REAL listener that is definitely accepting. A deferred client is unconnected
// after the apply; a client the commit path dialed is connected.
func TestCommitPathLeavesStreamClientsUnconnected9326(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	store := testStoreWithSetConfig(t, []string{
		"set security log mode stream",
		fmt.Sprintf("set security log stream reachable host %s", host),
		fmt.Sprintf("set security log stream reachable port %d", port),
		"set security log stream reachable transport protocol tcp",
	})
	var captured []*logging.SyslogClient
	d := &Daemon{syslogWarmFn: func(cs []*logging.SyslogClient) { captured = cs }}
	d.applySyslogConfig(logging.NewEventReader(nil, nil), store.ActiveConfig())

	if len(captured) != 1 {
		t.Fatalf("NON-VACUITY: expected exactly one stream client, got %d", len(captured))
	}
	c := captured[0]
	if c.Connected() {
		t.Errorf("#9326: the commit path CONNECTED the stream client. The dial is back "+
			"on the commit path, where three unreachable hosts cost a measured 15.01s "+
			"— 3 x the 5s dialer timeout — and a commit is the operator's control loop.\n"+
			"  remote=%s", c.RemoteAddr())
	}

	// POSITIVE CONTROL. Without it, `Connected()==false` is equally consistent
	// with a listener that is not actually accepting, and the assertion above
	// would pass for the wrong reason on any broken fixture.
	if err := c.Connect(); err != nil {
		t.Fatalf("CONTROL FAILED: the client cannot reach the test listener at all "+
			"(%v), so `not connected` above proves nothing about whether the commit "+
			"path dialed", err)
	}
	if !c.Connected() {
		t.Fatal("CONTROL FAILED: Connect() reported success and Connected() is still " +
			"false, so the accessor cannot observe the property under test")
	}
}
