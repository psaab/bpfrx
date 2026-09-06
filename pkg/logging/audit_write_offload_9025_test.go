package logging

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9025: two synchronous, deadline-free I/O sites sat on the EventStream reader
// goroutine — the one that also carries HA session sync
// (EventTypeSessionOpen/Update/Close), the ISSU drain signal
// (EventTypeDrainComplete) and EventTypeFullResync. Stalling it stalls those.
//
// Site 1: UDP syslog writes had no deadline, exempted by a comment asserting
// "UDP is connectionless and never blocks on Write" — which this tree's own
// flowexport module refutes verbatim (#4423 H07: a connected-UDP Write "can
// block indefinitely on a full socket send buffer").
//
// Site 2: trace and local-log writers did a synchronous WriteString on a raw
// *os.File, plus an inline rotate(), one write(2) per logged event.

// ── Site 1: the UDP path arms a deadline ──

// deadlineRecordingConn records whether SetWriteDeadline was armed before Write.
type deadlineRecordingConn9025 struct {
	armedBeforeWrite atomic.Bool
	armed            atomic.Bool
	writes           atomic.Int32
}

func (c *deadlineRecordingConn9025) Write(b []byte) (int, error) {
	c.writes.Add(1)
	c.armedBeforeWrite.Store(c.armed.Load())
	return len(b), nil
}
func (c *deadlineRecordingConn9025) Read(_ []byte) (int, error)    { return 0, nil }
func (c *deadlineRecordingConn9025) Close() error                  { return nil }
func (c *deadlineRecordingConn9025) LocalAddr() net.Addr           { return dummyAddr{} }
func (c *deadlineRecordingConn9025) RemoteAddr() net.Addr          { return dummyAddr{} }
func (c *deadlineRecordingConn9025) SetDeadline(time.Time) error   { return nil }
func (c *deadlineRecordingConn9025) SetReadDeadline(time.Time) error {
	return nil
}
func (c *deadlineRecordingConn9025) SetWriteDeadline(t time.Time) error {
	c.armed.Store(!t.IsZero())
	return nil
}

func udpClient9025(conn net.Conn) *SyslogClient {
	return &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.23:514",
		protocol:          "udp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              conn,
	}
}

func TestUDPSyslogWriteArmsADeadline9025(t *testing.T) {
	conn := &deadlineRecordingConn9025{}
	c := udpClient9025(conn)

	if err := c.writeMsg("<134>test\n"); err != nil {
		t.Fatalf("writeMsg: %v", err)
	}
	if conn.writes.Load() != 1 {
		t.Fatalf("fixture: expected exactly one write, got %d", conn.writes.Load())
	}
	if !conn.armedBeforeWrite.Load() {
		t.Error("#9025: the UDP syslog write ran with NO write deadline armed. " +
			"A connected-UDP Write can block indefinitely on a full socket send " +
			"buffer (ENOBUFS / a congested or down egress path parks the goroutine " +
			"in the netpoller) — and the goroutine it parks is the EventStream " +
			"reader, which also carries HA session sync and the ISSU drain signal. " +
			"UDP is the DEFAULT protocol, so this was the common path")
	}

	// The BINARY path is a separate function and needed the same fix.
	conn2 := &deadlineRecordingConn9025{}
	c2 := udpClient9025(conn2)
	if err := c2.writeBinaryMsg([]byte{1, 2, 3}); err != nil {
		t.Fatalf("writeBinaryMsg: %v", err)
	}
	if !conn2.armedBeforeWrite.Load() {
		t.Error("#9025: writeBinaryMsg's UDP path has no deadline — it is a " +
			"separate function from writeMsg and fixing only one leaves the other " +
			"unbounded")
	}
}

// A UDP deadline expiry must be COUNTED, not silently swallowed. Volume
// backpressure already existed (#3478); latency backpressure did not, and a
// hung write never returned to be counted at all.
func TestUDPSyslogDeadlineExpiryIsCounted9025(t *testing.T) {
	c := udpClient9025(&timeoutConn{})
	before := c.DroppedWrites()

	err := c.Send(SyslogInfo, "probe")
	if err == nil {
		t.Fatal("a write that timed out must surface an error")
	}
	if got := c.DroppedWrites(); got != before+1 {
		t.Errorf("#9025: a UDP write-deadline expiry was not counted as a drop "+
			"(%d -> %d). Arming the deadline turns a silent STALL into a silent "+
			"DROP unless it is counted, and a silent drop is worse — it is "+
			"indistinguishable from success", before, got)
	}
}

// ── Site 2: the trace write is OFF the caller's goroutine ──

func TestTraceWriteDoesNotBlockTheCaller9025(t *testing.T) {
	dir := t.TempDir()
	restore := SetTraceLogDirForTest(dir)
	defer restore()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()

	// Wedge the WRITER goroutine inside a write, modelling a stalled disk
	// (writeback stall, dirty-page throttling, a hung device).
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	tw.async.write = func(it auditItem) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	defer close(release)

	tw.HandleEvent(EventRecord{Type: "SESSION_OPEN"}, nil)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture: the writer goroutine never entered the blocked write, " +
			"so the assertion below would not be about a stalled disk")
	}

	// With the writer wedged, the CALLER must still return promptly. Before
	// #9025 this call did the write itself and would have blocked here.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			tw.HandleEvent(EventRecord{Type: "SESSION_OPEN"}, nil)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("#9025: HandleEvent blocked while the disk write was stalled. " +
			"This runs on the EventStream reader goroutine, so HA session-sync " +
			"deltas and the ISSU drain signal are parked behind it")
	}
}

// A FULL queue must DROP and COUNT, not block — blocking on a full queue puts
// the stall back one buffer later, which would be a fix in name only.
func TestTraceWriteQueueOverflowDropsAndCounts9025(t *testing.T) {
	dir := t.TempDir()
	restore := SetTraceLogDirForTest(dir)
	defer restore()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()

	release := make(chan struct{})
	tw.async.write = func(it auditItem) { <-release }
	defer close(release)

	before := tw.DroppedWrites()
	// Overrun the queue by a wide margin; every excess line must be counted.
	for i := 0; i < auditQueueDepth*2; i++ {
		tw.HandleEvent(EventRecord{Type: "SESSION_OPEN"}, nil)
	}
	if got := tw.DroppedWrites(); got <= before {
		t.Errorf("#9025: %d events were pushed at a queue of depth %d with the "+
			"writer wedged, and DroppedWrites did not move (%d). Either the "+
			"enqueue is blocking — which reinstates the stall one buffer later — "+
			"or overflow is silent, which loses audit telemetry the operator "+
			"cannot detect (#3478's whole point)",
			auditQueueDepth*2, auditQueueDepth, got)
	}
}

// A retired writer must REFUSE, not silently accept into a channel nobody
// drains. This is stricter than the pre-#9025 behaviour required, and it is
// here because the first version of the fix regressed exactly this: the queue
// had room, so post-Close events were swallowed with no drop counted — worse
// than the synchronous nil-file drop it replaced.
func TestRetiredTraceWriterStillCountsDrops9025(t *testing.T) {
	dir := t.TempDir()
	restore := SetTraceLogDirForTest(dir)
	defer restore()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err != nil {
		t.Fatal(err)
	}
	tw.Close()

	before := tw.DroppedWrites()
	tw.HandleEvent(EventRecord{Type: "SESSION_OPEN"}, nil)
	if got := tw.DroppedWrites(); got != before+1 {
		t.Errorf("#9025: an event dispatched to a RETIRED trace writer was not "+
			"counted (%d -> %d) — it was accepted into a queue with no reader, "+
			"which is a silent loss", before, got)
	}
}

// The queued tail must be written on Close, not discarded — those are exactly
// the audit records around whatever caused the shutdown.
func TestCloseDrainsTheQueuedTail9025(t *testing.T) {
	dir := t.TempDir()
	restore := SetTraceLogDirForTest(dir)
	defer restore()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		tw.HandleEvent(EventRecord{Type: "SESSION_OPEN"}, nil)
	}
	tw.Close()

	data, err := os.ReadFile(dir + "/flow.log")
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 50 {
		t.Errorf("#9025: Close wrote %d of 50 queued lines. A shutdown that "+
			"discards the queued tail loses the audit records around whatever "+
			"caused it", lines)
	}
}
