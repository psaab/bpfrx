package api

// sse_slow_reader_pin_7632_test.go — #7632.
//
// The SSE sibling of #6809. An event stream writes straight to the
// ResponseWriter and flushes, and http.Server runs with WriteTimeout 0
// process-wide so these long-lived streams are not severed — so a subscriber
// that stays CONNECTED and stops reading fills the socket buffers and parks the
// handler goroutine in Write indefinitely, holding a subscriber slot with it.
//
// The fixture is the one #6809 built (stalledConn6809 / stalledListener6809): a
// net.Conn that accepts a fixed prefix of bytes and then parks the writer
// exactly as a full send buffer does, until the write deadline or forever if
// none is armed. Reused rather than rebuilt — it is the deterministic
// instrument for this whole class.
//
// The SSE-SPECIFIC property is the idle cell below. An event feed on a quiet
// firewall is SUPPOSED to sit silent for long stretches, so an elapsed budget
// would sever the healthy case; a per-write deadline bounds a write that has
// BEGUN and says nothing about the gap between events. That difference is why
// this is a sibling and not a copy of #6809.

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// startStalledSSEServer7632 serves an SSE handler over a listener whose conns
// stop accepting bytes after budget, and reports when the handler returns.
func startStalledSSEServer7632(
	t *testing.T,
	h func(*Server, http.ResponseWriter, *http.Request),
	budget int,
	deadlineUnsupported bool,
) (addr string, buf *logging.EventBuffer, done <-chan struct{}, cleanup func()) {
	t.Helper()
	buf = logging.NewEventBuffer(1024)
	srv := &Server{eventBuf: buf}

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	sl := &stalledListener6809{Listener: base, budget: budget, deadlineUnsupported: deadlineUnsupported}

	handlerDone := make(chan struct{})
	var once sync.Once
	ts := &httptest.Server{
		Listener: sl,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer once.Do(func() { close(handlerDone) })
			h(srv, w, r)
		})},
	}
	ts.Start()
	return ts.Listener.Addr().String(), buf, handlerDone, func() {
		sl.releaseAll()
		ts.Close()
	}
}

// floodEvents7632 publishes enough events to push the stream past the stalled
// conn's byte budget and into the blocking write.
func floodEvents7632(buf *logging.EventBuffer, n int) {
	for i := 0; i < n; i++ {
		buf.Add(logging.EventRecord{
			Time:     time.Now(),
			Type:     "SESSION_OPEN",
			SrcAddr:  fmt.Sprintf("10.0.1.%d:12345", i%256),
			DstAddr:  "10.0.2.100:80",
			Protocol: "TCP",
			Action:   "permit",
			PolicyID: 1,
		})
	}
}

// TestSlowSSEReaderDoesNotPinTheHandler7632 is the issue: a connected
// non-reading subscriber must not park the handler goroutine indefinitely.
//
// FAIL-ON-REVERT: drop the newSSEStream wrapping (write straight to w, as
// before) and no deadline is ever armed, so stalledConn6809.Write takes its
// wdl.IsZero() branch and blocks until teardown — this cell then fails on the
// timeout.
func TestSlowSSEReaderDoesNotPinTheHandler7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 250 * time.Millisecond
	t.Cleanup(func() { sseWriteDeadline = restore })

	addr, buf, done, cleanup := startStalledSSEServer7632(t,
		(*Server).eventStreamHandler, 8*1024, false)
	defer cleanup()
	dialAndRequestWithoutReading6809(t, addr)

	// Let the subscription come up, then push far more than the conn will take.
	time.Sleep(100 * time.Millisecond)
	floodEvents7632(buf, 4000)

	select {
	case <-done:
		// Returned: the write deadline turned the blocked write into an
		// ordinary error, and the handler treats a write failure as terminal.
	case <-time.After(15 * time.Second):
		t.Fatal("the SSE handler is still running ~60 write-deadline windows after " +
			"a connected subscriber stopped reading — the goroutine, the socket " +
			"and the subscriber slot are all pinned, and nothing in the request " +
			"bounds them (#7632)")
	}
}

// TestSlowSSEReaderPinIsReachableWithoutTheDeadline7632 is the NEGATIVE
// CONTROL. "The handler returned" proves the fix only if this fixture is
// capable of NOT returning: with write deadlines unsupported nothing can
// interrupt the blocked write, so the handler MUST still be running.
func TestSlowSSEReaderPinIsReachableWithoutTheDeadline7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 100 * time.Millisecond
	t.Cleanup(func() { sseWriteDeadline = restore })

	addr, buf, done, cleanup := startStalledSSEServer7632(t,
		(*Server).eventStreamHandler, 8*1024, true /* deadlines unsupported */)
	defer cleanup()
	dialAndRequestWithoutReading6809(t, addr)

	time.Sleep(100 * time.Millisecond)
	floodEvents7632(buf, 4000)

	select {
	case <-done:
		t.Fatal("the handler returned with write deadlines unsupported — the " +
			"fixture cannot pin, so the sibling cell's pass proves nothing")
	case <-time.After(2 * time.Second):
		// Still blocked, as a real socket would be.
	}
}

// TestIdleSSEStreamIsNotSevered7632 is the cell that makes this a SIBLING of
// #6809 rather than a copy of it, and the one a fresh lane would most likely
// get wrong.
//
// An event feed on a quiet firewall sits silent for long stretches — that is
// its normal operating state, not a symptom. So the bound must be per-WRITE and
// never elapsed: a stream that has sent nothing for many multiples of the write
// deadline is HEALTHY and must stay open.
//
// FAIL-ON-REVERT: add any elapsed budget to the stream (e.g. wrap r.Context()
// in a WithTimeout the way the RIB dump does) and this cell reds — which is
// exactly the design mistake it exists to prevent.
func TestIdleSSEStreamIsNotSevered7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 100 * time.Millisecond
	t.Cleanup(func() { sseWriteDeadline = restore })

	buf, resp, stop := openSSEStream7632(t, sseWriteDeadline)
	defer stop()

	// Drain the establishing event so the read below can only see what arrives
	// AFTER the idle period.
	if first := readSSEChunk7632(t, resp, 3*time.Second); !strings.Contains(first, "SESSION_OPEN") {
		t.Fatalf("precondition: the stream did not establish; read %q", first)
	}

	// Now idle for many multiples of the write deadline with NO events at all.
	time.Sleep(10 * sseWriteDeadline)

	// The stream is still live: an event published now is still delivered.
	floodEvents7632(buf, 1)
	got := readSSEChunk7632(t, resp, 3*time.Second)
	if !strings.Contains(got, "SESSION_OPEN") {
		t.Fatalf("an SSE stream that idled for %v was severed — idling is the NORMAL "+
			"state of an event feed, so the bound must be per-WRITE and never "+
			"elapsed (#7632). read: %q", 10*sseWriteDeadline, got)
	}
}

// TestHealthySSEReaderStillGetsEvents7632 is the PAIRED control for the
// budgets. Every cell above asserts something STOPS; without this they are all
// satisfied by a handler that stops on every request.
func TestHealthySSEReaderStillGetsEvents7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 2 * time.Second
	t.Cleanup(func() { sseWriteDeadline = restore })

	buf, resp, stop := openSSEStream7632(t, 2*time.Second)
	defer stop()

	got := readSSEChunk7632(t, resp, 3*time.Second)
	if n := strings.Count(got, "SESSION_OPEN"); n < 1 {
		t.Fatalf("a reader that IS reading received no events — the #7632 deadline "+
			"severed a healthy stream. read: %q", got)
	}
	if !strings.Contains(got, "id: 1") {
		t.Fatalf("the SSE envelope is malformed: %q", got)
	}

	// And it keeps delivering: a second batch after the first read.
	floodEvents7632(buf, 3)
	if more := readSSEChunk7632(t, resp, 3*time.Second); !strings.Contains(more, "SESSION_OPEN") {
		t.Fatalf("the stream stopped after the first batch; read %q", more)
	}
}

// openSSEStream7632 starts an event-stream server and returns an ESTABLISHED
// stream.
//
// Establishing it needs one event, and that is a real property of these
// handlers rather than a test artifact: net/http does not send response headers
// until the first Write or Flush, and setSSEHeaders only sets header VALUES —
// so a client connecting to a quiet feed blocks in http.Get waiting for headers
// that no one has sent yet. (Pre-existing, unchanged by #7632, and noted rather
// than fixed here: a browser EventSource on an idle firewall would hang the
// same way.) The publish therefore runs on its own goroutine, because the GET
// cannot return until it lands.
func openSSEStream7632(t *testing.T, deadline time.Duration) (*logging.EventBuffer, *http.Response, func()) {
	t.Helper()
	restore := sseWriteDeadline
	sseWriteDeadline = deadline
	t.Cleanup(func() { sseWriteDeadline = restore })

	buf := logging.NewEventBuffer(256)
	srv := &Server{eventBuf: buf}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.eventStreamHandler(w, r)
	}))

	go func() {
		time.Sleep(150 * time.Millisecond) // let the subscription come up
		floodEvents7632(buf, 1)
	}()

	resp, err := http.Get(ts.URL + "/api/v1/events/stream")
	if err != nil {
		ts.Close()
		t.Fatalf("GET: %v", err)
	}
	stop := func() {
		resp.Body.Close()
		// The handler is parked in its select; force the connection shut so its
		// request context fires and Close() is not left waiting on it.
		ts.CloseClientConnections()
		ts.Close()
	}
	return buf, resp, stop
}

// readSSEChunk7632 reads whatever the stream has produced within d. An SSE
// response never ends on its own, so a plain ReadAll would block forever.
func readSSEChunk7632(t *testing.T, resp *http.Response, d time.Duration) string {
	t.Helper()
	type res struct{ s string }
	ch := make(chan res, 1)
	go func() {
		b := make([]byte, 16*1024)
		n, _ := resp.Body.Read(b)
		ch <- res{string(b[:n])}
	}()
	select {
	case r := <-ch:
		return r.s
	case <-time.After(d):
		return ""
	}
}
