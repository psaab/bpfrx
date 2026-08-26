package api

// bgp_slow_reader_pin_6809_test.go — #6809.
//
// /api/routing/bgp?type=routes streams the RIB straight from a vtysh child to
// the client. Every bound it had was a bound on PROGRESS — maxBGPRoutes caps
// bytes, StreamBGPRoutes caps memory, the #5232 check aborts on DISCONNECT.
// None of them bound the handler while it is BLOCKED.
//
// An authenticated client that opens the endpoint and then reads slowly, or
// stops reading without disconnecting, fills the socket buffers; the periodic
// bw.Flush() parks in the kernel; the callback never returns; the scan never
// resumes; and the cancel/close/reap that would kill vtysh all sit AFTER the
// scan loop. Handler goroutine, vtysh child, pipe and connection stay pinned
// indefinitely. http.Server's WriteTimeout is deliberately 0 process-wide for
// SSE, so there was no global backstop either.
//
// The fixture models the hazard rather than approximating it: a net.Conn that
// accepts a fixed prefix of bytes and then behaves exactly as a real socket
// with a full send buffer — it parks the writer until the write deadline
// expires, and forever if none is set. That makes the fail-on-revert
// DETERMINISTIC (no socket-buffer-size guessing, no sleeps calibrated against
// a real slow client) and it is why the negative-control cell below can prove
// the harness is genuinely capable of pinning.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
	"github.com/psaab/xpf/pkg/frr"
)

// --- a connection that stops accepting bytes, like a full send buffer -------

type stalledConn6809 struct {
	net.Conn
	mu sync.Mutex
	// budget is how many more bytes the "socket buffer" accepts before writes
	// start blocking. The response header and the first chunk must get through
	// or the test would be exercising a different (pre-stream) blocking point.
	budget int
	wdl    time.Time
	// deadlineUnsupported models a ResponseWriter that cannot carry a write
	// deadline: SetWriteDeadline fails, so nothing can interrupt a blocked
	// write and only the elapsed backstop remains (which bounds the CHILD, not
	// this goroutine — see the routing.go note).
	deadlineUnsupported bool
	closed              chan struct{}
	closeOnce           sync.Once
}

func (c *stalledConn6809) SetWriteDeadline(t time.Time) error {
	if c.deadlineUnsupported {
		return http.ErrNotSupported
	}
	c.mu.Lock()
	c.wdl = t
	c.mu.Unlock()
	return nil
}

func (c *stalledConn6809) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.budget > 0 {
		c.budget -= len(p)
		c.mu.Unlock()
		return c.Conn.Write(p)
	}
	wdl := c.wdl
	c.mu.Unlock()

	// Buffers are "full". A real socket parks the writer here.
	if wdl.IsZero() {
		<-c.closed // no deadline armed: block until the test tears down
		return 0, net.ErrClosed
	}
	t := time.NewTimer(time.Until(wdl))
	defer t.Stop()
	select {
	case <-t.C:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *stalledConn6809) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// stalledListener6809 wraps every accepted conn so net/http writes the response
// through it — which is also what routes http.ResponseController's
// SetWriteDeadline into stalledConn6809 above.
type stalledListener6809 struct {
	net.Listener
	budget              int
	deadlineUnsupported bool
	mu                  sync.Mutex
	conns               []*stalledConn6809
}

func (l *stalledListener6809) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	sc := &stalledConn6809{
		Conn:                c,
		budget:              l.budget,
		deadlineUnsupported: l.deadlineUnsupported,
		closed:              make(chan struct{}),
	}
	l.mu.Lock()
	l.conns = append(l.conns, sc)
	l.mu.Unlock()
	return sc, nil
}

func (l *stalledListener6809) releaseAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		c.closeOnce.Do(func() { close(c.closed) })
	}
}

// bigBGPTable6809 renders enough routes that the stream enters the periodic
// 1024-route flush branch many times over.
func bigBGPTable6809(n int) string {
	rows := make([][3]string, n)
	for i := range rows {
		rows[i] = [3]string{
			fmt.Sprintf("10.%d.%d.0/24", i/256%256, i%256),
			"192.0.2.1",
			"65001 i",
		}
	}
	return makeFRRBGPOutput(rows)
}

// startStalledBGPServer6809 serves bgpHandler over a listener whose conns stop
// accepting bytes after budget, and reports when the handler returns.
func startStalledBGPServer6809(t *testing.T, budget int, deadlineUnsupported bool) (addr string, done <-chan struct{}, cleanup func()) {
	t.Helper()
	srv := newBGPServer(t, bigBGPTable6809(20000))

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
			srv.bgpHandler(w, r)
		})},
	}
	ts.Start()
	return ts.Listener.Addr().String(), handlerDone, func() {
		sl.releaseAll()
		ts.Close()
	}
}

// dialAndRequestWithoutReading6809 opens a raw connection, sends the request,
// and NEVER reads the response — the exact shape of the hazard. The connection
// stays OPEN, so nothing produces a disconnect or a write error on its own.
func dialAndRequestWithoutReading6809(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := fmt.Fprintf(c, "GET /api/routing/bgp?type=routes HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return c
}

// TestSlowReaderDoesNotPinTheHandler6809 is the issue. A connected non-reader
// must not park the handler goroutine indefinitely.
//
// FAIL-ON-REVERT: remove either armWriteDeadline() call and no deadline is ever
// set on the conn, so stalledConn6809.Write takes its wdl.IsZero() branch and
// blocks until teardown — this cell then fails on the timeout, naming the pin.
func TestSlowReaderDoesNotPinTheHandler6809(t *testing.T) {
	restore := bgpStreamWriteDeadline
	bgpStreamWriteDeadline = 250 * time.Millisecond
	t.Cleanup(func() { bgpStreamWriteDeadline = restore })

	// Budget lets the header and the first chunks through, so the stall lands
	// inside the route stream rather than before it.
	addr, done, cleanup := startStalledBGPServer6809(t, 32*1024, false)
	defer cleanup()
	dialAndRequestWithoutReading6809(t, addr)

	select {
	case <-done:
		// Returned: the write deadline converted the blocked flush into an
		// ordinary terminal write error, which the existing error path already
		// turns into "stop the scan and cancel vtysh".
	case <-time.After(15 * time.Second):
		t.Fatal("the BGP route handler is still running ~60 write-deadline " +
			"windows after a connected client stopped reading — the handler " +
			"goroutine, the vtysh child, its pipe and the connection are all " +
			"pinned, and nothing in the request bounds them (#6809)")
	}
}

// TestStalledConnCanActuallyPinTheHandler6809 is the NEGATIVE CONTROL for the
// cell above, and it is not optional: "the handler returned" proves the fix
// only if this fixture is capable of NOT returning. Here the conn refuses write
// deadlines and the elapsed backstop is set far away, so nothing can interrupt
// the blocked write — the handler MUST still be running.
//
// It also pins the honest limit of the elapsed backstop: with write deadlines
// unavailable it bounds the vtysh child, not this goroutine.
func TestStalledConnCanActuallyPinTheHandler6809(t *testing.T) {
	restoreW, restoreT := bgpStreamWriteDeadline, bgpStreamTotalBudget
	bgpStreamWriteDeadline = 100 * time.Millisecond
	bgpStreamTotalBudget = time.Hour // far away: not the thing under test
	t.Cleanup(func() { bgpStreamWriteDeadline, bgpStreamTotalBudget = restoreW, restoreT })

	addr, done, cleanup := startStalledBGPServer6809(t, 32*1024, true /* deadlines unsupported */)
	defer cleanup()
	dialAndRequestWithoutReading6809(t, addr)

	select {
	case <-done:
		t.Fatal("the handler returned even though write deadlines are " +
			"unsupported and the elapsed backstop is an hour away — the " +
			"fixture cannot pin, so the sibling cell's pass proves nothing")
	case <-time.After(2 * time.Second):
		// Still blocked, as a real socket would be. Good.
	}
}

// TestRIBStreamLimiterRefusesOverCap6809 covers the second half of the hazard:
// even a bounded stream is a vtysh child, so an unbounded NUMBER of them is
// still an accumulation. Over-cap requests are refused immediately (429), not
// queued — a queued request holds the same connection it would hold while
// streaming, which just moves the pin.
func TestRIBStreamLimiterRefusesOverCap6809(t *testing.T) {
	restore := ribStreamLimiter
	ribStreamLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { ribStreamLimiter = restore })

	// Hold the only slot, exactly as an in-flight stream would.
	release, err := ribStreamLimiter.Acquire()
	if err != nil {
		t.Fatalf("precondition: the fresh limiter must admit the first holder: %v", err)
	}

	srv := newBGPServer(t, makeFRRBGPOutput([][3]string{{"10.0.0.0/24", "192.0.2.1", "65001 i"}}))
	rec := httptest.NewRecorder()
	srv.bgpHandler(rec, httptest.NewRequest(http.MethodGet, "/api/routing/bgp?type=routes", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-cap RIB stream status = %d, want %d — an unbounded number "+
			"of concurrent full-RIB streams can accumulate vtysh children (#6809)",
			rec.Code, http.StatusTooManyRequests)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Error("a 429 without Retry-After tells a client to back off but not for " +
			"how long, so a poller retries immediately and the refusal costs more " +
			"than it saves")
	}

	// PAIRED: once the slot is free the same request is admitted and streams.
	release()
	rec2 := httptest.NewRecorder()
	srv.bgpHandler(rec2, httptest.NewRequest(http.MethodGet, "/api/routing/bgp?type=routes", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d after the slot was released, want 200 — the limiter "+
			"refuses every request, not just over-cap ones", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "10.0.0.0/24") {
		t.Fatalf("admitted stream did not carry the route: %s", rec2.Body.String())
	}
}

// TestNormalReaderStillGetsTheWholeTable6809 is the PAIRED control for the
// budgets. Every cell above asserts that something STOPS; without this one they
// are all satisfied by a handler that stops on every request, which would break
// the endpoint for the clients it exists to serve.
func TestNormalReaderStillGetsTheWholeTable6809(t *testing.T) {
	// Deliberately tight budgets: a reader that actually reads must still get
	// the complete table, because each flush is granted a FRESH window.
	restoreW, restoreT := bgpStreamWriteDeadline, bgpStreamTotalBudget
	bgpStreamWriteDeadline = 2 * time.Second
	bgpStreamTotalBudget = 30 * time.Second
	t.Cleanup(func() { bgpStreamWriteDeadline, bgpStreamTotalBudget = restoreW, restoreT })

	const routes = 5000
	srv := newBGPServer(t, bigBGPTable6809(routes))
	ts := httptest.NewServer(http.HandlerFunc(srv.bgpHandler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/routing/bgp?type=routes")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body := readAllString6809(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// The envelope closed properly — a stream cut short by a budget would not.
	if !strings.HasSuffix(strings.TrimSpace(body), `"}}`) {
		t.Fatalf("response envelope was not closed; the stream was cut short:\n%s",
			tail6809(body, 200))
	}
	// Every route is present: count the emitted lines rather than spot-checking
	// one, so a stream truncated in the middle fails.
	if got := strings.Count(body, "192.0.2.1"); got != routes {
		t.Fatalf("emitted %d routes, want %d — the #6809 budgets truncated a "+
			"healthy stream", got, routes)
	}
}

func readAllString6809(t *testing.T, r interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	var b strings.Builder
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}

func tail6809(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// --- the elapsed backstop, bound by what it can actually be observed to do ---

// ctxCapturingExecutor6809 records the context StreamBGPRoutes hands to
// VtyshStream. That context is what exec.CommandContext binds the vtysh child
// to, so its cancellation IS the child's death — the one observable the elapsed
// backstop actually produces.
type ctxCapturingExecutor6809 struct {
	fakeBGPExecutor
	got chan context.Context
}

func (e *ctxCapturingExecutor6809) VtyshStream(ctx context.Context, cmd string) (io.ReadCloser, func() error, error) {
	select {
	case e.got <- ctx:
	default:
	}
	return e.fakeBGPExecutor.VtyshStream(ctx, cmd)
}

// TestElapsedBackstopReapsVtyshWhenWriteDeadlinesAreUnsupported6809 binds the
// budget the write deadline cannot cover.
//
// This cell exists because the mutation matrix caught its absence: deleting the
// elapsed backstop left the whole package GREEN. Every other cell here either
// depends on the write deadline (which the backstop does not affect) or
// deliberately parks the handler forever, so none of them could see it go.
//
// The property is deliberately NOT "the handler returns". With write deadlines
// unsupported the handler genuinely cannot be unpinned — nothing short of a
// socket deadline interrupts a blocked write — and a cell asserting otherwise
// would be asserting something false. What the backstop does is cancel the
// context the vtysh child is bound to, so the CHILD, its pipe and the RIB dump
// are freed on a bounded schedule even while the goroutine stays parked. That
// is a partial bound, and this asserts exactly the part that is real.
//
// FAIL-ON-REVERT: replace the context.WithTimeout with a bare WithCancel and
// nothing cancels this context (the handler is blocked, so neither deferred
// cancel runs) — the wait below times out.
func TestElapsedBackstopReapsVtyshWhenWriteDeadlinesAreUnsupported6809(t *testing.T) {
	restoreW, restoreT := bgpStreamWriteDeadline, bgpStreamTotalBudget
	bgpStreamWriteDeadline = 100 * time.Millisecond
	bgpStreamTotalBudget = 500 * time.Millisecond
	t.Cleanup(func() { bgpStreamWriteDeadline, bgpStreamTotalBudget = restoreW, restoreT })

	exec := &ctxCapturingExecutor6809{
		fakeBGPExecutor: fakeBGPExecutor{vtyshOut: bigBGPTable6809(20000)},
		got:             make(chan context.Context, 1),
	}
	srv := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", exec)}

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// deadlineUnsupported: the write deadline is off the table, so the elapsed
	// backstop is the ONLY bound left and this cell is measuring it alone.
	sl := &stalledListener6809{Listener: base, budget: 32 * 1024, deadlineUnsupported: true}
	ts := &httptest.Server{
		Listener: sl,
		Config:   &http.Server{Handler: http.HandlerFunc(srv.bgpHandler)},
	}
	ts.Start()
	defer func() { sl.releaseAll(); ts.Close() }()

	dialAndRequestWithoutReading6809(t, ts.Listener.Addr().String())

	var streamCtx context.Context
	select {
	case streamCtx = <-exec.got:
	case <-time.After(10 * time.Second):
		t.Fatal("vtysh was never started, so this cell cannot observe the child's " +
			"lifetime")
	}

	select {
	case <-streamCtx.Done():
		// The vtysh child's context was cancelled on schedule:
		// exec.CommandContext kills and reaps it, freeing the process, its pipe
		// and the RIB dump, even though this request's goroutine is still
		// parked in a write nothing can interrupt.
	case <-time.After(10 * time.Second):
		t.Fatal("the vtysh child's context was never cancelled — with a connected " +
			"non-reader and no usable write deadline, the child, its pipe and " +
			"the full RIB dump stay live for as long as the client holds the " +
			"connection open (#6809)")
	}
}
