// #5380: syncSessionRequestsLocked mirrors a batch of session-sync requests to
// the Rust helper by dialing the dedicated session control socket once PER
// request. Each request already fails in bounded time (sessionSyncDialTimeout +
// sessionSyncRoundtripDeadline), but before this fix the batch loop paid that
// deadline ONCE PER request: a hung helper (accepts the connection but never
// reads or replies) made an N-request batch block for N * the round-trip
// deadline. A bulk delete chunk is up to sessionHelperDeleteChunk (256)
// requests, so a single hung helper stalled bulk session ops — while repeatedly
// holding sessionMu, starving live session installs — for minutes.
//
// The fix wraps a transport-layer round-trip failure (dial/write/read) with
// errSessionHelperUnreachable and aborts the batch on the first such error, so
// a hung helper costs ~one round-trip deadline for the WHOLE batch, not one per
// request. The mirror is best-effort; the periodic sweep retries once the
// helper is healthy.
//
// FAIL-ON-REVERT: delete the `if errors.Is(err, errSessionHelperUnreachable) {
// break }` fast-fail in syncSessionRequestsLocked and this test goes RED — the
// batch reverts to N per-request deadlines and blows the elapsed bound (it
// takes ~n * shrunk-deadline instead of ~one).
package userspace

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// startHungSessionSocket binds the dedicated session socket and ACCEPTS
// connections but never reads or responds — reproducing a helper whose session
// thread is wedged. A client dial succeeds (the kernel/handler accepts) and the
// client's read then blocks until its own deadline fires, which is exactly the
// per-request stall the batch loop must not pay once per request.
func startHungSessionSocket(t *testing.T, sockPath string) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen hung session socket: %v", err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Park the connection without reading or writing so the client's
			// round-trip stalls until its read deadline.
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	})
}

func TestSyncSessionRequestsLockedFastFailsOnHungHelper5380(t *testing.T) {
	// A SHORT temp-dir prefix (not t.TempDir(), which embeds the long test
	// name) keeps the AF_UNIX path under the 108-byte sun_path limit — the
	// "bind: invalid argument" trap. Respects TMPDIR (run with TMPDIR=/tmp).
	dir, err := os.MkdirTemp("", "x5380")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	controlSock := filepath.Join(dir, "control.sock")
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	startHungSessionSocket(t, sessionSock)

	// Shrink the per-request bounds so the batch timing is fast to measure. The
	// dial succeeds (the socket accepts), so it is the round-trip deadline that
	// dominates the hung-helper stall.
	origDial, origRT := sessionSyncDialTimeout, sessionSyncRoundtripDeadline
	sessionSyncDialTimeout = 150 * time.Millisecond
	sessionSyncRoundtripDeadline = 150 * time.Millisecond
	t.Cleanup(func() {
		sessionSyncDialTimeout = origDial
		sessionSyncRoundtripDeadline = origRT
	})

	m := New()
	m.cfg.ControlSocket = controlSock

	// A batch of n requests. With the fast-fail the batch stops after the first
	// transport failure (~one round-trip deadline). Without it, every request
	// pays the deadline: ~n * 150ms = 1.5s.
	const n = 10
	reqs := make([]SessionSyncRequest, n)
	for i := range reqs {
		reqs[i] = SessionSyncRequest{Operation: "delete"}
	}

	type result struct {
		elapsed time.Duration
		err     error
	}
	resCh := make(chan result, 1)
	go func() {
		start := time.Now()
		m.mu.Lock()
		err := m.syncSessionRequestsLocked(reqs...)
		m.mu.Unlock()
		resCh <- result{elapsed: time.Since(start), err: err}
	}()

	// Bound is ~3x one shrunk deadline: comfortably above a single request's
	// stall (plus jitter) and far below the n-deadline (1.5s) the unfixed batch
	// would take. The 5s watchdog guarantees the suite never hangs even on the
	// pathological unbounded regression.
	const bound = 500 * time.Millisecond
	select {
	case res := <-resCh:
		if res.elapsed > bound {
			t.Fatalf("syncSessionRequestsLocked took %v for %d hung requests; want <%v. "+
				"The batch is paying the per-request round-trip deadline once PER request — "+
				"the errSessionHelperUnreachable fast-fail break is missing (#5380)",
				res.elapsed, n, bound)
		}
		// The batch aborted BECAUSE the helper was unreachable — prove the
		// returned error carries the sentinel so callers (clear-all #5881) still
		// report the failure rather than masquerading it as success.
		if !errors.Is(res.err, errSessionHelperUnreachable) {
			t.Fatalf("expected errSessionHelperUnreachable from a hung helper, got %v", res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("syncSessionRequestsLocked did not return within 5s for %d hung requests; "+
			"the batch is not fast-failing on an unreachable helper (#5380)", n)
	}
}
