// #5380 residual: the fast-fail `break` inside deleteHelperSessions{V4,V6}
// only aborts the 256-request loop of a SINGLE call. ClearAllSessions drives
// the helper delete through ClearAllSessionsChunked, which invokes the delete
// callback ONCE PER mirror chunk (sessionClearSnapshotChunk = 4096 keys) — and
// once per family (v4 chunks, then v6 chunks). Because the callbacks return
// void, an inner abort does not propagate: without the ClearAllSessions
// helperDown() guard the shim keeps handing every remaining chunk to a hung
// helper, so a full clear-all still paid ~one round-trip deadline PER chunk
// (~2440 chunks/family on a max table ≈ hours), not "one deadline total".
//
// This binds the OUTER guard. A mirror seeded with one v4 and one v6 session
// produces exactly two delete callbacks (one v4 chunk, then one v6 chunk)
// against a HUNG helper (accepts but never replies). With the guard the v4
// chunk's transport failure is recorded and the v6 chunk SKIPS its helper
// delete: the helper socket is dialed once and the clear pays ~one deadline.
// Without the guard both chunks dial the hung helper: two dials, ~two
// deadlines.
//
// FAIL-ON-REVERT: delete the `if helperDown() { return }` guard from the two
// ClearAllSessionsChunked closures in ClearAllSessions (or make helperDown()
// always false) and this test goes RED — the v6 chunk dials the hung helper
// too (helperDials == 2, not 1) and the elapsed doubles to ~2 * the shrunk
// deadline, blowing the bound. A clean structural + elapsed assertion, not a
// compile break. The #5881 propagation (helperErr still set) and the
// app-rejection-continues path are unaffected — only a TRANSPORT failure trips
// the skip.
package userspace

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

// countingHungSessionSocket binds the dedicated session socket, ACCEPTS every
// connection, and parks it without reading or replying — a helper whose
// session thread is wedged. It records how many connections were accepted so a
// test can prove which chunks actually dialed the helper (a skipped chunk
// never dials).
type countingHungSessionSocket struct {
	ln      net.Listener
	mu      sync.Mutex
	accepts int
	held    []net.Conn
}

func startCountingHungSessionSocket(t *testing.T, sockPath string) *countingHungSessionSocket {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen hung session socket: %v", err)
	}
	c := &countingHungSessionSocket{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.accepts++
			c.held = append(c.held, conn)
			c.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		c.mu.Lock()
		for _, h := range c.held {
			_ = h.Close()
		}
		c.mu.Unlock()
	})
	return c
}

func (c *countingHungSessionSocket) acceptCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accepts
}

func TestClearAllSessionsFastFailsAcrossChunksOnHungHelper5380(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}

	// One v4 + one v6 mirror session → two delete callbacks (a v4 chunk then a
	// v6 chunk). newClearManager5881 sets m.proc, injects real session maps,
	// and seeds the pair; the short-prefix mkdtemp keeps the AF_UNIX path under
	// the 108-byte sun_path limit (run with TMPDIR=/tmp).
	m, adapter, sessionSock := newClearManager5881(t)
	sock := startCountingHungSessionSocket(t, sessionSock)

	// Shrink the per-request bounds so the batch timing is fast to measure. The
	// dial succeeds (the socket accepts), so the round-trip deadline is what a
	// hung chunk pays.
	origDial, origRT := sessionSyncDialTimeout, sessionSyncRoundtripDeadline
	sessionSyncDialTimeout = 400 * time.Millisecond
	sessionSyncRoundtripDeadline = 400 * time.Millisecond
	t.Cleanup(func() {
		sessionSyncDialTimeout = origDial
		sessionSyncRoundtripDeadline = origRT
	})

	type result struct {
		v4, v6  int
		err     error
		elapsed time.Duration
	}
	resCh := make(chan result, 1)
	go func() {
		start := time.Now()
		v4, v6, err := adapter.ClearAllSessions()
		resCh <- result{v4: v4, v6: v6, err: err, elapsed: time.Since(start)}
	}()

	// Bound sits between one and two shrunk deadlines: the guarded clear pays
	// ~one deadline (the v4 chunk) and skips the v6 helper delete; the unfixed
	// clear pays ~two (v4 + v6 chunk). The 5s watchdog guarantees the suite
	// never hangs on the pathological regression.
	const bound = 650 * time.Millisecond
	select {
	case res := <-resCh:
		if res.elapsed > bound {
			t.Fatalf("ClearAllSessions took %v against a hung helper; want <%v. "+
				"The v6 chunk is still dialing the hung helper after the v4 chunk "+
				"recorded a transport failure — the ClearAllSessions helperDown() "+
				"guard is missing, so clear-all pays ~one deadline PER chunk (#5380)",
				res.elapsed, bound)
		}
		// Structural, jitter-free RED signal: only the v4 chunk dials the helper;
		// the v6 chunk short-circuits, so the hung socket sees exactly ONE accept.
		if got := sock.acceptCount(); got != 1 {
			t.Fatalf("hung helper accepted %d connections; want 1 (v4 chunk only). "+
				"The v6 chunk dialed the hung helper too — the helperDown() guard "+
				"does not skip remaining chunks after a transport failure (#5380)", got)
		}
		// #5881 contract intact: the transport failure is still surfaced (the
		// wrapped sentinel), and the mirror's partial counts still come back.
		if !errors.Is(res.err, errSessionHelperUnreachable) {
			t.Fatalf("expected the clear-all error to carry errSessionHelperUnreachable "+
				"(the authoritative revocation is unconfirmed), got %v", res.err)
		}
		if res.v4 != 1 || res.v6 != 1 {
			t.Errorf("counts = (%d, %d), want (1, 1) surfaced alongside the error (#5882)", res.v4, res.v6)
		}
		if mv4, mv6 := m.bpfShim.SessionCount(); mv4 != 0 || mv6 != 0 {
			t.Errorf("mirror not cleared: count = (%d, %d), want (0, 0) — the skip must "+
				"only bypass the HELPER delete, never the mirror clear", mv4, mv6)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("ClearAllSessions did not return within 5s against a hung helper; " +
			"the per-chunk helper delete is not short-circuiting (#5380)")
	}
}
