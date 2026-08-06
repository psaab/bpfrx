package cluster

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSyncHandshakeTimeoutIsShort pins the #4370 bound: the setup handshake
// timeout must stay short (the keyed challenge-response completes in
// milliseconds; a longer bound only extends how long a hung/absent peer ties up
// a per-connection handshake goroutine and eats into the 5s Stop budget). RED
// on revert to the original 10s.
func TestSyncHandshakeTimeoutIsShort(t *testing.T) {
	if syncHandshakeTimeout < 1*time.Second || syncHandshakeTimeout > 3*time.Second {
		t.Fatalf("syncHandshakeTimeout = %v, want a short accept-loop bound in [1s, 3s] (#4370)", syncHandshakeTimeout)
	}
}

// TestAcceptLoopHandshakeDoesNotBlockOthers verifies the #4370 fix: a
// slow/hung auth handshake on one accepted connection does NOT stall the accept
// loop from accepting and handshaking OTHER connections.
//
// Client A connects and reads the server's auth HELLO — proving the server
// accepted A and is now committed to (blocked in) A's handshake read — then
// stalls, never sending its own frame. Client B then connects. With the
// per-connection goroutine, the accept loop keeps accepting, so B receives the
// server HELLO within milliseconds. RED on revert: the synchronous accept loop
// is parked inside A's handshake for the full syncHandshakeTimeout, so B is
// never accepted and B's read times out.
func TestAcceptLoopHandshakeDoesNotBlockOthers(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	s := newAuthSync(t, key)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.acceptLoop(ctx, ln, 0)

	// Client A: connect, consume the server HELLO, then stall.
	connA, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.Close()
	if err := connA.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("A set deadline: %v", err)
	}
	if typ, _, err := readSyncFrameRaw(connA); err != nil {
		t.Fatalf("A did not receive server HELLO: %v", err)
	} else if typ != syncMsgAuthHello {
		t.Fatalf("A: expected server HELLO type %d, got %d", syncMsgAuthHello, typ)
	}
	// A now holds the server's handshake read; on the pre-fix synchronous accept
	// loop the loop is stuck here for the full syncHandshakeTimeout.

	// Client B: connect after the server is committed to A. The accept loop must
	// still accept B and start its handshake promptly.
	connB, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer connB.Close()
	if err := connB.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("B set deadline: %v", err)
	}
	start := time.Now()
	typ, _, err := readSyncFrameRaw(connB)
	if err != nil {
		t.Fatalf("B did not receive server HELLO while A's handshake was in flight "+
			"(accept loop stalled on A?): %v", err)
	}
	if typ != syncMsgAuthHello {
		t.Fatalf("B: expected server HELLO type %d, got %d", syncMsgAuthHello, typ)
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("B's handshake started too late (%v) — accept loop appears serialized on A", elapsed)
	}
}
