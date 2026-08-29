package cluster

import (
	"context"
	"crypto/rand"
	"net"
	"testing"

	"github.com/flynn/noise"
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

	// #7163 INVERTED THE OPENING TURN, and the test follows it rather than
	// working around it. Under Noise the accepter is the RESPONDER: it speaks
	// only after reading the initiator's msg1. So the way a client parks the
	// server's handshake is to connect and say NOTHING — which is the truer
	// form of this hazard anyway, since a silent client is what a stalled or
	// hostile peer actually looks like.
	//
	// Client A: connect and stall by silence. The server is now parked reading
	// A's msg1 for the full syncHandshakeTimeout.
	connA, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.Close()

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
	// B plays the initiator with the REAL PSK and the server's role-ordered
	// prologue (server is node 0 and the responder, so the initiator is node 1).
	//
	// Both are required, and a first draft of this test got it wrong in an
	// instructive way: under psk0 the FIRST message already carries a tag, so a
	// wrong PSK is refused at msg1 and the server closes — which reads as
	// "the accept loop stalled" when it actually means "B was rejected". The
	// property under test is that the server ANSWERS PROMPTLY while A's
	// handshake is parked, so B has to get far enough to be answered.
	bhs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           syncNoiseCipherSuite,
		Pattern:               noise.HandshakeNN,
		Initiator:             true,
		Prologue:              syncNoisePrologue(syncNoisePhaseConnect, 22, 1, 0, 0),
		PresharedKey:          syncNoisePSK(key),
		PresharedKeyPlacement: 0,
		Random:                rand.Reader,
	})
	if err != nil {
		t.Fatalf("B handshake init: %v", err)
	}
	msg1, _, _, err := bhs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("B msg1: %v", err)
	}
	if err := writeMsg(connB, syncMsgAuthHello, msg1); err != nil {
		t.Fatalf("B failed to send msg1: %v", err)
	}
	typ, _, err := readSyncFrameRaw(connB)
	if err != nil {
		t.Fatalf("B did not receive the server's reply while A's handshake was in flight "+
			"(accept loop stalled on A?): %v", err)
	}
	if typ != syncMsgAuthProof {
		t.Fatalf("B: expected the server's noise msg2 (type %d), got %d", syncMsgAuthProof, typ)
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("B's handshake started too late (%v) — accept loop appears serialized on A", elapsed)
	}
}
