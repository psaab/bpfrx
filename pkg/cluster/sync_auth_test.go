package cluster

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeSyncAuthProvider is a test SyncAuthProvider that returns a fixed PSK and a
// settable heartbeat downgrade-guard signal.
type fakeSyncAuthProvider struct {
	key      []byte
	authSeen bool
}

func (f *fakeSyncAuthProvider) ControlLinkAuthKey() []byte  { return f.key }
func (f *fakeSyncAuthProvider) HeartbeatPeerAuthSeen() bool { return f.authSeen }

type handshakeResult struct {
	mode syncAuthMode
	key  []byte
	err  error
}

func runHandshake(s *SessionSync, conn net.Conn) <-chan handshakeResult {
	ch := make(chan handshakeResult, 1)
	go func() {
		mode, key, err := s.performSyncHandshake(conn)
		ch <- handshakeResult{mode: mode, key: key, err: err}
	}()
	return ch
}

func newAuthSync(t *testing.T, key []byte, authSeen bool) *SessionSync {
	t.Helper()
	s := NewSessionSync(":0", ":0", nil)
	if key != nil || authSeen {
		s.SetAuthProvider(&fakeSyncAuthProvider{key: key, authSeen: authSeen})
	}
	return s
}

// TestSyncAuthHandshakeBothKeyedAuthenticates verifies the happy path: two
// keyed peers with the SAME PSK complete the mutual challenge-response, both
// negotiate authenticated, and both derive the same per-connection frame key —
// after which a sealed session frame round-trips. RED on revert: without the
// handshake there is no authentication and no derived key.
func TestSyncAuthHandshakeBothKeyedAuthenticates(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	a := newAuthSync(t, key, false)
	b := newAuthSync(t, key, false)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca)
	bch := runHandshake(b, cb)

	ar := <-ach
	br := <-bch

	if ar.err != nil || br.err != nil {
		t.Fatalf("handshake errored: a=%v b=%v", ar.err, br.err)
	}
	if ar.mode != syncAuthAuthenticated || br.mode != syncAuthAuthenticated {
		t.Fatalf("expected both authenticated, got a=%d b=%d", ar.mode, br.mode)
	}
	if len(ar.key) == 0 || !bytes.Equal(ar.key, br.key) {
		t.Fatalf("frame keys must be non-empty and equal: a=%x b=%x", ar.key, br.key)
	}

	// A sealed session frame must round-trip: seal on A's authConn, verify on
	// B's authConn (their frame keys are equal).
	sender := &authConn{Conn: ca, key: ar.key}
	receiver := &authConn{Conn: cb, key: br.key}
	frame := encodeRawMessage(syncMsgSessionV4, []byte("session-payload"))
	sealed := sender.sealFrame(frame)

	header := sealed[:syncHeaderSize]
	length := binary.LittleEndian.Uint32(header[8:12])
	payload := sealed[syncHeaderSize : syncHeaderSize+int(length)]
	trailer := sealed[syncHeaderSize+int(length):]
	if len(trailer) != syncAuthFrameTrailerSize {
		t.Fatalf("sealed frame trailer size = %d, want %d", len(trailer), syncAuthFrameTrailerSize)
	}
	if err := receiver.verifyFrame(header, payload, trailer); err != nil {
		t.Fatalf("authenticated frame failed to verify: %v", err)
	}
}

// TestSyncAuthHandshakeMismatchedKeyRejected verifies that a peer presenting a
// bad setup proof (a different PSK) is REJECTED — the connection is dropped and
// no session data is accepted. RED on revert: without the handshake the
// connection is accepted regardless of key.
func TestSyncAuthHandshakeMismatchedKeyRejected(t *testing.T) {
	a := newAuthSync(t, []byte("key-alpha"), false)
	b := newAuthSync(t, []byte("key-bravo-different"), false)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca)
	bch := runHandshake(b, cb)

	ar := <-ach
	br := <-bch

	if ar.err == nil {
		t.Fatalf("expected rejection on side A, got mode=%d key=%x", ar.mode, ar.key)
	}
	if br.err == nil {
		t.Fatalf("expected rejection on side B, got mode=%d key=%x", br.mode, br.key)
	}
	if ar.mode == syncAuthAuthenticated || br.mode == syncAuthAuthenticated {
		t.Fatalf("mismatched keys must not authenticate: a=%d b=%d", ar.mode, br.mode)
	}
}

// TestSyncAuthHandshakeKeyedNodeRejectsLegacyPeer is the #5078 fail-closed
// guard, and it REPLACES a test that asserted the opposite.
//
// The old TestSyncAuthHandshakeDualAcceptLegacyPeer required a keyed node to
// dual-accept a legacy/unkeyed peer "so the stream stays legacy-compatible (no
// brick)". That compatibility was an unauthenticated active bypass: the peer is
// admitted with no proof of the PSK, its first frame reaches cluster state, and
// it displaces the legitimate peer connection. A keyed node now rejects it, and
// the legacy-compat need is served by the explicit migration window below.
//
// RED on revert: restore the first-contact grace in syncAuthDecision and the
// handshake accepts instead of erroring.
func TestSyncAuthHandshakeKeyedNodeRejectsLegacyPeer(t *testing.T) {
	a := newAuthSync(t, []byte("psk"), false)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca)

	if _, _, err := readSyncFrameRaw(cb); err != nil {
		t.Fatalf("legacy peer failed to read HELLO: %v", err)
	}
	var clockBuf [8]byte
	binary.LittleEndian.PutUint64(clockBuf[:], 12345)
	if err := writeMsg(cb, syncMsgClockSync, clockBuf[:]); err != nil {
		t.Fatalf("legacy peer failed to send clock sync: %v", err)
	}

	ar := <-ach
	if ar.err == nil {
		t.Fatalf("a keyed node must REJECT an unauthenticated peer, got mode=%d", ar.mode)
	}
	if ar.key != nil {
		t.Fatalf("a rejected handshake must yield no frame key")
	}
}

// TestSyncAuthHandshakeDowngradeGuardRejects verifies the downgrade-guard: once
// the peer has authenticated (here via the heartbeat channel, authSeen=true), a
// later UNAUTHENTICATED connection from a legacy/unkeyed peer is REJECTED rather
// than silently downgraded. RED on revert: without the guard the legacy peer is
// dual-accepted.
func TestSyncAuthHandshakeDowngradeGuardRejects(t *testing.T) {
	a := newAuthSync(t, []byte("psk"), true) // heartbeat already saw the peer auth

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca)

	// Legacy peer: consume A's HELLO, then send a real frame with no handshake.
	if _, _, err := readSyncFrameRaw(cb); err != nil {
		t.Fatalf("legacy peer failed to read HELLO: %v", err)
	}
	var clockBuf [8]byte
	binary.LittleEndian.PutUint64(clockBuf[:], 1)
	// The peer may fail to write once A rejects and closes; ignore that error.
	_ = writeMsg(cb, syncMsgClockSync, clockBuf[:])

	ar := <-ach
	if ar.err == nil {
		t.Fatalf("downgrade-guard must reject an unauthenticated peer once authed, got mode=%d", ar.mode)
	}
	if ar.mode == syncAuthAuthenticated {
		t.Fatalf("guard rejection must not authenticate")
	}
}

// TestSyncAuthDisabledNoHandshake verifies that with no auth provider (or no
// key) the handshake is a no-op: no bytes are exchanged and the connection is
// unauthenticated (legacy behavior, byte-identical to before F23).
func TestSyncAuthDisabledNoHandshake(t *testing.T) {
	s := NewSessionSync(":0", ":0", nil) // no provider

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	// If performSyncHandshake performed any I/O it would block on the pipe; a
	// watchdog guarantees the test fails loudly instead of hanging.
	done := make(chan handshakeResult, 1)
	go func() {
		mode, key, err := s.performSyncHandshake(ca)
		done <- handshakeResult{mode: mode, key: key, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("disabled handshake errored: %v", r.err)
		}
		if r.mode != syncAuthUnauthenticated || r.key != nil {
			t.Fatalf("disabled handshake must be an unauthenticated no-op, got %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("performSyncHandshake blocked with no key configured (must be a no-op)")
	}
	_ = cb
}

// TestSyncFrameSealVerifyRoundTripAndReplay unit-tests the per-frame seal /
// verify path: sequential frames verify and advance the watermark; a replayed
// (regressed sequence) frame, a tampered payload, and a wrong-key MAC are all
// rejected. RED on revert: sealFrame/verifyFrame do not exist.
func TestSyncFrameSealVerifyRoundTripAndReplay(t *testing.T) {
	key := []byte("per-connection-frame-key-abc")
	send := &authConn{key: key}
	recv := &authConn{key: key}

	split := func(sealed []byte) (header, payload, trailer []byte) {
		header = sealed[:syncHeaderSize]
		length := binary.LittleEndian.Uint32(header[8:12])
		payload = sealed[syncHeaderSize : syncHeaderSize+int(length)]
		trailer = sealed[syncHeaderSize+int(length):]
		return
	}

	frame1 := encodeRawMessage(syncMsgSessionV4, []byte("one"))
	frame2 := encodeRawMessage(syncMsgSessionV6, []byte("two"))
	sealed1 := send.sealFrame(frame1)
	sealed2 := send.sealFrame(frame2)

	// Sequence must be strictly increasing (1, then 2).
	if got := binary.LittleEndian.Uint64(sealed1[len(sealed1)-syncAuthFrameTrailerSize : len(sealed1)-syncAuthMACSize]); got != 1 {
		t.Fatalf("first sealed frame seq = %d, want 1", got)
	}

	h1, p1, tr1 := split(sealed1)
	if err := recv.verifyFrame(h1, p1, tr1); err != nil {
		t.Fatalf("frame1 must verify: %v", err)
	}
	h2, p2, tr2 := split(sealed2)
	if err := recv.verifyFrame(h2, p2, tr2); err != nil {
		t.Fatalf("frame2 must verify: %v", err)
	}
	// Replay frame1 (seq 1 <= watermark 2) must be rejected.
	if err := recv.verifyFrame(h1, p1, tr1); err != errSyncFrameReplay {
		t.Fatalf("replayed frame must be rejected as replay, got %v", err)
	}

	// Tampered payload must fail the HMAC on a fresh receiver.
	recv2 := &authConn{key: key}
	tampered := append([]byte(nil), p2...)
	tampered[0] ^= 0xFF
	if err := recv2.verifyFrame(h2, tampered, tr2); err != errSyncFrameAuth {
		t.Fatalf("tampered payload must fail HMAC, got %v", err)
	}

	// Wrong key must fail the HMAC.
	recv3 := &authConn{key: []byte("wrong-key")}
	if err := recv3.verifyFrame(h1, p1, tr1); err != errSyncFrameAuth {
		t.Fatalf("wrong-key frame must fail HMAC, got %v", err)
	}
}

// TestSyncAuthDecisionMatrix exercises the fail-closed keyed policy (#5078).
//
// The two "not seen" rows below used to expect ACCEPT: a keyed node granted an
// unkeyed peer a first-contact grace until the sticky downgrade guard armed.
// That grace was an unauthenticated ACTIVE bypass — a PSK-less peer reaching
// the fabric on first contact was admitted, could fence the node, and displaced
// the real peer — and it was open on every fresh boot, because "before the
// guard arms" is exactly when a node starts. A keyed node now REJECTS an
// unauthenticated peer, and the rolling-rollout case that grace served is an
// explicit, default-off, time-bounded window instead.
//
// RED on revert: restore the `peerAuthSeen` grace (accept when the guard has
// not armed), or add any unconditional accept for an unkeyed peer, and
// legacy_peer_rejected_when_keyed / unkeyed_peer_rejected_when_keyed fail.
func TestSyncAuthDecisionMatrix(t *testing.T) {
	cases := []struct {
		name                                       string
		keyConfigured, peerAdv, peerKeyed, proofOK bool
		wantMode                                   syncAuthMode
		wantAccept                                 bool
	}{
		{"no local key accepts all", false, false, false, false, syncAuthUnauthenticated, true},
		{"both keyed good proof authenticates", true, true, true, true, syncAuthAuthenticated, true},
		{"both keyed bad proof rejected", true, true, true, false, syncAuthUnauthenticated, false},
		// The #5078 fix: a keyed node grants no grace at all.
		{"legacy_peer_rejected_when_keyed", true, false, false, false, syncAuthUnauthenticated, false},
		{"unkeyed_peer_rejected_when_keyed", true, true, false, false, syncAuthUnauthenticated, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, accept, reason := syncAuthDecision(tc.keyConfigured, tc.peerAdv, tc.peerKeyed, tc.proofOK)
			if mode != tc.wantMode || accept != tc.wantAccept {
				t.Fatalf("decision = (mode %d, accept %v, %q), want (mode %d, accept %v)", mode, accept, reason, tc.wantMode, tc.wantAccept)
			}
			if !accept && reason == "" {
				t.Fatalf("rejection must carry a reason")
			}
		})
	}
}

// TestSyncAuthProofBindsToNonce guards the challenge-response construction: the
// proof is HMAC(key, tag || challenge) and changes with the challenge, so a
// captured proof cannot be replayed onto a connection with a fresh nonce.
func TestSyncAuthProofBindsToNonce(t *testing.T) {
	key := []byte("k")
	n1 := bytes.Repeat([]byte{1}, syncAuthNonceSize)
	n2 := bytes.Repeat([]byte{2}, syncAuthNonceSize)
	if hmac.Equal(syncAuthProof(key, n1), syncAuthProof(key, n2)) {
		t.Fatal("proof must differ for different challenges")
	}
	want := hmac.New(sha256.New, key)
	want.Write(syncAuthProofTag)
	want.Write(n1)
	if !hmac.Equal(syncAuthProof(key, n1), want.Sum(nil)) {
		t.Fatal("proof must be HMAC(key, tag||challenge)")
	}
	// Frame-key derivation must be order-independent (both peers derive equal).
	if !bytes.Equal(syncDeriveFrameKey(key, n1, n2), syncDeriveFrameKey(key, n2, n1)) {
		t.Fatal("frame key derivation must be canonical/order-independent")
	}
}
