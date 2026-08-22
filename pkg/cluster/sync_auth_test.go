package cluster

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSyncAuthProvider is a test SyncAuthProvider that returns a fixed PSK.
//
// #5078: it also carried a settable HeartbeatPeerAuthSeen, the cross-channel
// downgrade-guard signal. That left the interface once syncPeerAuthSeen went,
// and with it the only caller that ever passed authSeen=true — the deleted
// TestSyncAuthHandshakeDowngradeGuardRejects.
type fakeSyncAuthProvider struct {
	key []byte
}

func (f *fakeSyncAuthProvider) ControlLinkAuthKey() []byte { return f.key }

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

func newAuthSync(t *testing.T, key []byte) *SessionSync {
	t.Helper()
	s := NewSessionSync(":0", ":0", nil)
	if key != nil {
		s.SetAuthProvider(&fakeSyncAuthProvider{key: key})
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
	a := newAuthSync(t, key)
	b := newAuthSync(t, key)

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
	a := newAuthSync(t, []byte("key-alpha"))
	b := newAuthSync(t, []byte("key-bravo-different"))

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
// it displaces the legitimate peer connection. A keyed node now rejects it.
//
// There is no migration window serving the legacy-compat need — an earlier
// draft of #5078 shipped one and it was removed; a rolling key rollout is
// handled by the procedure in pkg/cluster/README.md instead.
//
// RED on revert: make the legacy-peer ARM of performSyncHandshake return a nil
// error (i.e. hand the frame back instead of dropping the connection) and this
// test fails. This test is the SOLE catcher in pkg/cluster for that edit.
//
// It is deliberately NOT "restore the grace in syncAuthDecision" — that revert
// does NOT fail here, and the earlier comment claiming it would was wrong. The
// arm rejects unconditionally and discards the decision's accept bit (see
// sync_auth.go, "This arm rejects UNCONDITIONALLY"), so relaxing syncAuthDecision
// alone changes nothing on this path. That revert is caught instead by
// TestSyncAuthDecisionMatrix's legacy_peer_rejected_when_keyed /
// unkeyed_peer_rejected_when_keyed rows, and by nothing else. The two tests
// therefore cover DIFFERENT edits and neither is redundant.
func TestSyncAuthHandshakeKeyedNodeRejectsLegacyPeer(t *testing.T) {
	a := newAuthSync(t, []byte("psk"))

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
	// Assert the REASON, not just that some error occurred. A nil frame key is
	// the failure default of every error path in performSyncHandshake — a read
	// timeout, a short HELLO, a write failure all produce it — so `err != nil`
	// plus `key == nil` would still pass if the connection died for an
	// unrelated reason and never reached the legacy-peer arm at all. This
	// string is also the operator-facing diagnostic that arm exists to emit.
	if !strings.Contains(ar.err.Error(), "missing auth handshake") {
		t.Fatalf("rejection must come from the legacy-peer arm and name the cause; "+
			"got %q, want it to contain %q", ar.err.Error(), "missing auth handshake")
	}
	if ar.key != nil {
		t.Fatalf("a rejected handshake must yield no frame key")
	}
}

// writeSyncAuthHello writes a well-formed HELLO from the PEER side of a pipe,
// with the keyed byte under the caller's control. performSyncHandshake only
// ever emits keyed=1 (it returns early when it holds no key), so a keyed=0
// HELLO cannot be produced by running the real handshake on both ends — it has
// to be hand-built here. The version byte and the 32-byte nonce match what a
// real new-build peer sends, so the ONLY thing distinguishing the two callers
// below is the keyed advertisement.
func writeSyncAuthHello(t *testing.T, conn net.Conn, keyed byte, nonce []byte) {
	t.Helper()
	if len(nonce) != syncAuthNonceSize {
		t.Fatalf("test bug: nonce must be %d bytes, got %d", syncAuthNonceSize, len(nonce))
	}
	hello := make([]byte, 0, 2+syncAuthNonceSize)
	hello = append(hello, syncAuthVersion, keyed)
	hello = append(hello, nonce...)
	if err := writeMsg(conn, syncMsgAuthHello, hello); err != nil {
		t.Fatalf("peer failed to send HELLO(keyed=%d): %v", keyed, err)
	}
}

// TestSyncAuthHandshakeKeyedNodeRejectsUnkeyedHelloPeer covers the OTHER
// unauthenticated-admission arm of performSyncHandshake: a peer that speaks the
// handshake correctly but advertises keyed=0.
//
// This is the arm that literally IS the rolling-upgrade shape — a new build
// that has not been keyed yet — so it is the one an operator restoring
// rolling-upgrade compatibility edits first, and until this test existed
// nothing in pkg/cluster stopped them. Verified by mutation before the fix:
// replacing the whole arm body with `return syncAuthUnauthenticated, nil, nil`
// left the ENTIRE pkg/cluster suite GREEN. A PSK-less peer admitted there
// reaches syncMsgFence, which disables every routing group.
//
// TestSyncAuthDecisionMatrix does NOT reach this: it drives syncAuthDecision
// directly and never runs a handshake. TestSyncAuthHandshakeKeyedNodeRejects-
// LegacyPeer does not reach it either — it sends a real frame instead of a
// HELLO, so it exits at the `typ != syncMsgAuthHello` arm above and never
// evaluates peerKeyed.
//
// RED on revert: make this arm accept (return a nil error, the rolling-upgrade
// edit) and this test fails on "a keyed node must REJECT a peer advertising
// keyed=0". Note the arm's hardening is behavior-PRESERVING — restoring the
// old `if !accept { reject }` shape rejects identically, so that literal revert
// is green here by construction. What the hardening buys is that the accepting
// edit above is no longer one deleted `if` away; what this test buys is that
// the edit is no longer silent.
func TestSyncAuthHandshakeKeyedNodeRejectsUnkeyedHelloPeer(t *testing.T) {
	a := newAuthSync(t, []byte("psk"))

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca)

	// Read the keyed node's HELLO first — net.Pipe is unbuffered, and the
	// handshake blocks in <-writeErr until its HELLO is consumed.
	if typ, _, err := readSyncFrameRaw(cb); err != nil {
		t.Fatalf("peer failed to read HELLO: %v", err)
	} else if typ != syncMsgAuthHello {
		t.Fatalf("expected server HELLO type %d, got %d", syncMsgAuthHello, typ)
	}
	writeSyncAuthHello(t, cb, 0, bytes.Repeat([]byte{0xA5}, syncAuthNonceSize))

	ar := <-ach
	if ar.err == nil {
		t.Fatalf("a keyed node must REJECT a peer advertising keyed=0, got mode=%d key=%x", ar.mode, ar.key)
	}
	// Assert the REASON, not merely that some error occurred. Every error path
	// in performSyncHandshake returns (unauthenticated, nil, err) — a read
	// timeout, a short HELLO, a write failure all look identical here — so
	// `err != nil` alone would still pass if the connection died before ever
	// reaching the keyed=0 arm.
	if !strings.Contains(ar.err.Error(), "missing auth handshake") {
		t.Fatalf("rejection must come from the unkeyed-peer arm and name the cause; "+
			"got %q, want it to contain %q", ar.err.Error(), "missing auth handshake")
	}
	if ar.mode != syncAuthUnauthenticated {
		t.Fatalf("a rejected keyed=0 peer must not negotiate an authenticated mode, got %d", ar.mode)
	}
	if ar.key != nil {
		t.Fatalf("a rejected handshake must yield no frame key")
	}
}

// TestSyncAuthHandshakeKeyedHelloPeerStillAuthenticates is the OVER-REACH guard
// for the test above. It drives the same hand-built HELLO writer down the same
// pipe, changing exactly ONE byte — keyed 0 -> 1 — and then completes the
// challenge-response. The keyed peer must still authenticate and must still
// derive the shared frame key.
//
// Two things this pins that the rejection test cannot:
//   - the rejection is attributable to the keyed=0 ADVERTISEMENT, not to a
//     malformed frame or a fixture that never reached the handshake at all —
//     the identical construction with keyed=1 gets all the way to an
//     authenticated result;
//   - the fail-closed hardening did not over-reach into the keyed path.
//
// It stays GREEN under the keyed=0 arm's accepting mutation (that edit is
// unreachable from here), which is what makes it a guard rather than a
// restatement of the fix.
func TestSyncAuthHandshakeKeyedHelloPeerStillAuthenticates(t *testing.T) {
	key := []byte("psk")
	a := newAuthSync(t, key)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca)

	typ, payload, err := readSyncFrameRaw(cb)
	if err != nil {
		t.Fatalf("peer failed to read HELLO: %v", err)
	}
	if typ != syncMsgAuthHello {
		t.Fatalf("expected server HELLO type %d, got %d", syncMsgAuthHello, typ)
	}
	if len(payload) < 2+syncAuthNonceSize {
		t.Fatalf("server HELLO too short: %d bytes", len(payload))
	}
	if payload[1] == 0 {
		t.Fatalf("a keyed node must advertise keyed=1, got keyed=%d", payload[1])
	}
	serverNonce := append([]byte(nil), payload[2:2+syncAuthNonceSize]...)

	peerNonce := bytes.Repeat([]byte{0xA5}, syncAuthNonceSize)
	writeSyncAuthHello(t, cb, 1, peerNonce)

	// The node proves over OUR nonce; we prove over ITS nonce.
	ptyp, ppayload, err := readSyncFrameRaw(cb)
	if err != nil {
		t.Fatalf("peer failed to read PROOF: %v", err)
	}
	if ptyp != syncMsgAuthProof {
		t.Fatalf("expected PROOF type %d, got %d", syncMsgAuthProof, ptyp)
	}
	if !hmac.Equal(ppayload, syncAuthProof(key, peerNonce)) {
		t.Fatalf("node's proof does not verify over our nonce")
	}
	if err := writeMsg(cb, syncMsgAuthProof, syncAuthProof(key, serverNonce)); err != nil {
		t.Fatalf("peer failed to send PROOF: %v", err)
	}

	ar := <-ach
	if ar.err != nil {
		t.Fatalf("a keyed peer with a good proof must be ACCEPTED, got %v", ar.err)
	}
	if ar.mode != syncAuthAuthenticated {
		t.Fatalf("expected authenticated mode, got %d", ar.mode)
	}
	if want := syncDeriveFrameKey(key, serverNonce, peerNonce); !bytes.Equal(ar.key, want) {
		t.Fatalf("frame key mismatch: got %x, want %x", ar.key, want)
	}
}

// TestSyncAuthHandshakeDowngradeGuardRejects was DELETED here.
//
// It claimed to verify the downgrade-guard — "once the peer has authenticated
// (here via the heartbeat channel, authSeen=true), a later UNAUTHENTICATED
// connection is REJECTED rather than silently downgraded" — with a documented
// "RED on revert: without the guard the legacy peer is dual-accepted".
//
// That was false by the time #5078 landed. Flipping its single precondition,
// newAuthSync(t, []byte("psk"), true) -> false, left it PASSING: the guard was
// disarmed and the assertion still held, because syncAuthDecision now rejects
// EVERY unkeyed peer on a keyed node regardless of peerAuthSeen. The test was
// therefore a duplicate of TestSyncAuthHandshakeKeyedNodeRejectsLegacyPeer
// wearing a downgrade-guard name, and its stated RED-on-revert could not fire.
//
// A test whose documented failure mode cannot occur is worse than no test: it
// reads as coverage for a property nothing checks. The unconditional rejection
// it actually exercised is pinned by TestSyncAuthHandshakeKeyedNodeRejectsLegacyPeer
// and by the legacy_peer_rejected_when_keyed / unkeyed_peer_rejected_when_keyed
// rows of TestSyncAuthDecisionMatrix, so deleting it loses no coverage.
//
// The sync-side downgrade guard it was named for no longer exists — see the
// removal of syncPeerAuthSeen / syncAuthedEver. The #4107 HEARTBEAT downgrade
// guard is separate state (heartbeatAuthState.peerAuthenticated, reached via
// Manager.HeartbeatPeerAuthSeen) and is unaffected; it keeps its own coverage
// in heartbeat_auth_test.go.

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
// unauthenticated peer. There is NO migration window: an earlier draft of
// #5078 shipped a bounded dual-accept knob and it was deleted, so the
// rolling-rollout case is served by the operator procedure in
// pkg/cluster/README.md instead.
//
// RED on revert: add any unconditional accept for an unkeyed peer on a keyed
// node — the `peerAuthSeen` parameter this decision used to take is gone, so
// the revert is now "return accept=true from the final arm" — and
// legacy_peer_rejected_when_keyed / unkeyed_peer_rejected_when_keyed fail.
// This matrix is the sole catcher for that edit; the handshake test above
// catches a different one (the arm's own unconditional rejection).
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

// TestSyncAuthHandshakeRejectsReflectedNonce_5078 drives the #5078 vector-A
// reflection attack end-to-end against the real performSyncHandshake: a
// PSK-less attacker that holds no key, computes no HMAC, and simply ECHOES
// every frame the node sends straight back at it.
//
// Measured on origin/master a77d5568c BEFORE this guard existed, that echo
// returned `mode=syncAuthAuthenticated, err=nil` with a full 32-byte frame key
// derived — the node believed a byte-mirror was its keyed peer. That is the
// entire exploit; there is nothing else the attacker has to do.
//
// Two properties of the fixture are load-bearing, and both were WRONG in the
// first draft of this test:
//
//   - The attacker is a pure mirror (`writeMsg(cb, typ, payload)` on the bytes
//     just read), not a hand-built HELLO carrying the node's nonce. A
//     hand-built fixture would be keyed to the repair; the mirror is the
//     attacker's actual capability, so this binds the PROPERTY (an echo cannot
//     authenticate) rather than the mechanism that stops it.
//   - The mirror runs to COMPLETION in a goroutine, echoing frames until the
//     pipe closes. A fixture that echoed only the HELLO and then waited did
//     red under mutation — but at 3.00s with "read pipe: i/o timeout", i.e. it
//     proved only that the node stopped talking, never that the attack failed.
//     With the loop, a mutated node completes the whole handshake and this
//     test fails on the authentication itself.
//
// RED on revert: neuter the `bytes.Equal(peerNonce, localNonce)` arm of
// syncCheckPeerNonce, or drop its call from performSyncHandshake, and the echo
// authenticates again — failing on "a byte-echo attacker must NOT
// authenticate", not on a timeout.
//
// Scope, stated so a green here is not over-read: this closes vector A only.
// Vector B — a second keyed connection used as a proof oracle, where the two
// nonces differ and nothing here fires — is NOT closed, and cannot be without
// binding role/identity/transcript into the proof (a wire flag-day). #5078
// stays open for exactly that.
func TestSyncAuthHandshakeRejectsReflectedNonce_5078(t *testing.T) {
	a := newAuthSync(t, []byte("shared-control-link-secret-key"))

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca)

	// The attacker's ENTIRE algorithm: read a frame, write it back verbatim,
	// forever. It never touches a key and never parses a payload. net.Pipe is
	// unbuffered, so each read unblocks the node's concurrent write before the
	// echo goes out.
	attackerDone := make(chan struct{})
	go func() {
		defer close(attackerDone)
		for {
			typ, payload, err := readSyncFrameRaw(cb)
			if err != nil {
				return
			}
			if err := writeMsg(cb, typ, payload); err != nil {
				return
			}
		}
	}()

	ar := <-ach
	cb.Close() // release the mirror, which is parked in a read
	<-attackerDone

	if ar.err == nil {
		t.Fatalf("a byte-echo attacker must NOT authenticate (#5078 vector A): "+
			"got mode=%d frameKey=%x", ar.mode, ar.key)
	}
	// Assert the REASON, not merely that some error occurred. Every failure
	// path in performSyncHandshake returns (unauthenticated, nil, err) — a read
	// timeout, a short HELLO and a write error are indistinguishable from
	// `err != nil` alone. This assertion is what turned the first draft's
	// dishonest 3-second timeout red into a real one.
	if !strings.Contains(ar.err.Error(), "reflected handshake nonce") {
		t.Fatalf("rejection must come from the reflected-nonce arm and name the cause; "+
			"got %q, want it to contain %q", ar.err.Error(), "reflected handshake nonce")
	}
	if ar.key != nil {
		t.Fatalf("a rejected handshake must yield no frame key, got %x", ar.key)
	}
	if ar.mode == syncAuthAuthenticated {
		t.Fatalf("a rejected handshake must not report authenticated mode")
	}
}

// TestSyncAuthHandshakeRejectsZeroNonce_5078 covers the OTHER degenerate nonce:
// a peer that is valid in every other respect — it holds the PSK, advertises
// keyed=1, and returns a correct proof over the node's nonce — but offers an
// all-zero challenge. That is what a peer whose CSPRNG never seeded emits.
//
// The peer here is deliberately a FULL, key-holding participant rather than a
// fixture that sends a HELLO and stops. With a passive fixture the mutation red
// was "read pipe: i/o timeout" at the 3s handshake deadline: it showed the node
// went quiet, not that a zero-nonce peer is refused. Playing the handshake out
// means a node with the check removed AUTHENTICATES this peer, and the test
// then fails on the admission itself.
//
// Read against TestSyncAuthHandshakeKeyedHelloPeerStillAuthenticates, which is
// byte-identical apart from using a 0xA5 nonce and expecting success: the nonce
// VALUE is the only variable between the two, so this pair localises the
// rejection to the zero-nonce arm and simultaneously proves the arm does not
// over-reach into ordinary keyed peers.
//
// Separate from the reflection test on purpose: the two arms are two
// independent lines in syncCheckPeerNonce, and one fixture covering both could
// not localise — a compound probe reds on whichever arm is bound and masks the
// other. The zero nonce differs from the node's crypto/rand localNonce, so the
// reflection arm cannot fire here.
//
// RED on revert: neuter the `bytes.Equal(peerNonce, syncAuthZeroNonce)` arm and
// the zero-nonce peer authenticates. Claimed value is hygiene, not a live
// bypass — this peer holds the PSK, so it was entitled to authenticate; what
// the arm refuses is letting a predictable challenge into the transcript.
func TestSyncAuthHandshakeRejectsZeroNonce_5078(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	a := newAuthSync(t, key)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca)

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		// t.Errorf, never t.Fatalf: this is not the test goroutine, and a
		// Fatalf here would leave the handshake result unread.
		typ, payload, err := readSyncFrameRaw(cb)
		if err != nil {
			t.Errorf("peer failed to read HELLO: %v", err)
			return
		}
		if typ != syncMsgAuthHello || len(payload) < 2+syncAuthNonceSize {
			t.Errorf("expected a well-formed server HELLO, got type=%d len=%d", typ, len(payload))
			return
		}
		serverNonce := append([]byte(nil), payload[2:2+syncAuthNonceSize]...)

		writeSyncAuthHello(t, cb, 1, make([]byte, syncAuthNonceSize))

		// A node with the zero-nonce arm removed answers with its PROOF here;
		// a correct node has already dropped the connection, so this read
		// fails and the peer simply stops. Both outcomes are expected — the
		// assertion lives on the handshake result, not in this goroutine.
		if _, _, err := readSyncFrameRaw(cb); err != nil {
			return
		}
		// Complete the exchange as an honest key-holder would, so that a
		// mutated node has everything it needs to authenticate.
		if err := writeMsg(cb, syncMsgAuthProof, syncAuthProof(key, serverNonce)); err != nil {
			return
		}
	}()

	ar := <-ach
	cb.Close()
	<-peerDone

	if ar.err == nil {
		t.Fatalf("an all-zero challenge nonce must be REJECTED (#5078) even from a "+
			"key-holding peer: got mode=%d key=%x", ar.mode, ar.key)
	}
	if !strings.Contains(ar.err.Error(), "all-zero handshake nonce") {
		t.Fatalf("rejection must come from the zero-nonce arm and name the cause; "+
			"got %q, want it to contain %q", ar.err.Error(), "all-zero handshake nonce")
	}
	if ar.key != nil {
		t.Fatalf("a rejected handshake must yield no frame key, got %x", ar.key)
	}
}
