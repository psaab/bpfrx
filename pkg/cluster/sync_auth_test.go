package cluster

import (
	"bytes"
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
	key    []byte
	node   int
	cluster int
}

func (f *fakeSyncAuthProvider) ControlLinkAuthKey() []byte { return f.key }

// #7163: the Noise prologue binds cluster/node identity, so the fake supplies
// it. fakeSyncAuthProviderNoIdentity below deliberately does NOT — it exists to
// prove the handshake refuses to run unbound rather than defaulting to zeros.
func (f *fakeSyncAuthProvider) NodeID() int    { return f.node }
func (f *fakeSyncAuthProvider) ClusterID() int { return f.cluster }

// fakeSyncAuthProviderNoIdentity is a provider that satisfies SyncAuthProvider
// but NOT SyncIdentityProvider.
type fakeSyncAuthProviderNoIdentity struct{ key []byte }

func (f *fakeSyncAuthProviderNoIdentity) ControlLinkAuthKey() []byte { return f.key }

type handshakeResult struct {
	mode syncAuthMode
	key  syncNoiseKeys
	err  error
}

func runHandshake(s *SessionSync, conn net.Conn, initiator bool) <-chan handshakeResult {
	ch := make(chan handshakeResult, 1)
	go func() {
		mode, key, err := s.performSyncHandshake(conn, initiator, 0)
		ch <- handshakeResult{mode: mode, key: key, err: err}
	}()
	return ch
}

func newAuthSync(t *testing.T, key []byte) *SessionSync {
	t.Helper()
	return newAuthSyncNode(t, key, 0)
}

// newAuthSyncNode builds a SessionSync whose provider reports the given node
// id. #7163: the two ends of a handshake must disagree about node id the way
// real nodes do (0 and 1), because the prologue binds ROLE-ORDERED ids and a
// pair that agreed on both would not exercise the ordering at all.
func newAuthSyncNode(t *testing.T, key []byte, node int) *SessionSync {
	t.Helper()
	s := NewSessionSync(":0", ":0", nil)
	if key != nil {
		s.SetAuthProvider(&fakeSyncAuthProvider{key: key, node: node, cluster: 22})
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
	// #7163: the two ends must be DIFFERENT nodes. The prologue binds
	// role-ordered node ids, so a fixture that gave both ends the same id would
	// build mismatched prologues and fail — which is the binding working, not a
	// bug. Real nodes are 0 and 1.
	a := newAuthSyncNode(t, key, 0)
	b := newAuthSyncNode(t, key, 1)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)  // dialer => Noise initiator
	bch := runHandshake(b, cb, false) // accepter => Noise responder

	ar := <-ach
	br := <-bch

	if ar.err != nil || br.err != nil {
		t.Fatalf("handshake errored: a=%v b=%v", ar.err, br.err)
	}
	if ar.mode != syncAuthAuthenticated || br.mode != syncAuthAuthenticated {
		t.Fatalf("expected both authenticated, got a=%d b=%d", ar.mode, br.mode)
	}
	// #7163: the two directions must derive INDEPENDENT keys, and A's write
	// direction must match B's read direction (and vice versa). Before this
	// change one key covered both, which is what let a node's own frame verify
	// when echoed back at it.
	if len(ar.key.writeKey) == 0 || len(ar.key.readKey) == 0 {
		t.Fatalf("frame keys must be non-empty: %+v", ar.key)
	}
	if bytes.Equal(ar.key.readKey, ar.key.writeKey) {
		t.Fatalf("THE VECTOR B FIX: the two directions derived the SAME key (%x). "+
			"A single key covering both directions is exactly what makes a node's own "+
			"syncMsgFence verify when reflected back to it on the same connection.",
			ar.key.readKey)
	}
	if bytes.Equal(br.key.readKey, br.key.writeKey) {
		t.Fatalf("responder derived one key for both directions: %x", br.key.readKey)
	}
	if !bytes.Equal(ar.key.writeKey, br.key.readKey) {
		t.Fatalf("A's write key must equal B's read key: %x vs %x", ar.key.writeKey, br.key.readKey)
	}
	if !bytes.Equal(ar.key.readKey, br.key.writeKey) {
		t.Fatalf("A's read key must equal B's write key: %x vs %x", ar.key.readKey, br.key.writeKey)
	}

	// A sealed session frame must round-trip across the directional pair.
	sender := &authConn{Conn: ca, readKey: ar.key.readKey, writeKey: ar.key.writeKey}
	receiver := &authConn{Conn: cb, readKey: br.key.readKey, writeKey: br.key.writeKey}
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

	ach := runHandshake(a, ca, true)  // dialer => Noise initiator
	bch := runHandshake(b, cb, false) // accepter => Noise responder

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

	ach := runHandshake(a, ca, true)

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
	// #7163: the reason string moved with the construction. The property the
	// original assertion protected is UNCHANGED and still asserted — the
	// rejection must be attributable to the handshake refusing this peer's
	// frame, not to an unrelated death (a read timeout, a write failure), all
	// of which also produce an error and empty keys. Under Noise the
	// attributable diagnostic is the frame the peer sent where a Noise message
	// was required.
	if !strings.Contains(ar.err.Error(), "noise") {
		t.Fatalf("rejection must come from the Noise handshake and name the cause; "+
			"got %q, want it to mention the noise exchange", ar.err.Error())
	}
	if len(ar.key.readKey) != 0 || len(ar.key.writeKey) != 0 {
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

	ach := runHandshake(a, ca, true)

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
	// #7163: see the note in the legacy-peer test above. An unkeyed peer can no
	// longer announce itself with a keyed=0 flag — there is no such field in a
	// Noise exchange — so it simply cannot produce a valid msg2, and that is
	// what the rejection must be attributable to.
	if !strings.Contains(ar.err.Error(), "noise") {
		t.Fatalf("rejection must come from the Noise handshake and name the cause; "+
			"got %q, want it to mention the noise exchange", ar.err.Error())
	}
	if ar.mode != syncAuthUnauthenticated {
		t.Fatalf("a rejected keyed=0 peer must not negotiate an authenticated mode, got %d", ar.mode)
	}
	if len(ar.key.readKey) != 0 || len(ar.key.writeKey) != 0 {
		t.Fatalf("a rejected handshake must yield no frame key")
	}
}

func TestSyncAuthDisabledNoHandshake(t *testing.T) {
	s := NewSessionSync(":0", ":0", nil) // no provider

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	// If performSyncHandshake performed any I/O it would block on the pipe; a
	// watchdog guarantees the test fails loudly instead of hanging.
	done := make(chan handshakeResult, 1)
	go func() {
		mode, key, err := s.performSyncHandshake(ca, true, 0)
		done <- handshakeResult{mode: mode, key: key, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("disabled handshake errored: %v", r.err)
		}
		if r.mode != syncAuthUnauthenticated || len(r.key.readKey) != 0 {
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
	send := &authConn{readKey: key, writeKey: key}
	recv := &authConn{readKey: key, writeKey: key}

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
	recv2 := &authConn{readKey: key, writeKey: key}
	tampered := append([]byte(nil), p2...)
	tampered[0] ^= 0xFF
	if err := recv2.verifyFrame(h2, tampered, tr2); err != errSyncFrameAuth {
		t.Fatalf("tampered payload must fail HMAC, got %v", err)
	}

	// Wrong key must fail the HMAC.
	recv3 := &authConn{readKey: []byte("wrong-key"), writeKey: []byte("wrong-key")}
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


// #7163 SUPERSESSION NOTE. Four tests were removed from this file by the Noise
// conversion, and they are recorded here rather than deleted quietly, because
// three of them were the #5078/#7152 attack guards and a reader must be able to
// see where that coverage went:
//
//   - TestSyncAuthHandshakeKeyedHelloPeerStillAuthenticates asserted that a
//     peer speaking the legacy HELLO/PROOF exchange is ACCEPTED. That is the
//     opposite of the flag-day contract; it is replaced by
//     TestNoiseHandshakeRejectsLegacyPeer7163 below.
//   - TestSyncAuthProofBindsToNonce characterised syncAuthProof, which no
//     longer exists. Binding is now structural (prologue + transcript), and
//     TestNoiseHandshakeBindsIdentity7163 asserts the property that mattered:
//     two ends that disagree about identity cannot derive a common key.
//   - TestSyncAuthHandshakeRejectsReflectedNonce_5078 and
//     TestSyncAuthHandshakeRejectsZeroNonce_5078 guarded vector A by rejecting
//     a reflected/degenerate NONCE. There are no nonces to reflect any more —
//     the initiator and responder derive from a Diffie-Hellman exchange mixed
//     with the PSK — so the guard is replaced by
//     TestNoiseHandshakeRejectsReflectedMessage7163, which reflects the actual
//     handshake message and asserts it is refused.
//
// Deleting the three attack guards without replacements would have decommissioned
// the vector A coverage while the suite stayed green.

// TestNoiseHandshakeRejectsLegacyPeer7163 pins the FLAG DAY. A pre-#7163 peer
// sends the legacy HELLO, which is not a valid Noise message, and must be
// refused rather than silently downgraded to an unauthenticated stream.
func TestNoiseHandshakeRejectsLegacyPeer7163(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	a := newAuthSyncNode(t, key, 0)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)

	// Consume our msg1 and answer with a legacy-shaped HELLO.
	go func() {
		_, _, _ = readSyncFrameRaw(cb)
		legacy := make([]byte, 2+syncAuthNonceSize)
		legacy[0], legacy[1] = 1, 1
		_ = writeMsg(cb, syncMsgAuthHello, legacy)
	}()

	ar := <-ach
	if ar.err == nil {
		t.Fatal("a legacy peer was ACCEPTED. This is a flag day: the old handshake " +
			"must not interoperate, or an operator gets a silently unauthenticated " +
			"fabric instead of a refused one.")
	}
	if ar.mode == syncAuthAuthenticated {
		t.Fatalf("legacy peer negotiated authenticated mode: %d", ar.mode)
	}
}

// TestNoiseHandshakeRejectsReflectedMessage7163 replaces the vector A nonce
// guards. The attacker reflects the initiator's own handshake message back at
// it — the modern form of the same attack — and it must not authenticate.
func TestNoiseHandshakeRejectsReflectedMessage7163(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	a := newAuthSyncNode(t, key, 0)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)

	go func() {
		_, msg1, err := readSyncFrameRaw(cb)
		if err != nil {
			return
		}
		// Echo msg1 straight back as if it were msg2.
		_ = writeMsg(cb, syncMsgAuthProof, msg1)
	}()

	ar := <-ach
	if ar.err == nil {
		t.Fatal("a REFLECTED handshake message authenticated. The initiator accepted " +
			"its own message as the responder's, which is vector A in its modern form.")
	}
}

// TestNoiseHandshakeBindsIdentity7163 asserts the property the deleted
// proof-binding test cared about: identity is inside the transcript, so two
// ends that disagree about it cannot derive a common key.
//
// The discriminator is a CLUSTER-ID mismatch with an identical PSK. If identity
// were not bound, the shared PSK alone would complete the handshake and both
// sides would key up — which is precisely the pre-#7163 behaviour.
func TestNoiseHandshakeBindsIdentity7163(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	a := newAuthSyncNode(t, key, 0)
	b := newAuthSyncNode(t, key, 1)

	// Same PSK, DIFFERENT cluster id on b.
	b.SetAuthProvider(&fakeSyncAuthProvider{key: key, node: 1, cluster: 99})

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)
	bch := runHandshake(b, cb, false)
	ar, br := <-ach, <-bch

	if ar.err == nil && br.err == nil {
		t.Fatal("two nodes with the SAME PSK but DIFFERENT cluster ids completed the " +
			"handshake. Identity is not bound into the transcript, so the prologue is " +
			"not doing its job and a node could be keyed into the wrong cluster.")
	}
}

// TestNoiseHandshakeRefusesWithoutIdentity7163 pins the FAIL-CLOSED path. A
// provider that cannot answer for identity must stop the handshake, not default
// to zeros — a zero prologue is well-formed, binds nothing, and would be
// identical on both nodes, so the handshake would SUCCEED with the identity
// binding silently absent. That is the "silently does not run" shape this whole
// issue exists to remove, and it must not be re-introduced by the fix.
func TestNoiseHandshakeRefusesWithoutIdentity7163(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	s := NewSessionSync(":0", ":0", nil)
	s.SetAuthProvider(&fakeSyncAuthProviderNoIdentity{key: key})

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	_, _, err := s.performSyncHandshake(ca, true, 0)
	if err == nil {
		t.Fatal("a provider with no identity produced a handshake. It must refuse: a " +
			"defaulted zero prologue binds nothing while looking perfectly healthy.")
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("error should name the missing identity, got: %v", err)
	}
}
