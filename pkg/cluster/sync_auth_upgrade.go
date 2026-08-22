package cluster

// In-place authentication upgrade for an established session-sync connection
// (#6628).
//
// THE DEFECT. `performSyncHandshake` selects authentication ONCE, when the TCP
// connection is created, and `wrapSyncConn` fixes that connection's posture for
// its whole lifetime. Committing a key updates the manager's key but does NOT
// tear the connection down: the restart decision compares
// `clusterTransportKey`, which excludes the auth key — an exclusion that is
// deliberate and pinned (TestAuthKeyChangeDoesNotRestartClusterComms_5078),
// because the established connection is what carries the key to a READ-ONLY
// secondary (`EnterConfigureSession` returns ErrClusterReadOnly there, so
// config-sync is that node's only writer).
//
// So an unkeyed session-sync stream stays unkeyed INDEFINITELY after the key is
// committed. Legitimate traffic stays unsigned until an incidental disconnect
// or a daemon restart, and a rotation never rekeys an existing connection.
// pkg/cluster/README.md records the operator consequence: "the restart in step
// 3 is not optional".
//
// WHAT THIS CLOSES, AND WHAT IT DOES NOT.
//
// Closed — the two properties about the LEGITIMATE peer:
//
//   - an established unkeyed stream becomes authenticated once both ends hold
//     the same key, with no restart and no disconnect;
//   - a key rotation rekeys the live connection instead of leaving it on a
//     frame key derived from the retired PSK.
//
// NOT closed — a HOSTILE stream admitted before the commit keeps injecting
// frames. A hostile peer declines the upgrade by never answering, and a peer
// that declines is INDISTINGUISHABLE from a legitimate peer that is not keyed
// yet, which is the rolling-upgrade case this must not break. The
// indistinguishability is the problem; a timer is not the missing piece.
// Closing it needs a bounded window after which an un-upgraded connection is
// dropped, and #5078 shipped and then REMOVED exactly such a window for three
// reasons any future attempt must answer: it had to bound a connection's
// LIFETIME rather than just its admission, it had to stop an admitted peer
// re-arming it through config-sync, and it could not survive a crash loop
// without persisting its deadline. Tracked separately; not attempted here.
//
// NEVER DROPS. Every failure path — no key, wrong key, malformed frame, a peer
// that does not answer — leaves the connection exactly as it was. That is the
// property that makes this a strict improvement rather than a trade.
//
// THIS IS A MID-STREAM KEY SWITCH, not merely an "upgrade". There is a live
// frame stream in both directions and the switch point has to be exact.
// `authConn` used ONE key field with a single `authed()` gating both
// receiveLoop's "read and verify a trailer" and writeMsg's "seal", so flipping
// it promotes both directions on one end at the same instant: that end starts
// requiring a trailer while the peer is still sending unsealed frames,
// consumes syncAuthFrameTrailerSize bytes of the NEXT frame as a trailer, fails
// the MAC, and DROPS the connection. The key is therefore split per direction
// (authConn.readKey / writeKey) and each side switches at the boundary the
// peer switched at. TCP preserves order within a direction, so a frame is an
// unambiguous boundary.
//
// THE EXCHANGE, and why it takes four frames rather than three.
//
//	I (initiator)                         R (responder)
//	-- Hello{nI} --------------------->
//	                                      <-- Proof{proof_R(nI), nR} --
//	                                      R switches NOTHING yet
//	I verifies proof over nI. That
//	verification PROVES R holds the
//	same key, so I's own proof is
//	certain to verify at R.
//	-- Proof{proof_I(nR), nI} -------->
//	I sets writeKey after that write
//	                                      R verifies proof over nR,
//	                                      sets readKey (this frame IS
//	                                      the boundary), then:
//	                                      <-- Ack --
//	                                      R sets writeKey after that write
//	I receives Ack, sets readKey
//	(that frame IS the boundary)
//
// The obvious three-frame version — R switches its write direction right after
// sending its Proof — is UNSAFE, and the case that breaks it is a botched
// rotation rather than an exotic one. If the two nodes hold DIFFERENT keys, R
// has proven nothing when it switches; I's verification of R's proof fails, I
// never switches, and R's next sealed frame arrives at a reader that is not
// expecting a trailer. Frame desync, connection dropped — by the mechanism
// whose entire premise is that it never drops. Deferring R's switch until it
// has verified I's proof means NEITHER side ever switches until key equality
// is mutually proven.
//
// SIMULTANEOUS INITIATION needs no special case and no timer. Both nodes may
// commit at once and both send a Hello. Each then knows both nonces, and the
// role is decided by comparing them: the SMALLER nonce initiates. Both sides
// compute the same assignment from the same two values, so exactly one Proof-
// first exchange runs. Equal nonces cannot arise from 32 bytes of crypto/rand
// and are refused anyway by syncCheckPeerNonce, which is the #5078 reflection
// guard and applies here for the same reason: this node emits a proof over the
// peer's nonce, so a reflected or degenerate nonce must be refused BEFORE the
// proof is computed.
//
// CONCURRENCY. writeKey is installed under SessionSync.writeMu — already the
// invariant serialising every write to a connection — inside the same critical
// section as the frame that precedes it, so no frame can slip out between the
// proof and the switch and no concurrent seal can race the install. readKey and
// the exchange state are touched only by the single receiveLoop goroutine that
// owns the connection, except where noted under writeMu.
//
// MIXED VERSION. The frames are additive types with no wire-version bump; the
// receive switch has no default arm, so a peer that predates this ignores them,
// never answers, and stays un-upgraded — the intended behaviour, not a failure.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
)

// syncAuthUpgradeVersion is the in-place upgrade wire version. A peer that does
// not recognise it is left un-upgraded, never dropped.
const syncAuthUpgradeVersion = 1

// errUpgradeNotApplicable means there is nothing to upgrade on this connection
// — not an authConn, an exchange already in flight, or already authenticated
// under the current key. Never surfaced to the operator.
var errUpgradeNotApplicable = errors.New("cluster sync: auth upgrade not applicable")

// ReconcileConnectionAuth re-evaluates the authentication posture of every
// installed session-sync connection against the CURRENT control-link key and
// starts an in-place upgrade on any whose posture is stale (#6628).
//
// Level-triggered: it re-reads the live key and the live connections on every
// call, so a call with nothing to do is a cheap no-op (two pointer reads and a
// bytes.Equal) and a missed trigger heals on the next one. The daemon calls it
// after a config apply.
//
// It never closes a connection.
func (s *SessionSync) ReconcileConnectionAuth(reason string) {
	key := s.authKey()
	if len(key) == 0 {
		// The key was cleared, or none was ever set. An already-authenticated
		// connection is deliberately left sealing: tearing its authentication
		// down because of a config edit would be a DOWNGRADE, and the peer
		// would reject the unsealed frames anyway. Clearing takes effect on
		// the next connection.
		return
	}
	s.mu.Lock()
	conns := []net.Conn{s.conn0, s.conn1}
	s.mu.Unlock()
	for _, c := range conns {
		if c == nil {
			continue
		}
		err := s.beginAuthUpgrade(c, key, reason)
		if err != nil && !errors.Is(err, errUpgradeNotApplicable) {
			slog.Warn("cluster sync: could not start the in-place auth upgrade; the connection "+
				"stays exactly as it is (#6628)", "reason", reason, "err", err,
				"remote", connRemoteAddrString(c))
		}
	}
}

// beginAuthUpgrade emits an UpgradeHello on conn when its posture is stale.
func (s *SessionSync) beginAuthUpgrade(conn net.Conn, key []byte, reason string) error {
	ac, ok := conn.(*authConn)
	if !ok {
		return errUpgradeNotApplicable
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if bytes.Equal(ac.authPSK, key) {
		// Already authenticated under exactly this key. This is the check that
		// makes the reconciler safe to call on every commit: without it an
		// unrelated config change would restart the exchange on a healthy
		// authenticated connection.
		return errUpgradeNotApplicable
	}
	if !ac.beginUpgradeExchangeLocked(key) {
		// An exchange for THIS key is already in flight. Re-emitting a Hello
		// would mint a second nonce and leave the peer proving over a
		// challenge we no longer hold. State from an exchange for an OLDER key
		// has just been cleared, so a rotation is not blocked by it.
		return errUpgradeNotApplicable
	}
	nonce := make([]byte, syncAuthNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ac.upgradeNonce = nonce
	payload := make([]byte, 0, 1+syncAuthNonceSize)
	payload = append(payload, syncAuthUpgradeVersion)
	payload = append(payload, nonce...)
	if err := writeMsg(conn, syncMsgAuthUpgradeHello, payload); err != nil {
		// Leave the nonce set: the connection is failing and will drop, and a
		// retry on a dying connection buys nothing.
		return err
	}
	slog.Info("cluster sync: starting the in-place authentication upgrade on an established "+
		"connection (#6628)", "reason", reason, "remote", connRemoteAddrString(conn))
	return nil
}

// upgradeIAmResponder decides this node's role once both nonces are known.
// The SMALLER nonce initiates; both sides compute the same answer from the
// same two values, so a simultaneous initiation converges with no tie-break
// message and no timer.
func upgradeIAmResponder(localNonce, peerNonce []byte) bool {
	return bytes.Compare(localNonce, peerNonce) > 0
}

// handleAuthUpgradeHello answers a peer's challenge when this node is the
// responder. It switches NOTHING: see the four-frame rationale in the file
// header — a responder that switched here would desync the stream whenever the
// two nodes hold different keys.
//
// Runs on the receiveLoop goroutine that owns conn.
func (s *SessionSync) handleAuthUpgradeHello(conn net.Conn, payload []byte) {
	ac, ok := conn.(*authConn)
	if !ok {
		return
	}
	if len(payload) < 1+syncAuthNonceSize || payload[0] != syncAuthUpgradeVersion {
		slog.Warn("cluster sync: malformed or unsupported auth-upgrade hello; leaving the "+
			"connection as it is (#6628)", "len", len(payload))
		return
	}
	key := s.authKey()
	if len(key) == 0 {
		// Not keyed here yet — the rolling-upgrade case. Silence is the right
		// answer: the peer keeps its connection, unauthenticated, exactly as
		// today, and a later commit on this node starts our own Hello.
		return
	}
	peerNonce := payload[1 : 1+syncAuthNonceSize]

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// A Hello always belongs to the peer's CURRENT key, and we answer with
	// ours; state from an exchange under a key we have rotated away from must
	// not block that. The return value is ignored on purpose — an in-flight
	// exchange for this key is exactly the simultaneous-initiation case, which
	// the role decision below resolves.
	_ = ac.beginUpgradeExchangeLocked(key)
	if ac.upgradePeerNonce == nil {
		ac.upgradePeerNonce = append([]byte(nil), peerNonce...)
	}
	if ac.upgradeNonce != nil && !upgradeIAmResponder(ac.upgradeNonce, ac.upgradePeerNonce) {
		// We also sent a Hello and ours sorts first: we are the INITIATOR.
		// Wait for the responder's proof rather than answering, so exactly one
		// side proves first.
		return
	}
	s.emitUpgradeProofLocked(ac, key, ac.upgradePeerNonce)
}

// handleAuthUpgradeProof verifies the peer's proof and advances the exchange.
//
// The verification is the load-bearing step: a proof over OUR nonce that
// verifies under OUR key PROVES the peer holds the same key. Only after that
// does this node commit to any switch, which is what keeps a key mismatch from
// desyncing the stream.
//
// Runs on the receiveLoop goroutine that owns conn.
func (s *SessionSync) handleAuthUpgradeProof(conn net.Conn, payload []byte) {
	ac, ok := conn.(*authConn)
	if !ok {
		return
	}
	if len(payload) < 1+syncAuthProofLen+syncAuthNonceSize || payload[0] != syncAuthUpgradeVersion {
		slog.Warn("cluster sync: malformed or unsupported auth-upgrade proof; leaving the "+
			"connection as it is (#6628)", "len", len(payload))
		return
	}
	key := s.authKey()
	if len(key) == 0 {
		return
	}
	proof := payload[1 : 1+syncAuthProofLen]
	peerNonce := payload[1+syncAuthProofLen : 1+syncAuthProofLen+syncAuthNonceSize]

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	localNonce := ac.upgradeNonce
	if localNonce == nil {
		slog.Warn("cluster sync: auth-upgrade proof with no outstanding challenge; ignoring (#6628)")
		return
	}
	if !hmac.Equal(proof, syncAuthProof(key, localNonce)) {
		// The peer holds a different key, or is not the peer. Nothing has
		// switched on either side, so leaving the connection alone costs
		// nothing and loses nothing.
		slog.Warn("cluster sync: auth-upgrade proof did not verify — the peer holds a "+
			"different control-link key; the connection stays in its current posture (#6628)",
			"remote", connRemoteAddrString(conn))
		return
	}
	if ac.upgradePeerNonce == nil {
		ac.upgradePeerNonce = append([]byte(nil), peerNonce...)
	}
	if err := syncCheckPeerNonce(localNonce, ac.upgradePeerNonce); err != nil {
		slog.Warn("cluster sync: refusing the auth-upgrade peer nonce (#6628)", "err", err)
		return
	}
	// Key equality is now PROVEN. This is the flag that authorises a switch;
	// nothing switches on either side before it is set on that side.
	ac.upgradePeerVerified = true

	if !ac.upgradeProofSent {
		// We are the INITIATOR and this is the responder's proof. Key equality
		// is now proven, so our proof is certain to verify there. Send it and
		// switch our WRITE direction immediately after that write; our READ
		// direction waits for the responder's Ack.
		s.emitUpgradeProofLocked(ac, key, ac.upgradePeerNonce)
		return
	}

	// We are the RESPONDER and this is the initiator's proof. The initiator
	// switched its write direction right after emitting THIS frame, so
	// everything it sends from here on is sealed: set readKey now, with this
	// frame as the boundary. Then Ack and switch our write direction.
	ac.readKey = syncDeriveFrameKey(key, localNonce, ac.upgradePeerNonce)
	ac.upgradeReadDone = true
	slog.Info("cluster sync: in-place auth upgrade — inbound frames are now authenticated (#6628)",
		"remote", connRemoteAddrString(conn))
	// Written through ac, NOT ac.Conn: on a re-upgrade (a rotation over an
	// already-authenticated connection) the connection is still sealing under
	// the OLD key, and the peer's read side is still on that key until this
	// frame moves it. Writing to the raw conn would emit an unsealed frame
	// into a stream the peer expects to be sealed — a desync, on the one path
	// where the connection was healthy to begin with.
	if err := writeMsg(ac, syncMsgAuthUpgradeAck, []byte{syncAuthUpgradeVersion}); err != nil {
		// The Ack did not go out, so the initiator will not switch its read
		// direction. Undo our read switch rather than leaving the two ends
		// disagreeing: the connection is failing anyway, and a half-switched
		// posture is the one state that could desync a survivor.
		ac.readKey = nil
		slog.Warn("cluster sync: auth-upgrade ack send failed; reverting to the un-upgraded "+
			"posture (#6628)", "err", err)
		return
	}
	s.completeUpgradeWriteLocked(ac, key, "responder")
}

// handleAuthUpgradeAck completes the exchange on the INITIATOR: the responder
// switched its write direction right after emitting this frame, so everything
// it sends from here on is sealed.
//
// Runs on the receiveLoop goroutine that owns conn.
func (s *SessionSync) handleAuthUpgradeAck(conn net.Conn, payload []byte) {
	ac, ok := conn.(*authConn)
	if !ok {
		return
	}
	if len(payload) < 1 || payload[0] != syncAuthUpgradeVersion {
		return
	}
	key := s.authKey()
	if len(key) == 0 {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if ac.upgradeNonce == nil || ac.upgradePeerNonce == nil || !ac.upgradeProofSent {
		// An Ack outside an exchange we are part of. Ignore rather than derive
		// a key from state we did not establish.
		return
	}
	if ac.upgradeReadDone {
		return
	}
	ac.readKey = syncDeriveFrameKey(key, ac.upgradeNonce, ac.upgradePeerNonce)
	ac.upgradeReadDone = true
	if ac.upgradeWriteDone {
		ac.authPSK = append([]byte(nil), key...)
	}
	slog.Info("cluster sync: in-place auth upgrade complete — this connection is now "+
		"authenticated in both directions (#6628)", "remote", connRemoteAddrString(conn))
}

// emitUpgradeProofLocked writes our proof over peerNonce and installs writeKey
// AFTER that write, both inside the caller's writeMu section so no frame can
// slip out between the two and the peer's read boundary is exact.
//
// Idempotent: a second call on the same connection is a no-op.
//
// Caller holds s.writeMu.
func (s *SessionSync) emitUpgradeProofLocked(ac *authConn, key, peerNonce []byte) {
	if ac.upgradeProofSent {
		return
	}
	localNonce := ac.upgradeNonce
	if localNonce == nil {
		// Responder with no challenge of its own yet: mint one and carry it in
		// the proof so the initiator can derive the same frame key.
		n := make([]byte, syncAuthNonceSize)
		if _, err := rand.Read(n); err != nil {
			slog.Warn("cluster sync: auth-upgrade nonce generation failed; the connection "+
				"stays as it is (#6628)", "err", err)
			return
		}
		localNonce = n
		ac.upgradeNonce = n
	}
	if err := syncCheckPeerNonce(localNonce, peerNonce); err != nil {
		slog.Warn("cluster sync: refusing the auth-upgrade peer nonce before emitting a "+
			"proof (#6628)", "err", err)
		return
	}
	payload := make([]byte, 0, 1+syncAuthProofLen+syncAuthNonceSize)
	payload = append(payload, syncAuthUpgradeVersion)
	payload = append(payload, syncAuthProof(key, peerNonce)...)
	payload = append(payload, localNonce...)
	// Through ac, not ac.Conn — see the Ack write for why.
	if err := writeMsg(ac, syncMsgAuthUpgradeProof, payload); err != nil {
		slog.Warn("cluster sync: auth-upgrade proof send failed; the connection stays as it "+
			"is (#6628)", "err", err)
		return
	}
	ac.upgradeProofSent = true

	// The RESPONDER must not switch here — it has proven nothing yet. Only the
	// INITIATOR reaches this point having already verified the responder's
	// proof, which is what makes the switch safe. The discriminator is whether
	// we have a peer nonce we verified against, recorded by the caller.
	if ac.upgradePeerVerified {
		s.completeUpgradeWriteLocked(ac, key, "initiator")
	}
}

// completeUpgradeWriteLocked installs writeKey. Caller holds s.writeMu and has
// already written the frame that is the peer's read boundary.
func (s *SessionSync) completeUpgradeWriteLocked(ac *authConn, key []byte, role string) {
	if ac.upgradeWriteDone {
		return
	}
	ac.writeKey = syncDeriveFrameKey(key, ac.upgradeNonce, ac.upgradePeerNonce)
	ac.upgradeWriteDone = true
	if ac.upgradeReadDone {
		ac.authPSK = append([]byte(nil), key...)
	}
	slog.Info("cluster sync: in-place auth upgrade — outbound frames are now authenticated (#6628)",
		"role", role, "remote", connRemoteAddrString(ac.Conn))
}

// SyncMsgAuthUpgradeHelloForTest exposes the upgrade Hello message type to
// pkg/daemon's call-site binding test, which must assert on the frame the
// apply tail actually puts on the wire rather than on a source string.
const SyncMsgAuthUpgradeHelloForTest = syncMsgAuthUpgradeHello

// InstallUnauthenticatedConnForTest installs conn as fabric 0 wrapped in an
// UNAUTHENTICATED authConn — the posture of a connection handshaked while both
// ends were unkeyed, which is by construction the one #6628 is about.
//
// Test-only seam. Production installs connections through installConn, which
// this deliberately does not call: the cold-prime decision and the incarnation
// stamping it performs are irrelevant here and would drag a whole SessionSync
// lifecycle into a test about one line in the apply tail.
func (s *SessionSync) InstallUnauthenticatedConnForTest(conn net.Conn) {
	s.mu.Lock()
	s.conn0 = &authConn{Conn: conn}
	s.mu.Unlock()
}
