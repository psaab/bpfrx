package cluster

// Session-sync stream authentication (#4107 F23).
//
// The cross-chassis session-sync stream (sync.go / sync_conn.go /
// sync_protocol.go) is length-framed: every message is a `syncHeader`
// (magic + type + length) followed by `length` payload bytes. Before this
// change the stream carried session state, config, and election/failover
// control messages in cleartext with no authentication — any host that could
// reach the fabric/control-link IP could open the listener, dump session
// tuples, or drive a failover.
//
// The heartbeat's trailing-HMAC approach (heartbeat.go, #4357/PR-A) does NOT
// work on a length-framed stream: a legacy reader would mis-frame an appended
// HMAC as the next message header. So F23 uses an auth-capability HANDSHAKE at
// connection setup that negotiates — BEFORE any session frame flows — whether
// the connection is authenticated, and, once authenticated, seals every
// subsequent frame with a per-connection monotonic sequence + HMAC so an
// on-path attacker can neither forge nor replay a frame.
//
// Design summary:
//   - Handshake (performSyncHandshake): only a node that holds the shared
//     control-link PSK (the same `set chassis cluster authentication-key`
//     secret that #4357 wired for the heartbeat + fabric gRPC) initiates the
//     handshake. It sends a HELLO advertising a fresh 32-byte challenge nonce;
//     when BOTH peers are keyed each proves possession of the PSK with an
//     HMAC over the OTHER side's nonce (mutual challenge-response). Fresh
//     per-connection nonces make the proof replay-safe at setup.
//   - Dual-accept, UNKEYED SIDE ONLY: a node with no key never handshakes and
//     is byte-for-byte a legacy peer, so an unkeyed node still accepts anything.
//     A KEYED node does NOT dual-accept — #5078 removed that. It requires an
//     authenticated peer and rejects a legacy/unkeyed one outright, with no
//     first-contact grace and no migration window; see syncAuthDecision.
//   - No sync-side downgrade-guard: there is nothing left for one to protect.
//     A guard of that shape only matters where an unkeyed peer would otherwise
//     be admitted, and on a keyed node none ever is. The former
//     syncPeerAuthSeen / syncAuthedEver pair was removed once #5078 made the
//     rejection unconditional — it had become unreachable, and a dead guard
//     whose doc still asserts a live property is exactly the hazard #5078
//     removed the pre-admission frame path for. The #4107 HEARTBEAT downgrade
//     guard is SEPARATE state (heartbeatAuthState.peerAuthenticated, reached
//     via Manager.HeartbeatPeerAuthSeen) and is unaffected, as is the #4357
//     fabric guard that consumes it.
//   - Per-frame seal (authConn.sealFrame / verifyFrame): on an authenticated
//     connection every frame gets an 8-byte per-connection sequence + a
//     32-byte HMAC (keyed by a per-connection key derived from the PSK and
//     BOTH handshake nonces). The receiver rejects a bad HMAC (forgery /
//     tamper) or a non-increasing sequence (replay). Frames on an
//     unauthenticated connection are pass-through — identical to the legacy
//     wire — so dual-accept never changes the bytes.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

const (
	// syncMsgAuthHello and syncMsgAuthProof are the two handshake message
	// types. They are ABOVE the legacy message set (<= 26) so a peer that
	// predates F23 hits the (implicit) default receive case and ignores them —
	// the same additive-type discipline as the #2239 DHCP-lease messages.
	syncMsgAuthHello = 27 // {version:u8, keyed:u8, nonce[32]}
	syncMsgAuthProof = 28 // HMAC-SHA256 proof over the peer's HELLO nonce
)

const (
	syncAuthVersion   = 1
	syncAuthNonceSize = 32
	syncAuthMACSize   = sha256.Size // 32
	// syncAuthFrameTrailerSize is appended to each frame on an authenticated
	// connection: seq(8) + HMAC-SHA256(32).
	syncAuthFrameTrailerSize = 8 + syncAuthMACSize
	// syncHandshakeTimeout bounds the whole setup handshake. A hung/absent
	// peer drops the connection; fabricConnectLoop retries after ~1s, so a
	// transient handshake failure only delays reconnect — it never bricks
	// (dual-accept keeps a rolling upgrade alive without the handshake).
	//
	// The keyed↔keyed challenge-response completes in milliseconds when both
	// nodes are up; this bound only covers a hung or absent peer. It is kept
	// short (#4370) because the accepting node runs the handshake per inbound
	// connection — a longer bound lets a stalled connection tie up a handshake
	// goroutine (and, on Stop, keep it inside the 5s shutdown budget). 3s is
	// ample headroom over the sub-millisecond keyed path.
	syncHandshakeTimeout = 3 * time.Second
)

// Domain-separation tags — bound into every HMAC so a value produced for one
// purpose can never be reused as another.
var (
	syncAuthProofTag    = []byte("xpf-cluster-sync-auth-proof-v1\x00")
	syncAuthFrameKeyTag = []byte("xpf-cluster-sync-frame-key-v1\x00")
	syncAuthFrameMACTag = []byte("xpf-cluster-sync-frame-mac-v1\x00")
)

// syncAuthZeroNonce is the all-zero challenge nonce — the value a peer whose
// CSPRNG never seeded emits. It is a comparison target for syncCheckPeerNonce,
// never something this node sends: localNonce always comes from crypto/rand.
var syncAuthZeroNonce = make([]byte, syncAuthNonceSize)

var (
	errSyncFrameAuth   = errors.New("cluster sync: frame HMAC verification failed")
	errSyncFrameReplay = errors.New("cluster sync: frame sequence replay/regression")

	// Handshake-time nonce rejections (#5078). Distinct sentinels, and distinct
	// operator-facing text, because they say different things: a reflected
	// nonce is an ATTACK signature (or a loopback/echo misconfiguration), an
	// all-zero nonce is a BROKEN PEER. Folding them into one message would
	// send an operator hunting the wrong fault.
	errSyncReflectedNonce = errors.New("cluster sync: rejecting reflected handshake nonce (peer echoed our own challenge)")
	errSyncZeroNonce      = errors.New("cluster sync: rejecting all-zero handshake nonce (peer CSPRNG is not seeded)")
)

// syncAuthMode is the negotiated auth posture for one sync connection.
type syncAuthMode int

const (
	syncAuthUnauthenticated syncAuthMode = iota // dual-accept: frames are pass-through
	syncAuthAuthenticated                       // PSK handshake succeeded; frames sealed
)

// SyncAuthProvider supplies the shared control-link PSK to the session-sync
// stream authenticator (#4107 F23). *Manager satisfies it. It is OPTIONAL:
// when no provider is wired, or the key is empty, the sync stream runs in
// legacy unauthenticated mode, byte-identical to before.
//
// #5078: this used to also require HeartbeatPeerAuthSeen(), the cross-channel
// downgrade-guard signal. Its only consumer was syncPeerAuthSeen, which the
// unconditional keyed-node rejection made unreachable, so the requirement went
// with it. Manager still EXPORTS HeartbeatPeerAuthSeen — the gRPC fabric
// listener (pkg/grpcapi) and the control-link auth status string both consume
// it — it is simply no longer part of this interface's contract.
type SyncAuthProvider interface {
	ControlLinkAuthKey() []byte
}

type syncAuthProviderBox struct{ p SyncAuthProvider }

// SetAuthProvider wires the shared-PSK source used to authenticate the
// session-sync stream. Call once before Start.
func (s *SessionSync) SetAuthProvider(p SyncAuthProvider) {
	s.authProvider.Store(&syncAuthProviderBox{p: p})
}

// authKey returns the current control-link PSK, or nil when no provider is
// wired / no key is configured. Read live so a key added/changed at commit is
// picked up on the next handshake.
func (s *SessionSync) authKey() []byte {
	if box := s.authProvider.Load(); box != nil && box.p != nil {
		return box.p.ControlLinkAuthKey()
	}
	return nil
}

// authConn wraps a session-sync connection after the setup handshake. When
// key != nil the connection is AUTHENTICATED: every frame written through
// writeFull gets a per-connection sequence + HMAC trailer (sealFrame) and
// receiveLoop verifies + replay-checks it (verifyFrame). key == nil is an
// UNAUTHENTICATED (dual-accept) pass-through — byte-identical to the legacy
// path — so the same wrapper type covers both negotiated postures.
type authConn struct {
	net.Conn
	key     []byte        // per-connection frame-MAC key (nil ⇒ pass-through)
	sendSeq atomic.Uint64 // monotonic per-connection send counter
	// recvSeq/recvSeen are the replay watermark, touched only by the single
	// receiveLoop goroutine that owns this connection — no lock needed.
	recvSeq  uint64
	recvSeen bool
}

// authed reports whether this connection seals/verifies frames.
func (a *authConn) authed() bool { return a != nil && len(a.key) > 0 }

// sealFrame appends the per-connection auth trailer to a fully-encoded frame
// (header||payload). Callers hold s.writeMu — the invariant that serializes
// every write to a connection — so the assigned sequence order equals the
// on-wire order.
func (a *authConn) sealFrame(frame []byte) []byte {
	seq := a.sendSeq.Add(1)
	out := make([]byte, len(frame)+syncAuthFrameTrailerSize)
	n := copy(out, frame)
	binary.LittleEndian.PutUint64(out[n:n+8], seq)
	mac := hmac.New(sha256.New, a.key)
	mac.Write(syncAuthFrameMACTag)
	mac.Write(out[:n+8]) // frame || seq
	copy(out[n+8:], mac.Sum(nil))
	return out
}

// verifyFrame authenticates the trailer that follows a frame on an
// authenticated connection and enforces the strictly-increasing per-connection
// sequence (replay/regression guard). header+payload are the frame as read by
// receiveLoop; trailer is the syncAuthFrameTrailerSize bytes read immediately
// after. On success it advances the watermark; any error causes receiveLoop to
// drop the connection.
func (a *authConn) verifyFrame(header, payload, trailer []byte) error {
	if len(trailer) != syncAuthFrameTrailerSize {
		return errSyncFrameAuth
	}
	seq := binary.LittleEndian.Uint64(trailer[:8])
	mac := hmac.New(sha256.New, a.key)
	mac.Write(syncAuthFrameMACTag)
	mac.Write(header)
	mac.Write(payload)
	mac.Write(trailer[:8])
	if !hmac.Equal(trailer[8:], mac.Sum(nil)) {
		return errSyncFrameAuth
	}
	if a.recvSeen && seq <= a.recvSeq {
		return errSyncFrameReplay
	}
	a.recvSeq = seq
	a.recvSeen = true
	return nil
}

// syncAuthProof computes the challenge-response proof: HMAC-SHA256(key, tag ||
// challenge). Each side proves possession of the PSK over the PEER's fresh
// nonce, so a captured proof cannot be replayed onto a new connection.
func syncAuthProof(key, challenge []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(syncAuthProofTag)
	mac.Write(challenge)
	return mac.Sum(nil)
}

// syncCheckPeerNonce rejects the two degenerate peer challenge nonces, before
// this node computes a proof over one of them. Returns nil when the nonce is
// usable.
//
// #5078 vector A — REFLECTION. syncAuthProof is HMAC(key, tag ‖ challenge):
// it carries no role, no node identity, and no transcript, and the accept test
// is `hmac.Equal(peerProof, syncAuthProof(key, localNonce))`. So a PSK-less
// attacker that simply ECHOES every byte back authenticates: this node's HELLO
// returns as the peer HELLO with peerNonce == localNonce, this node computes
// and sends HMAC(key, tag ‖ localNonce) first, and the attacker replays that
// same value as the peer proof. Refusing an equal nonce breaks that identity
// before the proof is emitted, so the echo never obtains the one value it
// needs.
//
// This is NECESSARY, NOT SUFFICIENT, and the distinction is load-bearing: the
// two-connection variant (vector B) uses a SECOND keyed connection as a proof
// oracle — the attacker relays a proof computed over connection α's local
// nonce onto connection β — and there the two nonces on each connection differ,
// so nothing here fires. Because both nodes share one PSK, that oracle can be
// the PEER node, which no per-node nonce bookkeeping can see. Closing vector B
// needs the proof bound to role + identity + transcript, i.e. a new proof
// construction and a wire flag-day, which #5078 still tracks.
//
// The all-zero rejection is the same class of cheap degeneracy check: it is not
// an entropy test (entropy is unmeasurable from one sample), only a refusal of
// the single value that a peer with an unseeded CSPRNG emits.
//
// Both comparisons are variable-time on purpose. Challenge nonces travel in
// cleartext in the HELLO — the attacker supplied peerNonce and can observe
// localNonce — so there is no secret here for a timing side channel to leak,
// and hmac.Equal would imply one exists.
func syncCheckPeerNonce(localNonce, peerNonce []byte) error {
	if bytes.Equal(peerNonce, localNonce) {
		return errSyncReflectedNonce
	}
	if bytes.Equal(peerNonce, syncAuthZeroNonce) {
		return errSyncZeroNonce
	}
	return nil
}

// syncDeriveFrameKey derives the per-connection frame-MAC key from the PSK and
// BOTH handshake nonces, ordered canonically so both peers derive the same key.
// Binding the key to the fresh nonces means a frame captured on one connection
// cannot verify on another (cross-connection replay is excluded, not only
// intra-connection replay).
func syncDeriveFrameKey(key, nonceA, nonceB []byte) []byte {
	lo, hi := nonceA, nonceB
	if bytes.Compare(lo, hi) > 0 {
		lo, hi = hi, lo
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(syncAuthFrameKeyTag)
	mac.Write(lo)
	mac.Write(hi)
	return mac.Sum(nil)
}

// syncAuthDecision applies the #4107 dual-accept policy for a session-sync
// connection handshake and returns the negotiated mode, whether to accept the
// connection, and (on rejection) a short reason for logging — never the key.
// It mirrors heartbeatAuthDecision.
//
//	keyConfigured  — the local ControlLinkAuthKey is set (we can verify).
//	peerAdvertised — the peer sent an auth HELLO (an upgrade-aware peer).
//	peerKeyed      — the peer's HELLO advertised that it holds a key.
//	proofOK        — the peer's challenge-response proof verified (meaningful
//	                 only when both sides are keyed).
//
// Policy:
//   - No local key: dual-accept — this node cannot verify and may be the
//     not-yet-keyed side of a rolling upgrade.
//   - Local key + peer keyed (proof exchanged): enforce — reject a bad proof.
//   - Local key + peer legacy/unkeyed: REJECT, unconditionally.
//
// #5078: that last line used to grant a first-contact grace — a keyed node
// dual-accepted an unkeyed peer whenever `peerAuthSeen` was still false. That
// grace was an unauthenticated ACTIVE bypass, not a compatibility affordance,
// and it did not need the reflection weakness to exploit: a PSK-less attacker
// reaching the fabric on first contact was admitted, could fence the node
// (disabling every RG), and displaced the legitimate peer connection — after
// which arming the sticky guard did not evict it. `peerAuthSeen` is therefore
// no longer consulted for this branch; it cannot be, because the whole window
// is "before the guard arms".
//
// There is deliberately NO relaxation knob — but the rollout constraint is
// sharper than an earlier revision of this comment claimed. An RG0 secondary
// whose read-only gate is ARMED cannot be keyed locally:
// applyRG0OwnershipTransition sets the store read-only on
// StateSecondary/StateSecondaryHold and EnterConfigureSession then returns
// ErrClusterReadOnly, so config-sync is that node's only writer. Arming is
// driven by an RG0 TRANSITION event and nothing else, so a node that
// cold-starts into secondary and never transitions is still writable, and REST
// has no RG0 check of its own — see #6890 (and #6889 for the dropped-event
// variant). Both are OPEN and unscheduled; do not design a rollout around
// either, and do not assume they are fixed.
// Keying a LIVE cluster therefore means committing on the PRIMARY while sync is
// connected and letting the established connection carry the key across — which
// works only because the auth key is absent from clusterTransportKey, so a key
// commit does not restart cluster comms (pinned by
// TestAuthKeyChangeDoesNotRestartClusterComms_5078). Keying at provisioning,
// before either node seats as secondary, avoids the question entirely.
//
// A bounded dual-accept window was shipped and then removed. It had to bound a
// connection's LIFETIME rather than just its admission (an admitted
// pass-through stream outlived the deadline), it had to stop an admitted peer
// re-arming it through config-sync, and it could not survive a crash loop
// without persisting its deadline. A relaxation that needs three guards of its
// own does not belong in the fix that closes the hole.
//
// The property this leaves is the right one for a security appliance: for a
// connection established AFTER keying, a node must POSSESS the key to join a
// keyed cluster. A fresh or RMA node is keyed locally as part of the same
// bootstrap that gives it its node-id.
//
// That qualifier is load-bearing, and it is exactly what makes the live-keying
// procedure above work. Verification is gated PER CONNECTION on ac.authed(),
// which is fixed at handshake time, so a connection established BEFORE the key
// was committed stays unauthenticated for its whole lifetime and keeps having
// its frames accepted with no HMAC — the key never applies retroactively to an
// established stream. That residual is PRE-EXISTING (master behaves
// identically) and is tracked by #6628 — the broader "never re-handshakes on
// an auth-key CHANGE", which also covers a key ROTATION and subsumes the
// narrower unkeyed→keyed case. It is OPEN. Do not read the sentence above as
// claiming it is closed. pkg/cluster/README.md, "Rolling it onto
// a live unkeyed cluster", spells out the operator consequence: the restart in
// step 3 is not optional.
func syncAuthDecision(keyConfigured, peerAdvertised, peerKeyed, proofOK bool) (mode syncAuthMode, accept bool, reason string) {
	if !keyConfigured {
		return syncAuthUnauthenticated, true, ""
	}
	if peerAdvertised && peerKeyed {
		if proofOK {
			return syncAuthAuthenticated, true, ""
		}
		return syncAuthUnauthenticated, false, "hmac verification failed"
	}
	return syncAuthUnauthenticated, false, "missing auth handshake (enforced: this node is keyed)"
}

// readSyncFrameRaw reads one length-framed sync frame (header+payload) directly
// from a connection during the handshake, before any per-frame sealing is in
// effect. It does not strip an auth trailer.
func readSyncFrameRaw(conn net.Conn) (typ uint8, payload []byte, err error) {
	hdr := make([]byte, syncHeaderSize)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	if [4]byte{hdr[0], hdr[1], hdr[2], hdr[3]} != syncMagic {
		return 0, nil, errors.New("cluster sync: bad magic during handshake")
	}
	typ = hdr[4]
	length := binary.LittleEndian.Uint32(hdr[8:12])
	if length > 16*1024*1024 {
		return 0, nil, fmt.Errorf("cluster sync: handshake frame too large: %d", length)
	}
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return typ, payload, nil
}

// performSyncHandshake runs the connection-setup auth-capability handshake on a
// freshly connected sync connection and returns the negotiated mode, the
// per-connection frame key (non-nil only when authenticated), an optional first
// frame a legacy/unkeyed peer already sent (the caller must process it before
// reading further), and an error when the connection must be dropped (bad PSK
// proof, a downgrade attempt, or an I/O failure).
//
// The handshake runs ONLY when a local key is configured. An unkeyed node
// (legacy build, or a new build with no key yet) sends nothing special and is
// indistinguishable from — and fully compatible with — a legacy peer, so
// existing no-key deployments and tests are unaffected (dual-accept).
//
// HELLO and PROOF are written concurrently with reading the peer's frame so the
// handshake works over a fully-synchronous transport (net.Pipe in tests): a
// strict write-then-read on both symmetric peers would deadlock.
func (s *SessionSync) performSyncHandshake(conn net.Conn) (syncAuthMode, []byte, error) {
	key := s.authKey()
	if len(key) == 0 {
		// No local key ⇒ no handshake; legacy behavior (dual-accept).
		return syncAuthUnauthenticated, nil, nil
	}

	if err := conn.SetDeadline(time.Now().Add(syncHandshakeTimeout)); err != nil {
		return syncAuthUnauthenticated, nil, err
	}
	defer conn.SetDeadline(time.Time{})

	localNonce := make([]byte, syncAuthNonceSize)
	if _, err := rand.Read(localNonce); err != nil {
		return syncAuthUnauthenticated, nil, fmt.Errorf("cluster sync: handshake nonce: %w", err)
	}
	hello := make([]byte, 0, 2+syncAuthNonceSize)
	hello = append(hello, syncAuthVersion, 1) // version, keyed=1
	hello = append(hello, localNonce...)

	writeErr := make(chan error, 1)
	go func() { writeErr <- writeMsg(conn, syncMsgAuthHello, hello) }()

	typ, payload, err := readSyncFrameRaw(conn)
	if err != nil {
		<-writeErr
		return syncAuthUnauthenticated, nil, err
	}
	if werr := <-writeErr; werr != nil {
		return syncAuthUnauthenticated, nil, werr
	}

	if typ != syncMsgAuthHello {
		// Peer sent a real frame, not a HELLO ⇒ legacy or unkeyed peer. This
		// node is keyed (the len(key)==0 early return is above), so the frame
		// is discarded unread and the connection dropped. This arm rejects
		// UNCONDITIONALLY — it does not branch on syncAuthDecision's accept
		// bit, which is consulted only for the operator-facing reason string.
		// That is deliberate: with the pending mechanism gone there is no
		// "accept" outcome available here, so re-introducing a grace in the
		// decision must not silently re-open this path.
		//
		// #5078: this arm used to hand that first frame back to the caller as a
		// `pendingFrame`, which executed it BEFORE the connection was admitted
		// — `syncMsgFence` on that path disabled every routing group for a peer
		// that had proven nothing. With the dual-accept grace gone the arm can
		// no longer accept, so the mechanism is deleted rather than reordered:
		// unreachable code that mutates cluster state pre-admission is one edit
		// away from being live again.
		_, _, reason := syncAuthDecision(true, false, false, false)
		return syncAuthUnauthenticated, nil, errors.New(reason)
	}

	if len(payload) < 2+syncAuthNonceSize {
		return syncAuthUnauthenticated, nil, errors.New("cluster sync: short auth HELLO")
	}
	peerKeyed := payload[1] != 0
	peerNonce := payload[2 : 2+syncAuthNonceSize]

	if !peerKeyed {
		// Peer is a new build that speaks the handshake but holds no key ⇒ it
		// is not signing and can prove nothing. This node is keyed, so the
		// connection is dropped.
		//
		// Like the legacy/no-HELLO arm above, this arm rejects
		// UNCONDITIONALLY — it does not branch on syncAuthDecision's accept
		// bit, which is consulted only for the operator-facing reason string.
		// The two arms are the SAME admission decision reached by different
		// evidence (no HELLO at all vs. a HELLO advertising keyed=0), so they
		// get the same shape deliberately: this is the arm that literally IS
		// the rolling-upgrade case, so it is the one an operator restoring
		// rolling-upgrade compatibility would edit first. Leaving an "accept"
		// outcome reachable here — even one that today's decision never
		// returns — is a single deleted `if` away from admitting a PSK-less
		// peer that then fences every routing group.
		_, _, reason := syncAuthDecision(true, true, false, false)
		return syncAuthUnauthenticated, nil, errors.New(reason)
	}

	// #5078: refuse a reflected or degenerate peer nonce BEFORE this node emits
	// a proof over it. Ordered ahead of syncAuthProof deliberately — the proof
	// this node writes IS the value the echo attack replays back, so a check
	// that ran after it would already have handed the attacker the answer.
	if err := syncCheckPeerNonce(localNonce, peerNonce); err != nil {
		return syncAuthUnauthenticated, nil, err
	}

	// Both keyed ⇒ mutual challenge-response: prove we hold the key over the
	// PEER's nonce; verify the peer's proof over OUR nonce.
	proofOut := syncAuthProof(key, peerNonce)
	go func() { writeErr <- writeMsg(conn, syncMsgAuthProof, proofOut) }()

	ptyp, ppayload, err := readSyncFrameRaw(conn)
	if err != nil {
		<-writeErr
		return syncAuthUnauthenticated, nil, err
	}
	if werr := <-writeErr; werr != nil {
		return syncAuthUnauthenticated, nil, werr
	}

	proofOK := ptyp == syncMsgAuthProof && hmac.Equal(ppayload, syncAuthProof(key, localNonce))
	mode, accept, reason := syncAuthDecision(true, true, true, proofOK)
	if !accept {
		return syncAuthUnauthenticated, nil, errors.New(reason)
	}
	frameKey := syncDeriveFrameKey(key, localNonce, peerNonce)
	return mode, frameKey, nil
}

// wrapSyncConn applies the negotiated handshake result to a connection: it
// wraps conn in an authConn (sealing frames when authenticated) and, when the
// connection authenticated, arms the sticky downgrade-guard. pending is the
// legacy peer's first frame (nil when none) and is returned for the caller to
// process before starting the receive loop.
func (s *SessionSync) wrapSyncConn(fabricIdx int, conn net.Conn, mode syncAuthMode, frameKey []byte) *authConn {
	ac := &authConn{Conn: conn}
	if mode == syncAuthAuthenticated {
		ac.key = frameKey
		slog.Info("cluster sync: connection authenticated with control-link PSK",
			"fabric", fabricIdx, "remote", connRemoteAddrString(conn))
	}
	return ac
}
