package cluster

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// upgEnd is one side of an in-place upgrade: a SessionSync with a single
// installed authConn, driven frame by frame so the test can assert on the
// exact switch boundaries rather than on a settled end state.
type upgEnd struct {
	s    *SessionSync
	ac   *authConn
	wire net.Conn // the peer's end of the pipe, read by the harness

	// sealedOut records whether this end was SEALING at the instant it was
	// asked to write. A frame's sealed-ness is the writer's posture BEFORE the
	// write, never after — every switch in this exchange happens after the
	// frame that is the peer's boundary — so the harness must sample it at the
	// same instant production does.
	sealedOut bool
}

// tcpPair returns a connected loopback TCP pair.
//
// NOT net.Pipe: net.Pipe is synchronous and unbuffered, so a handler that
// answers a frame blocks until someone reads it — and the exchange under test
// is precisely a sequence of answer-a-frame steps. Driving that over net.Pipe
// needs a goroutine per delivery, which puts the test goroutine's state reads
// in a race with the handler it is asserting about. A kernel socket buffer
// makes every write in this exchange return immediately, so each step can run
// synchronously and the assertions see a settled state.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	t.Cleanup(func() { dialed.Close(); got.c.Close() })
	return dialed, got.c
}

func newUpgEnd(t *testing.T, key string) *upgEnd {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	if key != "" {
		s.SetAuthProvider(&staticAuthProvider{key: []byte(key)})
	}
	local, remote := tcpPair(t)
	ac := &authConn{Conn: local}
	s.mu.Lock()
	s.conn0 = ac
	s.mu.Unlock()
	return &upgEnd{s: s, ac: ac, wire: remote}
}

// pump reads one frame off e's wire and delivers it to the OTHER end's
// handleMessage, which is exactly what that end's receiveLoop would do.
// Returns the message type delivered.
//
// Frames are moved one at a time on purpose: the whole correctness argument is
// about which frame is the boundary for each direction's key switch, and a
// harness that let both sides run free could not distinguish "switched at the
// right frame" from "settled correctly eventually".
func pump(t *testing.T, from *upgEnd, to *upgEnd) uint8 {
	t.Helper()
	_ = from.wire.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, syncHeaderSize)
	if _, err := io.ReadFull(from.wire, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := binary.LittleEndian.Uint32(hdr[8:12])
	body := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(from.wire, body); err != nil {
			t.Fatalf("read frame body: %v", err)
		}
	}
	// The trailer is drained only when the writer was ALREADY sealing before
	// it wrote this frame, which is what makes this an assertion rather than a
	// convenience: every switch in the exchange happens AFTER the frame that
	// is the peer's boundary, so on a first upgrade none of the four frames
	// carries a trailer, and on a re-upgrade (a rotation over an already
	// authenticated connection) all of them do. Move any switch ahead of its
	// write and this drain goes wrong by exactly one trailer — the step below
	// then fails on a bogus message type, which is the same desync the
	// ordering contract exists to prevent, surfaced here instead of on a live
	// cluster.
	if from.sealedOut {
		trailer := make([]byte, syncAuthFrameTrailerSize)
		if _, err := io.ReadFull(from.wire, trailer); err != nil {
			t.Fatalf("read frame trailer: %v", err)
		}
	}
	to.sealedOut = to.ac.writeAuthed()
	to.s.handleMessage(to.ac, hdr[4], body)
	return hdr[4]
}

// runUpgrade drives the full exchange initiated by a, and returns the ordered
// list of message types that crossed.
func runUpgrade(t *testing.T, a, b *upgEnd) []uint8 {
	t.Helper()
	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	var seen []uint8
	seen = append(seen, pump(t, a, b)) // Hello   a -> b
	seen = append(seen, pump(t, b, a)) // Proof   b -> a
	seen = append(seen, pump(t, a, b)) // Proof   a -> b
	seen = append(seen, pump(t, b, a)) // Ack     b -> a
	return seen
}

// TestInPlaceUpgradeAuthenticatesAnEstablishedConnection6628 is the primary
// gate: a connection established while BOTH ends were unkeyed — which is by
// construction the connection that carries the PSK across, since
// performSyncHandshake runs no handshake without a local key — becomes
// authenticated in both directions after both ends commit the key, with no
// reconnect and no restart.
//
// FAIL-ON-REVERT: drop the ReconcileConnectionAuth call, or the receive arms,
// and the exchange never happens; the connection stays unauthenticated and
// this reds.
func TestInPlaceUpgradeAuthenticatesAnEstablishedConnection6628(t *testing.T) {
	const psk = "in-place-upgrade-psk-6628"
	a := newUpgEnd(t, psk)
	b := newUpgEnd(t, psk)

	// Precondition: the connection is unauthenticated in both directions, as a
	// connection handshaked while both ends were unkeyed is.
	if a.ac.readAuthed() || a.ac.writeAuthed() || b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("the fixture must start unauthenticated, or the assertions below are vacuous")
	}

	seen := runUpgrade(t, a, b)
	want := []uint8{syncMsgAuthUpgradeHello, syncMsgAuthUpgradeProof, syncMsgAuthUpgradeProof, syncMsgAuthUpgradeAck}
	if len(seen) != len(want) {
		t.Fatalf("frame sequence %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("frame %d is type %d, want %d (sequence %v)", i, seen[i], want[i], seen)
		}
	}

	if !a.ac.authed() {
		t.Fatalf("the initiator must be authenticated in BOTH directions after the exchange "+
			"(read=%v write=%v); an established unkeyed stream that stays unkeyed after the "+
			"key is committed is the whole of #6628", a.ac.readAuthed(), a.ac.writeAuthed())
	}
	if !b.ac.authed() {
		t.Fatalf("the responder must be authenticated in BOTH directions (read=%v write=%v)",
			b.ac.readAuthed(), b.ac.writeAuthed())
	}
	// Both ends must reach the SAME frame key in each direction, or every
	// sealed frame from here on fails verification.
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) {
		t.Fatal("a's write key must equal b's read key")
	}
	if !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("b's write key must equal a's read key")
	}

	// And the upgrade is real: a frame sealed by one end verifies at the other.
	frame := encodeRawMessage(syncMsgSessionV4, []byte("post-upgrade"))
	sealed := a.ac.sealFrame(frame)
	header := sealed[:syncHeaderSize]
	length := binary.LittleEndian.Uint32(header[8:12])
	payload := sealed[syncHeaderSize : syncHeaderSize+int(length)]
	trailer := sealed[syncHeaderSize+int(length):]
	if err := b.ac.verifyFrame(header, payload, trailer); err != nil {
		t.Fatalf("a frame sealed after the upgrade must verify at the peer: %v", err)
	}
}

// TestInPlaceUpgradeNeverSwitchesOneDirectionEarly6628 is the assertion the
// four-frame shape exists for, and it is the one a settled-end-state test
// cannot make.
//
// A single `key` field on authConn — the pre-#6628 shape — would flip read and
// write together on one end. That end then requires a trailer while the peer
// is still sending unsealed frames, consumes syncAuthFrameTrailerSize bytes of
// the NEXT frame as a trailer, fails the MAC and DROPS the connection. So the
// invariant is not "both ends end up authenticated"; it is "no end ever
// requires a trailer before the peer has started writing one".
//
// Checked at every frame boundary of the exchange.
func TestInPlaceUpgradeNeverSwitchesOneDirectionEarly6628(t *testing.T) {
	const psk = "in-place-upgrade-psk-6628"
	a := newUpgEnd(t, psk)
	b := newUpgEnd(t, psk)

	check := func(stage string) {
		t.Helper()
		// a reads sealed frames only once b is sealing them, and vice versa.
		if a.ac.readAuthed() && !b.ac.writeAuthed() {
			t.Fatalf("%s: the initiator requires a trailer the responder is not writing — the "+
				"next unsealed frame desyncs the stream and drops the connection", stage)
		}
		if b.ac.readAuthed() && !a.ac.writeAuthed() {
			t.Fatalf("%s: the responder requires a trailer the initiator is not writing", stage)
		}
	}

	check("before the exchange")
	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b)
	check("after Hello")
	pump(t, b, a)
	check("after the responder's Proof")
	pump(t, a, b)
	check("after the initiator's Proof")
	pump(t, b, a)
	check("after the Ack")

	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("the exchange must still complete — a test that never switches anything " +
			"satisfies the invariant above vacuously")
	}
}

// TestInPlaceUpgradeWithMismatchedKeysSwitchesNothing6628 is why the responder
// waits for the initiator's proof instead of switching after its own.
//
// A botched rotation leaves the two nodes on different keys. In the obvious
// three-frame design the responder switches its write direction right after
// sending its proof, having proven NOTHING; the initiator's verification then
// fails, the initiator never switches, and the responder's next sealed frame
// arrives at a reader not expecting a trailer. Frame desync, connection
// dropped — by the mechanism whose premise is that it never drops.
//
// FAIL-ON-REVERT: move the responder's writeKey install from the Ack path to
// the Proof path and this reds.
func TestInPlaceUpgradeWithMismatchedKeysSwitchesNothing6628(t *testing.T) {
	a := newUpgEnd(t, "key-alpha-6628")
	b := newUpgEnd(t, "key-beta-6628")

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello  a -> b
	pump(t, b, a) // Proof  b -> a  (a will fail to verify it)

	if a.ac.readAuthed() || a.ac.writeAuthed() {
		t.Fatal("the initiator must not switch anything on a proof that did not verify")
	}
	if b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("the responder must not switch anything before it has verified the " +
			"initiator's proof; switching there desyncs the stream whenever the two nodes " +
			"hold different keys, which is exactly a botched rotation")
	}
	// The connection is untouched, not dropped: that is the property.
	if a.ac.authPSK != nil || b.ac.authPSK != nil {
		t.Fatal("a failed upgrade must leave the connection recorded as unauthenticated")
	}
}

// TestInPlaceUpgradeIsSilentAgainstAnUnkeyedPeer6628: the rolling-upgrade case.
// A peer with no key must not be answered and must not be dropped — it keeps
// its connection, unauthenticated, exactly as today.
//
// This is also the honest limit of #6628: a HOSTILE stream declines the
// upgrade in precisely this way, and a decliner is indistinguishable from a
// legitimate not-yet-keyed peer. That residual is tracked separately.
func TestInPlaceUpgradeIsSilentAgainstAnUnkeyedPeer6628(t *testing.T) {
	a := newUpgEnd(t, "in-place-upgrade-psk-6628")
	b := newUpgEnd(t, "") // no key: a pre-keying peer, or one declining

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello a -> b

	if b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("an unkeyed peer cannot authenticate anything")
	}
	// b must NOT have written a reply. Read with a short deadline: a reply
	// would arrive immediately over net.Pipe.
	_ = b.wire.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := b.wire.Read(buf); err == nil {
		t.Fatal("an unkeyed peer must answer a Hello with silence — anything else would " +
			"either leak that it is unkeyed or start an exchange it cannot finish")
	}
	if a.ac.readAuthed() || a.ac.writeAuthed() {
		t.Fatal("the initiator must not switch on its own Hello")
	}
}

// TestReconcileConnectionAuthIsANoOpWhenAlreadyKeyed6628 binds the staleness
// test. The reconciler runs on EVERY commit, so an already-authenticated
// connection must cost nothing and, more importantly, must not restart the
// exchange — a second Hello mints a second nonce and leaves the peer proving
// over a challenge this node no longer holds.
//
// FAIL-ON-REVERT: drop the authPSK comparison in beginAuthUpgrade and this
// reds with a spurious Hello on the wire.
func TestReconcileConnectionAuthIsANoOpWhenAlreadyKeyed6628(t *testing.T) {
	const psk = "in-place-upgrade-psk-6628"
	a := newUpgEnd(t, psk)
	b := newUpgEnd(t, psk)
	runUpgrade(t, a, b)
	if !a.ac.authed() {
		t.Fatal("precondition: the connection must be authenticated")
	}

	// An unrelated commit.
	a.s.ReconcileConnectionAuth("unrelated-commit")
	_ = a.wire.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := a.wire.Read(buf); err == nil {
		t.Fatal("a commit that does not change the key must put NOTHING on the wire; " +
			"restarting the exchange on a healthy connection leaves the peer proving over " +
			"a challenge this node no longer holds")
	}
}

// TestConnectAuthenticatedConnectionIsNotDisturbedByACommit6628 covers the
// case the reconciler sees most often and the rest of this file does not
// reach: a connection that authenticated at CONNECT time, through
// performSyncHandshake, and has never been near an upgrade.
//
// Its exchange state is empty, so the "an exchange is already in flight"
// guard does not apply to it; only the recorded PSK distinguishes it from a
// connection that genuinely needs upgrading. Without that record every commit
// would start a pointless exchange on a healthy authenticated stream — needless
// traffic, and a mid-stream key switch exercised for no reason.
//
// FAIL-ON-REVERT: drop the authPSK stamp in wrapSyncConn, or the authPSK
// comparison in beginAuthUpgrade, and a Hello appears on the wire here.
func TestConnectAuthenticatedConnectionIsNotDisturbedByACommit6628(t *testing.T) {
	const psk = "connect-authenticated-psk-6628"
	e := newUpgEnd(t, psk)
	// Built by wrapSyncConn, NOT by hand. Hand-setting readKey/writeKey/authPSK
	// would bind the reconciler's comparison while leaving the STAMP unbound —
	// delete `ac.authPSK = ...` from wrapSyncConn and a hand-built fixture stays
	// green while every real connect-authenticated connection is churned on
	// every commit. Driving the production wrapper is the difference.
	frameKey := syncDeriveFrameKey([]byte(psk),
		[]byte("nonce-a-connect-time-32-bytes-xx"), []byte("nonce-b-connect-time-32-bytes-yy"))
	wrapped := e.s.wrapSyncConn(0, e.ac.Conn, syncAuthAuthenticated, frameKey)
	e.ac = wrapped
	e.s.mu.Lock()
	e.s.conn0 = wrapped
	e.s.mu.Unlock()
	if !wrapped.authed() {
		t.Fatal("precondition: wrapSyncConn must produce an authenticated connection")
	}

	e.s.ReconcileConnectionAuth("unrelated-commit")

	_ = e.wire.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := e.wire.Read(buf); err == nil {
		t.Fatal("a commit must put NOTHING on the wire for a connection that already " +
			"authenticated at connect time under the same key; starting an exchange there " +
			"churns a healthy stream and performs a mid-stream key switch for no reason")
	}
	if !e.ac.authed() {
		t.Fatal("the connection must still be authenticated — a reconciler that tore it " +
			"down would satisfy the check above for the wrong reason")
	}
}

// TestInPlaceUpgradeRekeysOnRotation6628: the second property #6628 names —
// "rotation never revokes an existing connection's old derived frame key". An
// authenticated connection whose PSK is rotated must re-derive under the new
// key rather than keep sealing with the retired one.
func TestInPlaceUpgradeRekeysOnRotation6628(t *testing.T) {
	const first = "rotation-first-psk-6628"
	const second = "rotation-second-psk-6628"
	a := newUpgEnd(t, first)
	b := newUpgEnd(t, first)
	runUpgrade(t, a, b)
	oldKey := append([]byte(nil), a.ac.writeKey...)
	if len(oldKey) == 0 {
		t.Fatal("precondition: the first upgrade must have produced a frame key")
	}

	// Rotate both ends and reset the per-connection exchange state the way a
	// fresh reconcile sees it: the exchange is one-shot per connection, so a
	// rotation must be able to start a new one.
	a.s.SetAuthProvider(&staticAuthProvider{key: []byte(second)})
	b.s.SetAuthProvider(&staticAuthProvider{key: []byte(second)})
	runUpgrade(t, a, b)
	if bytes.Equal(a.ac.writeKey, oldKey) {
		t.Fatal("a rotation must re-derive the connection's frame key; keeping the key " +
			"derived from the RETIRED PSK means the rotation revoked nothing on this " +
			"connection (#6628)")
	}
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("both ends must agree on the re-derived keys")
	}
	if !bytes.Equal(a.ac.authPSK, []byte(second)) {
		t.Fatal("the connection must record the PSK it is now authenticated under, or the " +
			"reconciler cannot tell a later rotation is needed")
	}
}

// staticAuthProvider supplies a fixed control-link PSK.
type staticAuthProvider struct{ key []byte }

func (p *staticAuthProvider) ControlLinkAuthKey() []byte { return p.key }

// TestAuthUpgradeMessageTypesAreUnique6628 mirrors the #6650/#6629 guards. An
// old peer ignores an UNKNOWN type via the receive switch's missing default arm
// — that is the whole no-version-bump argument — but it MISPARSES a known one.
func TestAuthUpgradeMessageTypesAreUnique6628(t *testing.T) {
	t.Parallel()
	for _, under := range []struct {
		v    int
		name string
	}{
		{syncMsgAuthUpgradeHello, "syncMsgAuthUpgradeHello"},
		{syncMsgAuthUpgradeProof, "syncMsgAuthUpgradeProof"},
		{syncMsgAuthUpgradeAck, "syncMsgAuthUpgradeAck"},
	} {
		live := liveSyncMessageTypesExcept(under.v)
		if len(live) < 34 {
			t.Fatalf("the live-type census holds only %d entries — it has fallen behind "+
				"sync.go and can no longer certify uniqueness", len(live))
		}
		for _, m := range live {
			if m.v == under.v {
				t.Fatalf("%s (%d) collides with %s", under.name, under.v, m.name)
			}
		}
	}
}
