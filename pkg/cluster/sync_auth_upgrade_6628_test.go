package cluster

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
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

// upgClusterID is the cluster id both ends of every fixture below share. The
// #7163 prologue binds it, so the two ends must agree or nothing authenticates.
const upgClusterID = 22

// newUpgEnd builds one end of an established, initially unauthenticated
// connection.
//
// node is load-bearing since #7163: the in-place upgrade takes its role from
// NODE ID (the lower id initiates), so a fixture that gave both ends the same
// id would have both ends believing they are the initiator and neither would
// ever answer a Hello. Callers pass 0 for the initiator side and 1 for the
// responder side.
func newUpgEnd(t *testing.T, key string, node int) *upgEnd {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	if key != "" {
		s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(key), node: node, cluster: upgClusterID})
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
	// is the peer's boundary, so on a first upgrade none of the frames carries
	// a trailer, and on a re-upgrade (a rotation over an already authenticated
	// connection) all of them do. Move any switch ahead of its write and this
	// drain goes wrong by exactly one trailer — the step below then fails on a
	// bogus message type, which is the same desync the ordering contract
	// exists to prevent, surfaced here instead of on a live cluster.
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

// expectSilence asserts that e has written nothing.
func expectSilence(t *testing.T, e *upgEnd, why string) {
	t.Helper()
	_ = e.wire.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := e.wire.Read(buf); err == nil {
		t.Fatal(why)
	}
}

// runUpgrade drives the full exchange initiated by a, and returns the ordered
// list of message types that crossed. a must be the node-0 (initiator) end.
func runUpgrade(t *testing.T, a, b *upgEnd) []uint8 {
	t.Helper()
	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	var seen []uint8
	seen = append(seen, pump(t, a, b)) // Hello   a -> b   (noise msg1)
	seen = append(seen, pump(t, b, a)) // Proof   b -> a   (noise msg2)
	seen = append(seen, pump(t, a, b)) // Confirm a -> b
	return seen
}

// upgradeFrameSequence is the #7163 three-frame choreography.
var upgradeFrameSequence = []uint8{
	syncMsgAuthUpgradeHello, syncMsgAuthUpgradeProof, syncMsgAuthUpgradeConfirm,
}

func assertFrameSequence(t *testing.T, seen, want []uint8) {
	t.Helper()
	if len(seen) != len(want) {
		t.Fatalf("frame sequence %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("frame %d is type %d, want %d (sequence %v)", i, seen[i], want[i], seen)
		}
	}
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
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

	// Precondition: the connection is unauthenticated in both directions, as a
	// connection handshaked while both ends were unkeyed is.
	if a.ac.readAuthed() || a.ac.writeAuthed() || b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("the fixture must start unauthenticated, or the assertions below are vacuous")
	}

	assertFrameSequence(t, runUpgrade(t, a, b), upgradeFrameSequence)

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

// TestInPlaceUpgradeInstallsDirectionalKeys7163 is the #7163 property carried
// into the upgrade path, and it is a DIFFERENT assertion from "both ends agree"
// above: the pre-#7163 syncDeriveFrameKey sorted its two nonces canonically, so
// both ends agreed AND both directions got the same bytes. Agreement alone is
// satisfied by the defect.
//
// The consequence that made it a vulnerability is SELF-FENCING: with one key
// per connection, a frame this node SENT verifies when echoed straight back at
// it, and verifyFrame's replay watermark cannot see it because it tracks the
// RECEIVE counter, which is independent of the send counter. The worst
// reflectable frame is syncMsgFence — empty payload, and on receipt the victim
// disables every one of its own redundancy groups.
//
// So this asserts the echo is REFUSED, not merely that two byte slices differ.
func TestInPlaceUpgradeInstallsDirectionalKeys7163(t *testing.T) {
	const psk = "directional-upgrade-psk-7163"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)
	runUpgrade(t, a, b)

	if bytes.Equal(a.ac.readKey, a.ac.writeKey) {
		t.Fatal("the initiator's two directions share one key — the pre-#7163 shape, which " +
			"is what let a node's own frame verify when echoed back at it")
	}
	if bytes.Equal(b.ac.readKey, b.ac.writeKey) {
		t.Fatal("the responder's two directions share one key")
	}

	// The echo, end to end: a's own sealed fence, replayed to a.
	fence := encodeRawMessage(syncMsgFence, nil)
	sealed := a.ac.sealFrame(fence)
	header := sealed[:syncHeaderSize]
	length := binary.LittleEndian.Uint32(header[8:12])
	payload := sealed[syncHeaderSize : syncHeaderSize+int(length)]
	trailer := sealed[syncHeaderSize+int(length):]
	if err := a.ac.verifyFrame(header, payload, trailer); err == nil {
		t.Fatal("a node's OWN sealed frame verified when echoed back at it. That is the " +
			"vector-B self-fencing primitive: the echoed frame is syncMsgFence, and on " +
			"receipt this node disables every redundancy group it owns.")
	}
	// Positive control: the same frame verifies at the PEER, so the refusal
	// above means "wrong direction", not "sealing is broken".
	if err := b.ac.verifyFrame(header, payload, trailer); err != nil {
		t.Fatalf("the same frame must verify at the peer, or the refusal above proves "+
			"nothing about directionality: %v", err)
	}
}

// TestInPlaceUpgradeNeverSwitchesOneDirectionEarly6628 is the assertion the
// multi-frame shape exists for, and it is the one a settled-end-state test
// cannot make.
//
// A single `key` field on authConn — the pre-#6628 shape — would flip read and
// write together on one end. That end then requires a trailer while the peer
// is still sending unsealed frames, consumes syncAuthFrameTrailerSize bytes of
// the NEXT frame as a trailer, fails the MAC and DROPS the connection. So the
// invariant is not "both ends end up authenticated"; it is "no end ever
// requires a trailer before the peer has started writing one".
//
// #7163 makes this harder rather than easier: Split() yields TWO keys where the
// old derivation yielded one, so there are two install points per direction.
// Checked at every frame boundary of the exchange.
func TestInPlaceUpgradeNeverSwitchesOneDirectionEarly6628(t *testing.T) {
	const psk = "in-place-upgrade-psk-6628"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

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
	check("after the initiator's Hello")
	pump(t, b, a)
	check("after the responder's Proof")
	pump(t, a, b)
	check("after the initiator's Confirm")

	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("the exchange must still complete — a test that never switches anything " +
			"satisfies the invariant above vacuously")
	}
}

// TestUpgradeInstallPointsAreAnchoredToTheirFrames7163 answers the question
// #7163 raises and #6628 did not have to: Split() gives two INDEPENDENT keys,
// so there are two install points per direction rather than one shared derived
// value. What happens if they land out of order?
//
// They cannot land in an arbitrary order, and the reason is worth stating
// exactly, because "both ends end up authenticated" does not imply it. Each
// direction has exactly one boundary frame; the WRITER installs immediately
// after writing that frame, inside the same writeMu section, and the READER
// installs while processing it. TCP orders frames within a direction, so every
// frame written before the install is unsealed and every frame after it is
// sealed, and the reader crosses the same line at the same frame.
//
//	responder WRITE + initiator READ  -> boundary is the Proof
//	initiator WRITE + responder READ  -> boundary is the Confirm
//
// Two sub-tests, because the risk has two halves: the boundary frame must be
// UNSEALED when it crosses a boundary that has not moved yet, and the writer's
// install must not happen at all if that frame did not go out.
func TestUpgradeInstallPointsAreAnchoredToTheirFrames7163(t *testing.T) {
	const psk = "install-points-psk-7163"

	t.Run("the Confirm crosses before the responder's read boundary moves", func(t *testing.T) {
		a := newUpgEnd(t, psk, 0)
		b := newUpgEnd(t, psk, 1)
		a.sealedOut = a.ac.writeAuthed()
		a.s.ReconcileConnectionAuth("test")
		pump(t, a, b) // Hello   a -> b
		pump(t, b, a) // Proof   b -> a

		// The Proof's own boundary has moved on BOTH ends, in one frame.
		if !b.ac.writeAuthed() || !a.ac.readAuthed() {
			t.Fatalf("the Proof must move the responder's write and the initiator's read "+
				"together (b.write=%v a.read=%v)", b.ac.writeAuthed(), a.ac.readAuthed())
		}
		// The initiator has already installed its write key, because the
		// Confirm went out inside the same handler. The responder has not moved
		// its read boundary, because the Confirm has not reached it yet.
		if !a.ac.writeAuthed() {
			t.Fatal("the initiator installs its write key immediately after writing the " +
				"Confirm; a gap between the two would let an unsealed frame follow a " +
				"boundary the peer has already crossed")
		}
		if b.ac.readAuthed() {
			t.Fatal("the responder must not move its read boundary before the Confirm " +
				"reaches it")
		}
		// So the Confirm — still in flight — MUST be unsealed, or the responder
		// cannot parse the very frame that moves its boundary. a.sealedOut was
		// sampled by pump before the handler ran, which is the same instant
		// production sampled it.
		if a.sealedOut {
			t.Fatal("the Confirm was sealed under a key the responder has not installed; " +
				"it would be read as a short frame plus garbage and the connection would " +
				"drop")
		}
		if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
			t.Fatalf("expected the Confirm, got frame type %d", typ)
		}
		if !a.ac.authed() || !b.ac.authed() {
			t.Fatal("both ends must be authenticated in both directions once the Confirm lands")
		}
		if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
			t.Fatal("both ends must agree on both directions")
		}
	})

	t.Run("a Confirm that never goes out installs no write key", func(t *testing.T) {
		// The only way the initiator's write install and the responder's read
		// install can end up on opposite sides of a frame is if the Confirm is
		// never written. Force exactly that: kill the socket, then hand the
		// initiator the Proof directly.
		a := newUpgEnd(t, psk, 0)
		b := newUpgEnd(t, psk, 1)
		a.sealedOut = a.ac.writeAuthed()
		a.s.ReconcileConnectionAuth("test")
		pump(t, a, b) // Hello a -> b, so b answers with a real msg2

		_ = a.wire.SetReadDeadline(time.Now().Add(3 * time.Second))
		hdr := make([]byte, syncHeaderSize)
		if _, err := io.ReadFull(b.wire, hdr); err != nil {
			t.Fatalf("read the responder's Proof header: %v", err)
		}
		body := make([]byte, binary.LittleEndian.Uint32(hdr[8:12]))
		if _, err := io.ReadFull(b.wire, body); err != nil {
			t.Fatalf("read the responder's Proof body: %v", err)
		}

		a.ac.Conn.Close()
		a.wire.Close()
		a.s.handleMessage(a.ac, hdr[4], body)

		if !a.ac.readAuthed() {
			t.Fatal("the read direction must still install: the responder switched its " +
				"write immediately after emitting that frame, so reverting it would " +
				"desync the direction that IS working")
		}
		if a.ac.writeAuthed() {
			t.Fatal("the write key was installed although the Confirm never went out. The " +
				"responder's read boundary therefore never moves, and the initiator's " +
				"next sealed frame desyncs a stream this mechanism promises never to drop.")
		}
	})
}

// TestUpgradeInFlightExchangeDoesNotBlockARotation6628 binds the other half of
// the in-flight guard, which has to be BOTH idempotent and non-sticky.
//
// The reconciler runs on every commit, so re-emitting a Hello for a key whose
// exchange is already in flight would mint a second ephemeral and leave the
// peer answering a handshake this node no longer holds. But an exchange the
// peer never answered — it was not keyed yet — must not then block the exchange
// for a key the operator rotates to, or the connection is stuck on a Hello
// nobody will ever reply to for the rest of its life.
//
// FAIL-ON-REVERT: make the in-flight test key-agnostic (drop the forPSK
// comparison) and the rotation below puts nothing on the wire.
func TestUpgradeInFlightExchangeDoesNotBlockARotation6628(t *testing.T) {
	const first = "in-flight-first-psk-6628"
	const second = "in-flight-second-psk-6628"
	a := newUpgEnd(t, first, 0)
	b := newUpgEnd(t, "", 1) // not keyed yet: it will never answer

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("first-commit")
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("expected a Hello, got frame type %d", typ)
	}
	// Idempotent: a second commit under the SAME key must add nothing.
	a.s.ReconcileConnectionAuth("unrelated-commit")
	expectSilence(t, a, "a commit under the same key must not re-emit a Hello while an "+
		"exchange for that key is already in flight; a second ephemeral leaves the peer "+
		"answering a handshake this node no longer holds")

	// Rotate. The in-flight state belongs to the retired key and must not
	// survive as a veto.
	a.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 0, cluster: upgClusterID})
	b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 1, cluster: upgClusterID})
	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("rotation")
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("a rotation must start a fresh exchange even though one for the RETIRED "+
			"key is still in flight; got frame type %d", typ)
	}
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeProof {
		t.Fatalf("expected a Proof, got frame type %d", typ)
	}
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
		t.Fatalf("expected a Confirm, got frame type %d", typ)
	}
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("the rotated exchange must complete both directions")
	}
	if !bytes.Equal(a.ac.authPSK, []byte(second)) {
		t.Fatal("the connection must record the key it is now authenticated under")
	}
}

// TestInPlaceUpgradeWithMismatchedKeysSwitchesNothing6628 is why neither end
// switches anything until key equality is proven.
//
// A botched rotation leaves the two nodes on different keys. #6628 needed four
// frames to survive it, because its responder had proven nothing when it
// answered. Under Noise_NNpsk0 the responder authenticates the initiator's msg1
// BEFORE answering, so a mismatch is refused one frame earlier and the
// responder simply says nothing — which is what this asserts.
//
// FAIL-ON-REVERT: install the responder's writeKey before the msg1 tag is
// checked, and the silence assertion reds.
func TestInPlaceUpgradeWithMismatchedKeysSwitchesNothing6628(t *testing.T) {
	a := newUpgEnd(t, "key-alpha-6628", 0)
	b := newUpgEnd(t, "key-beta-6628", 1)

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello a -> b  (b will fail to authenticate it)

	if a.ac.readAuthed() || a.ac.writeAuthed() {
		t.Fatal("the initiator must not switch anything on its own Hello")
	}
	if b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("the responder must not switch anything on a Hello that did not " +
			"authenticate; switching there desyncs the stream whenever the two nodes hold " +
			"different keys, which is exactly a botched rotation")
	}
	expectSilence(t, b, "a responder that could not authenticate the Hello must answer with "+
		"silence; a msg2 would hand the initiator a key it cannot derive and move a "+
		"boundary the initiator will never reach")
	// The connection is untouched, not dropped: that is the property.
	if a.ac.authPSK != nil || b.ac.authPSK != nil {
		t.Fatal("a failed upgrade must leave the connection recorded as unauthenticated")
	}

	// POSITIVE CONTROL (#7163). Everything above asserts that NOTHING switched,
	// which a completely broken exchange satisfies just as well as a correctly
	// refusing one. Without this, changing the handshake underneath — as #7163
	// does — could leave the whole test passing for the wrong reason while the
	// mechanism it guards had stopped working entirely.
	//
	// So: the SAME pump sequence, with MATCHING keys, must produce a msg2 and
	// go on to switch both ends. That is what makes the negative result above
	// mean "refused" rather than "never ran".
	c := newUpgEnd(t, "key-alpha-6628", 0)
	d := newUpgEnd(t, "key-alpha-6628", 1)
	c.sealedOut = c.ac.writeAuthed()
	c.s.ReconcileConnectionAuth("test")
	pump(t, c, d)
	if !d.ac.writeAuthed() {
		t.Fatal("positive control FAILED at the Proof: a matching-key Hello must be " +
			"authenticated and answered. The silence asserted above therefore proves " +
			"nothing — it would hold for an exchange that never runs.")
	}
	pump(t, d, c)
	pump(t, c, d)
	if !c.ac.authed() || !d.ac.authed() {
		t.Fatalf("positive control FAILED: matching keys did not complete the upgrade "+
			"(c.read=%v c.write=%v d.read=%v d.write=%v)",
			c.ac.readAuthed(), c.ac.writeAuthed(), d.ac.readAuthed(), d.ac.writeAuthed())
	}
}

// TestUpgradeMsg1IsAuthenticated7163 is the measurement the three-frame shape
// rests on, isolated so a change to it cannot hide inside an end-to-end result.
//
// #6628 needed a fourth frame because its responder had proven nothing when it
// switched its write direction. #7163 drops that frame on the claim that
// Noise_NNpsk0's FIRST message is already AEAD-tagged over the prologue and the
// transcript, so reading it proves key equality. If that claim ever stops
// holding — a pattern change, a placement change, a library change — the
// responder would be switching on an unauthenticated message and a key mismatch
// would desync the stream again.
//
// PAIRED: the wrong-key msg1 must be refused AND the right-key msg1 must be
// accepted, so "refuses everything" cannot pass.
func TestUpgradeMsg1IsAuthenticated7163(t *testing.T) {
	const good = "msg1-auth-good-7163"
	const bad = "msg1-auth-bad-7163"

	// The responder under test: node 1, keyed with `good`.
	deliver := func(t *testing.T, initiatorKey string) *upgEnd {
		t.Helper()
		b := newUpgEnd(t, good, 1)
		hs, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:  syncNoiseCipherSuite,
			Pattern:      noise.HandshakeNN,
			Initiator:    true,
			Prologue:     syncNoisePrologue(syncNoisePhaseUpgrade, upgClusterID, 0, 1, 0),
			PresharedKey: syncNoisePSK([]byte(initiatorKey)),
			Random:       rand.Reader,
		})
		if err != nil {
			t.Fatalf("build msg1: %v", err)
		}
		msg1, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			t.Fatalf("write msg1: %v", err)
		}
		if len(msg1) != 48 {
			t.Fatalf("msg1 is %d bytes, want 48 (32-byte ephemeral + 16-byte Poly1305 tag). "+
				"A msg1 with no tag would carry no proof of PSK possession, and the "+
				"three-frame exchange would be switching the responder's write direction "+
				"on an unauthenticated message.", len(msg1))
		}
		b.s.handleMessage(b.ac, syncMsgAuthUpgradeHello,
			append([]byte{syncAuthUpgradeVersion}, msg1...))
		return b
	}

	t.Run("wrong PSK is refused", func(t *testing.T) {
		b := deliver(t, bad)
		if b.ac.writeAuthed() || b.ac.readAuthed() {
			t.Fatal("a msg1 built under a different PSK must not move any boundary")
		}
		expectSilence(t, b, "a msg1 built under a different PSK must not be answered")
	})
	t.Run("right PSK is accepted", func(t *testing.T) {
		b := deliver(t, good)
		if !b.ac.writeAuthed() {
			t.Fatal("a msg1 built under the SAME PSK must be authenticated and answered, or " +
				"the refusal above proves nothing about the tag")
		}
	})
}

// TestUpgradePhaseSeparationRefusesAConnectMessage7163 binds the phase byte in
// the prologue.
//
// Both exchanges run under the same PSK, and a CONNECT msg1 travels in
// cleartext on a fresh TCP connection where anyone on the fabric can read it.
// Without the phase byte that captured message is also a well-formed upgrade
// Hello: replayed into an established unauthenticated stream, the responder
// would answer and switch its write direction to a key derived from an
// ephemeral nobody holds, and the legitimate peer could no longer read a frame.
// The connection would DROP — the one thing this mechanism promises it never
// does.
//
// PAIRED: the connect-phase message must be refused AND the upgrade-phase
// message accepted, so a responder that refuses everything cannot pass.
func TestUpgradePhaseSeparationRefusesAConnectMessage7163(t *testing.T) {
	const psk = "phase-separation-psk-7163"
	deliver := func(t *testing.T, phase byte) *upgEnd {
		t.Helper()
		b := newUpgEnd(t, psk, 1)
		hs, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:  syncNoiseCipherSuite,
			Pattern:      noise.HandshakeNN,
			Initiator:    true,
			Prologue:     syncNoisePrologue(phase, upgClusterID, 0, 1, 0),
			PresharedKey: syncNoisePSK([]byte(psk)),
			Random:       rand.Reader,
		})
		if err != nil {
			t.Fatalf("build msg1: %v", err)
		}
		msg1, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			t.Fatalf("write msg1: %v", err)
		}
		b.s.handleMessage(b.ac, syncMsgAuthUpgradeHello,
			append([]byte{syncAuthUpgradeVersion}, msg1...))
		return b
	}

	if b := deliver(t, syncNoisePhaseConnect); b.ac.writeAuthed() {
		t.Fatal("a CONNECT-phase msg1 was accepted as an in-place upgrade Hello. A msg1 " +
			"captured off a fresh connection can then be replayed into an established " +
			"stream to make this node seal under a key nobody holds.")
	}
	if b := deliver(t, syncNoisePhaseUpgrade); !b.ac.writeAuthed() {
		t.Fatal("the UPGRADE-phase msg1 must be accepted, or the refusal above says nothing " +
			"about the phase byte")
	}
}

// TestUpgradeRoleComesFromNodeIDNotTheWire7163: #6628 decided the role by
// comparing the two challenge nonces, which made role a function of a
// PEER-SUPPLIED value feeding this node's own key derivation — the same class
// of mistake vector B exploited. Role is now local knowledge on both sides.
//
// So a Hello arriving at the node that is the INITIATOR by id must be ignored:
// a peer cannot promote itself to initiator by sending a msg1.
func TestUpgradeRoleComesFromNodeIDNotTheWire7163(t *testing.T) {
	const psk = "role-from-node-id-7163"
	// a is node 0 (initiator) and b is node 1 (responder). Drive the exchange
	// BACKWARDS: b tries to open it.
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

	b.sealedOut = b.ac.writeAuthed()
	b.s.ReconcileConnectionAuth("test")
	typ := pump(t, b, a)
	if typ != syncMsgAuthUpgradeRequest {
		t.Fatalf("the responder-role node must PROMPT rather than open the exchange; it "+
			"emitted frame type %d, want %d", typ, syncMsgAuthUpgradeRequest)
	}

	// And a hand-built Hello aimed at the initiator-role node is ignored.
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:  syncNoiseCipherSuite,
		Pattern:      noise.HandshakeNN,
		Initiator:    true,
		Prologue:     syncNoisePrologue(syncNoisePhaseUpgrade, upgClusterID, 1, 0, 0),
		PresharedKey: syncNoisePSK([]byte(psk)),
		Random:       rand.Reader,
	})
	if err != nil {
		t.Fatalf("build msg1: %v", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	// Drain whatever the Request prompted a into writing, so the silence check
	// below is about the Hello and not about that.
	pump(t, a, b)
	a.s.handleMessage(a.ac, syncMsgAuthUpgradeHello,
		append([]byte{syncAuthUpgradeVersion}, msg1...))
	if a.ac.writeAuthed() || a.ac.readAuthed() {
		t.Fatal("the initiator-role node accepted a Hello and moved a boundary. Role must " +
			"come from node id; a peer that can choose the role can choose which side of " +
			"the derivation it controls.")
	}
	expectSilence(t, a, "the initiator-role node must not answer a Hello")
}

// TestUpgradeResponderPromptStartsTheExchange7163 is the heal path for the
// order that actually happens on a live cluster.
//
// The operator commits the key on the PRIMARY; config-sync carries it to the
// secondary, which applies it and reconciles. Either node may therefore be
// keyed first. If the higher-id node is keyed second it cannot open the
// exchange — role is fixed by node id — so it prompts, and the prompt is what
// makes the exchange converge without a timer.
//
// FAIL-ON-REVERT: drop the Request arm from the receive switch, or the
// responder-role branch in beginAuthUpgrade, and this reds on a read deadline.
func TestUpgradeResponderPromptStartsTheExchange7163(t *testing.T) {
	const psk = "responder-prompt-psk-7163"
	a := newUpgEnd(t, psk, 0) // initiator by id
	b := newUpgEnd(t, psk, 1) // responder by id, keyed second

	// a reconciles while b is not keyed yet: nothing can complete.
	unkeyed := newUpgEnd(t, "", 1)
	_ = unkeyed

	b.sealedOut = b.ac.writeAuthed()
	b.s.ReconcileConnectionAuth("test")
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeRequest {
		t.Fatalf("expected a Request, got frame type %d", typ)
	}
	// The prompt must have made a open the exchange.
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("a Request must make the initiator-role node emit a Hello; got frame "+
			"type %d. Without this the exchange never starts when the higher-id node is "+
			"the one that becomes keyed.", typ)
	}
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeProof {
		t.Fatalf("expected a Proof, got frame type %d", typ)
	}
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
		t.Fatalf("expected a Confirm, got frame type %d", typ)
	}
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatalf("the prompted exchange must complete both directions "+
			"(a.read=%v a.write=%v b.read=%v b.write=%v)",
			a.ac.readAuthed(), a.ac.writeAuthed(), b.ac.readAuthed(), b.ac.writeAuthed())
	}
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("both ends must agree on both directions")
	}
}

// TestUpgradeConfirmForgeryDoesNotMoveTheReadBoundary7163 is why the Confirm
// carries a MAC even though the responder already authenticated the initiator
// at msg1.
//
// The Confirm is the responder's read boundary. On a not-yet-sealed stream
// anyone able to inject a frame could send one; if the responder acted on it,
// it would start requiring a trailer while the real initiator is still writing
// unsealed frames, and the connection would DROP.
//
// PAIRED: the forgery must be refused AND the genuine Confirm that follows it
// must still land, so "ignore all Confirms" cannot pass.
func TestUpgradeConfirmForgeryDoesNotMoveTheReadBoundary7163(t *testing.T) {
	const psk = "confirm-forgery-psk-7163"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello
	pump(t, b, a) // Proof

	forged := make([]byte, 1+syncAuthUpgradeConfirmLen)
	forged[0] = syncAuthUpgradeVersion
	for i := 1; i < len(forged); i++ {
		forged[i] = 0x5A
	}
	b.s.handleMessage(b.ac, syncMsgAuthUpgradeConfirm, forged)
	if b.ac.readAuthed() {
		t.Fatal("a forged Confirm moved the responder's read boundary. The real initiator " +
			"is still writing unsealed frames, so the next one fails the MAC and the " +
			"connection drops — the outcome this mechanism promises never happens.")
	}

	// The genuine Confirm still completes the exchange.
	pump(t, a, b)
	if !b.ac.readAuthed() {
		t.Fatal("the genuine Confirm must still land after a forgery was refused, or the " +
			"refusal above is indistinguishable from ignoring every Confirm")
	}
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("the exchange must complete")
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
	a := newUpgEnd(t, "in-place-upgrade-psk-6628", 0)
	b := newUpgEnd(t, "", 1) // no key: a pre-keying peer, or one declining

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello a -> b

	if b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("an unkeyed peer cannot authenticate anything")
	}
	expectSilence(t, b, "an unkeyed peer must answer a Hello with silence — anything else "+
		"would either leak that it is unkeyed or start an exchange it cannot finish")
	if a.ac.readAuthed() || a.ac.writeAuthed() {
		t.Fatal("the initiator must not switch on its own Hello")
	}
}

// TestReconcileConnectionAuthIsANoOpWhenAlreadyKeyed6628 binds the staleness
// test. The reconciler runs on EVERY commit, so an already-authenticated
// connection must cost nothing and, more importantly, must not restart the
// exchange — a second Hello mints a second ephemeral and leaves the peer
// answering a handshake this node no longer holds.
//
// FAIL-ON-REVERT: drop the authPSK comparison in beginAuthUpgrade and this
// reds with a spurious Hello on the wire.
func TestReconcileConnectionAuthIsANoOpWhenAlreadyKeyed6628(t *testing.T) {
	const psk = "in-place-upgrade-psk-6628"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)
	runUpgrade(t, a, b)
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("precondition: the connection must be authenticated at both ends")
	}

	// An unrelated commit, on BOTH roles: the initiator must not re-Hello and
	// the responder must not re-prompt. Checking only one of them would leave
	// the other's branch unbound, and the responder's is the newer of the two.
	a.s.ReconcileConnectionAuth("unrelated-commit")
	expectSilence(t, a, "a commit that does not change the key must put NOTHING on the "+
		"wire; restarting the exchange on a healthy connection leaves the peer answering "+
		"a handshake this node no longer holds")
	b.s.ReconcileConnectionAuth("unrelated-commit")
	expectSilence(t, b, "the responder-role node must not re-prompt on an unrelated commit")
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
	e := newUpgEnd(t, psk, 0)
	// Built by wrapSyncConn, NOT by hand. Hand-setting readKey/writeKey/authPSK
	// would bind the reconciler's comparison while leaving the STAMP unbound —
	// delete `ac.authPSK = ...` from wrapSyncConn and a hand-built fixture stays
	// green while every real connect-authenticated connection is churned on
	// every commit. Driving the production wrapper is the difference.
	// #7163: directional keys. Deliberately DIFFERENT bytes per direction —
	// the pre-#7163 shape used one key for both, which is the defect.
	frameKeys := syncNoiseKeys{
		readKey:  []byte("connect-time-read-key-32-bytes!!"),
		writeKey: []byte("connect-time-write-key-32-byte!!"),
	}
	wrapped := e.s.wrapSyncConn(0, e.ac.Conn, syncAuthAuthenticated, frameKeys)
	e.ac = wrapped
	e.s.mu.Lock()
	e.s.conn0 = wrapped
	e.s.mu.Unlock()
	if !wrapped.authed() {
		t.Fatal("precondition: wrapSyncConn must produce an authenticated connection")
	}

	e.s.ReconcileConnectionAuth("unrelated-commit")

	expectSilence(t, e, "a commit must put NOTHING on the wire for a connection that "+
		"already authenticated at connect time under the same key; starting an exchange "+
		"there churns a healthy stream and performs a mid-stream key switch for no reason")
	if !e.ac.authed() {
		t.Fatal("the connection must still be authenticated — a reconciler that tore it " +
			"down would satisfy the check above for the wrong reason")
	}
}

// TestInPlaceUpgradeRekeysOnRotation6628: the second property #6628 names —
// "rotation never revokes an existing connection's old derived frame key". An
// authenticated connection whose PSK is rotated must re-derive under the new
// key rather than keep sealing with the retired one.
//
// The rotation is also the one path where every frame of the exchange itself is
// SEALED, under the OLD key, while the boundaries move — so it exercises the
// switch-point discipline on a stream that is already authenticated rather than
// on a bare one.
func TestInPlaceUpgradeRekeysOnRotation6628(t *testing.T) {
	const first = "rotation-first-psk-6628"
	const second = "rotation-second-psk-6628"
	a := newUpgEnd(t, first, 0)
	b := newUpgEnd(t, first, 1)
	runUpgrade(t, a, b)
	oldKey := append([]byte(nil), a.ac.writeKey...)
	if len(oldKey) == 0 {
		t.Fatal("precondition: the first upgrade must have produced a frame key")
	}

	// Rotate both ends. The exchange is one-shot per key, so a rotation must be
	// able to start a new one.
	a.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 0, cluster: upgClusterID})
	b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 1, cluster: upgClusterID})
	assertFrameSequence(t, runUpgrade(t, a, b), upgradeFrameSequence)
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
	// And the rotated connection still carries traffic under the NEW keys.
	frame := encodeRawMessage(syncMsgSessionV4, []byte("post-rotation"))
	sealed := a.ac.sealFrame(frame)
	hdr := sealed[:syncHeaderSize]
	n := binary.LittleEndian.Uint32(hdr[8:12])
	if err := b.ac.verifyFrame(hdr, sealed[syncHeaderSize:syncHeaderSize+int(n)],
		sealed[syncHeaderSize+int(n):]); err != nil {
		t.Fatalf("a frame sealed after the rotation must verify at the peer: %v", err)
	}
}

// TestAuthUpgradeMessageTypesAreUnique6628 mirrors the #6650/#6629 guards. A
// receiver MISPARSES a known type used for two purposes, so every upgrade frame
// number has to be unique across the whole live set.
func TestAuthUpgradeMessageTypesAreUnique6628(t *testing.T) {
	t.Parallel()
	for _, under := range []struct {
		v    int
		name string
	}{
		{syncMsgAuthUpgradeHello, "syncMsgAuthUpgradeHello"},
		{syncMsgAuthUpgradeProof, "syncMsgAuthUpgradeProof"},
		{syncMsgAuthUpgradeConfirm, "syncMsgAuthUpgradeConfirm"},
		{syncMsgAuthUpgradeRequest, "syncMsgAuthUpgradeRequest"},
	} {
		live := liveSyncMessageTypesExcept(under.v)
		if len(live) < 35 {
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
