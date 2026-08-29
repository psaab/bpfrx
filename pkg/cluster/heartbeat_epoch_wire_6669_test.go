package cluster

import (
	"math"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #6669 fold round 15 — THE PRODUCTION WIRING, at both ends.
//
// Every other epoch test in this package drives the auth gate with a frame the
// TEST marshalled, through a helper the TEST wrote. That leaves the two lines
// that actually carry the mechanism in production unbound, and both were
// measured severable with the whole package green:
//
//   - the SEND site, heartbeatSender.send: pass 0 instead of
//     mgr.heartbeatBootEpoch() and marshalHeartbeatAuthEpoch emits a
//     byte-identical LEGACY frame. Both nodes run "#6169", neither receiver ever
//     latches, and the sustained replay this change exists to close is fully
//     open — with green CI.
//   - the RECEIVE site, heartbeatReceiver.admitFrame: sever the
//     `if macOK { epoch, hasEpoch = heartbeatFrameEpoch(...) }` read and the
//     receiver treats every frame as epochless, so the floor is never consulted
//     and the latch never arms.
//
// A test that re-invokes marshalHeartbeatAuthEpoch with the sender's own
// arguments cannot see either: it RESTATES the send site rather than observing
// it, and it never reaches readLoop at all. So this file uses the real
// heartbeatSender, a real UDP socket, and the real readLoop goroutine, and
// asserts on what arrives at the far end.
//
// The receive half is additionally deduplicated rather than merely tested: the
// epoch fixtures' feed helpers now DELEGATE to heartbeatReceiver.admitFrame
// instead of restating its gate. See admitFrame.

// wireEpochNodes brings up one real sender and one real receiver on loopback,
// keyed with the same PSK and given distinct node ids so the receiver does not
// discard the frame as a duplicate-node-id (#4549 F11).
//
// The sender's Manager is the one that resolves an epoch — heartbeatSender.send
// is a caller of heartbeatBootEpoch — so its epoch store is redirected to a
// per-test file and its refine worker is joined before anything is sent. The
// receiver's Manager never resolves one, so it needs neither.
func wireEpochNodes(t *testing.T) (sender *heartbeatSender, recv *heartbeatReceiver, senderMgr, recvMgr *Manager) {
	t.Helper()

	senderMgr = keyedEpochManager(t, filepath.Join(t.TempDir(), "ha-boot-epoch"))
	recvMgr = epochGateManagerWithKey(epochTestPSK)
	recvMgr.nodeID = 1 // the peer of node 0, which is what senderMgr is

	recvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("receiver socket: %v", err)
	}
	sendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		recvConn.Close()
		t.Fatalf("sender socket: %v", err)
	}

	recv = newHeartbeatReceiver(recvMgr, recvConn, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	recvMgr.mu.Lock()
	recvMgr.hbReceiver = recv
	recvMgr.mu.Unlock()
	recv.start() // the REAL readLoop goroutine, reading the REAL socket
	t.Cleanup(recv.stop)

	sender = newHeartbeatSender(senderMgr, sendConn, recvConn.LocalAddr().(*net.UDPAddr),
		DefaultHeartbeatInterval)
	t.Cleanup(func() { sendConn.Close() })

	// Resolve and settle the epoch BEFORE the first send, so the value asserted
	// below cannot be raised out from under the assertion by the refine worker.
	senderMgr.heartbeatBootEpoch()
	awaitFirstRefine(t, senderMgr, "the sender's boot-epoch refinement")
	return sender, recv, senderMgr, recvMgr
}

// TestBootEpochTraversesTheRealSendAndReceivePath_6169 is the fail-on-revert
// gate for the production wiring at BOTH ends.
//
// RED-on-revert, measured, two independent mutations:
//
//   - heartbeat.go heartbeatSender.send — replace
//     `s.mgr.heartbeatBootEpoch()` with `0`.
//   - heartbeat.go heartbeatReceiver.admitFrame — replace `if macOK {` with
//     `if macOK && false {` on the heartbeatFrameEpoch read.
//
// Either one leaves the rest of pkg/cluster green and fails the latch assertion
// below with an assertion message, not a build break.
func TestBootEpochTraversesTheRealSendAndReceivePath_6169(t *testing.T) {
	// THE OBSERVATION HALF: what the real sender actually puts on the wire.
	// Named separately from the end-to-end case so a severed SEND site is
	// diagnosed as a sender fault rather than a receiver one.
	t.Run("the_real_sender_signs_an_epoch_onto_the_wire", func(t *testing.T) {
		senderMgr := keyedEpochManager(t, filepath.Join(t.TempDir(), "ha-boot-epoch"))
		sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("sink socket: %v", err)
		}
		defer sink.Close()
		sendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("sender socket: %v", err)
		}
		defer sendConn.Close()

		senderMgr.heartbeatBootEpoch()
		awaitFirstRefine(t, senderMgr, "the sender's boot-epoch refinement")
		want := senderMgr.heartbeatBootEpoch()
		if want == 0 {
			t.Fatal("the sender published no epoch at all; heartbeatBootEpoch must never return 0")
		}

		s := newHeartbeatSender(senderMgr, sendConn, sink.LocalAddr().(*net.UDPAddr),
			DefaultHeartbeatInterval)
		s.send()

		buf := make([]byte, maxHeartbeatSize)
		sink.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := sink.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("nothing arrived from the real sender: %v", err)
		}
		frame := buf[:n]

		// Read it back the way the receiver does, with the receiver's key.
		got, present := heartbeatFrameEpoch(frame, senderMgr.controlLinkAuthKey())
		if !present {
			t.Fatalf("the frame heartbeatSender.send put on the wire carries NO epoch section "+
				"(len=%d). The send site is not passing an epoch, so no peer can ever latch and "+
				"the #6169 sustained replay is wide open on a build that reports itself fixed.", n)
		}
		if got != want {
			t.Fatalf("on-wire epoch = %d, but this incarnation published %d — the send site is "+
				"signing something other than its own boot epoch", got, want)
		}
	})

	// THE END-TO-END HALF: the real sender's datagram, through the real socket,
	// into the real readLoop. This is the one that binds BOTH mutations.
	t.Run("the_real_readLoop_latches_what_the_real_sender_sent", func(t *testing.T) {
		sender, recv, senderMgr, recvMgr := wireEpochNodes(t)
		want := senderMgr.heartbeatBootEpoch()

		sender.send()

		// OVER-REACH GUARD, and it is deliberately asserted FIRST: neither
		// mutation may break peer liveness. A legacy (epoch-less) frame is still
		// dual-accepted, so under both mutations this stays GREEN and the
		// failure lands on the epoch assertions below. If this one ever goes red
		// the change under test has broken availability, which is a different
		// and worse fault than the one being guarded.
		deadline := time.Now().Add(5 * time.Second)
		for recv.received.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
		if got := recv.received.Load(); got != 1 {
			t.Fatalf("readLoop accepted %d frames, want 1 — the real sender's datagram never "+
				"reached the real receiver, so nothing below measures the epoch path "+
				"(recvErrors=%d)", got, recv.recvErrors.Load())
		}

		if !recvMgr.hbAuth.peerEpochLatched() {
			t.Fatal("#6169: one authenticated heartbeat travelled from the real heartbeatSender " +
				"through a real UDP socket into the real readLoop, and the receiver did NOT " +
				"latch a boot epoch. Either the send site is not signing one or the receive " +
				"site is not reading one; with the latch unarmed a pre-upgrade epoch-less " +
				"capture set replays indefinitely, which is the whole of #6169.")
		}
		if got := recvMgr.hbAuth.peerEpochFloor(); got != want {
			t.Fatalf("#6169: the receiver's floor is %d but the sender published %d — the value "+
				"that crossed the wire is not this incarnation's boot epoch", got, want)
		}
	})
}

// epochDowngradeWarned reports whether the rate-limited epoch-downgrade warning
// has fired on this Manager. It is the only observable effect of the
// NoteEpochDowngradeHeartbeat CALL SITE — the refusal itself is counted on the
// auth state (EpochDowngradeRejected), by admitAuthed, and therefore stays
// green when the call site is deleted.
func epochDowngradeWarned(m *Manager) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !m.lastEpochDowngradeWarn.IsZero()
}

// TestEpochDowngradeIsRaisedOnTheRealReceivePath_6169 binds the
// NoteEpochDowngradeHeartbeat CALL SITE inside admitFrame, not the method.
//
// The method's own test calls Manager.NoteEpochDowngradeHeartbeat DIRECTLY and
// asserts on the warning text, so the call site in the reject arm could be
// deleted with the suite green. The refusal is bound elsewhere; the
// operator-facing signal that says WHY — the one that separates a deliberate
// rollback from generic replay noise, and is the only place the rotate-then-
// restart recovery is stated — was not.
//
// RED-on-revert: delete the
// `if macOK && !hasEpoch && r.auth.peerEpochLatched()` block in admitFrame.
func TestEpochDowngradeIsRaisedOnTheRealReceivePath_6169(t *testing.T) {
	t.Run("a_refused_downgrade_raises_the_warning", func(t *testing.T) {
		e := newEpochEnv(t)

		// The peer proves it emits epochs, which arms the latch.
		e.liveRun(e.captureIncarnation(0x6F10, 9_300_000_000_000_000, epochFramesPerIncarnation),
			"live epoch-capable incarnation")
		if !e.r.auth.peerEpochLatched() {
			t.Fatal("an accepted epoch-bearing frame must arm the downgrade latch")
		}
		if epochDowngradeWarned(e.m) {
			t.Fatal("the downgrade warning fired before any downgrade arrived")
		}

		// Now an epoch-LESS frame from that same peer: a rollback, or a replayed
		// pre-upgrade capture. It must be refused AND surfaced.
		for i, f := range e.captureIncarnation(0x6F11, 0, epochFramesPerIncarnation) {
			if e.feed(f) {
				t.Fatalf("epoch-less frame %d admitted after the latch armed", i)
			}
		}
		if got := e.m.HeartbeatStats().EpochDowngradeRejected; got == 0 {
			t.Fatal("no downgrade was rejected; this subtest is not exercising the arm it says")
		}
		if !epochDowngradeWarned(e.m) {
			t.Fatal("#6169: the downgrade was refused but the operator-facing warning was never " +
				"raised on the real receive path. That warning is the only place the complete " +
				"recovery (rotate the PSK on BOTH nodes, THEN restart) is stated, so a " +
				"deliberate rollback is indistinguishable from ordinary replay noise and the " +
				"operator loops on restarts that cannot clear the latch.")
		}
	})

	// NEGATIVE CONTROL, on a fresh Manager so the 30s dampener cannot hide the
	// result: a frame that fails MAC verification is a rejection but NOT a
	// downgrade, and must not raise this warning. Without it the assertion above
	// is satisfied by any signal that fires on every rejection.
	t.Run("an_unverifiable_frame_is_not_a_downgrade", func(t *testing.T) {
		e := newEpochEnv(t)
		e.liveRun(e.captureIncarnation(0x6F20, 9_300_000_000_000_000, epochFramesPerIncarnation),
			"live epoch-capable incarnation")

		forged := e.captureIncarnation(0x6F21, 0, 1)[0]
		forged[len(forged)-1] ^= 0xFF
		if e.feed(forged) {
			t.Fatal("a frame with a corrupted MAC was admitted")
		}
		if epochDowngradeWarned(e.m) {
			t.Fatal("an unverifiable frame raised the epoch-downgrade warning — the warning " +
				"must name epoch downgrades, not rejections in general, or its recovery " +
				"instructions are handed to operators whose peer never rolled back")
		}
	})
}

// TestNonReplayEpochRefusalsAreNamedAndCounted_6669 binds the two epoch
// refusals that are NOT replays.
//
// Both arms used to `return false` with no counter, and heartbeatAuthDecision —
// which sees only `nonceFresh == false` — logged them as "stale nonce
// (replay)". That is not a cosmetic imprecision. Each has a DIFFERENT operator
// action, and neither is the one "replay" implies:
//
//   - out-of-band epoch: the PEER is emitting 0 or a post-2200 value. A
//     conforming #6169 build cannot; check the peer's state file or its build.
//   - beyond the forward bound: a CLOCK fault, and usually a perfectly healthy
//     peer. Check NTP on both nodes. Reading this one as a replay sends an
//     operator hunting an on-link attacker during what is an NTP problem.
//
// RED-on-revert: drop either `s.epochOutOfBandRejected.Add(1)` /
// `s.epochRaiseDeclinedAheadOfClock.Add(1)`, or collapse either arm's reason back to
// a bare `return false, ""`.
func TestNonReplayEpochRefusalsAreNamedAndCounted_6669(t *testing.T) {
	t.Run("out_of_band_epoch", func(t *testing.T) {
		var s heartbeatAuthState
		ok, reason := s.admitAuthed(true, math.MaxUint64, 0x7001, 1)
		if ok {
			t.Fatal("an out-of-band epoch must be refused")
		}
		if got := s.epochOutOfBandRejected.Load(); got != 1 {
			t.Fatalf("epochOutOfBandRejected = %d, want 1 — the refusal is invisible to an "+
				"operator, so a peer emitting corrupt epochs looks like an attack", got)
		}
		if reason == "" {
			t.Fatal("#6669: an out-of-band epoch was refused with NO reason, so the log says " +
				"\"stale nonce (replay)\". It is not a replay — it is a corrupt state file or " +
				"a peer that is not a conforming #6169 build, and the operator is sent to " +
				"the wrong place.")
		}
		if !strings.Contains(reason, "outside the plausible range") {
			t.Fatalf("the out-of-band reason does not name the range: %q", reason)
		}
		// The OTHER counter must not move — the two arms are distinguishable.
		if got := s.epochRaiseDeclinedAheadOfClock.Load(); got != 0 {
			t.Fatalf("the clock-skew counter moved (%d) on an out-of-band refusal; the two "+
				"arms must be separable or the split buys nothing", got)
		}
	})

	t.Run("epoch_beyond_the_forward_bound", func(t *testing.T) {
		var s heartbeatAuthState
		ahead := uint64(time.Now().UnixNano()) + bootEpochMaxSkew*3
		if !epochUsableAsFloor(ahead) {
			t.Fatalf("fixture broken: %d must be INSIDE the absolute band, or this measures "+
				"the out-of-band arm instead", ahead)
		}
		ok, reason := s.admitAuthed(true, ahead, 0x7002, 1)
		if ok {
			t.Fatal("an epoch beyond the forward bound must be refused")
		}
		if got := s.epochRaiseDeclinedAheadOfClock.Load(); got != 1 {
			t.Fatalf("epochRaiseDeclinedAheadOfClock = %d, want 1", got)
		}
		if reason == "" {
			t.Fatal("#6669: an epoch past the forward bound was refused with NO reason, so " +
				"the log says \"stale nonce (replay)\" for what is a CLOCK fault on a healthy " +
				"peer. The operator opens a security incident instead of checking NTP.")
		}
		if !strings.Contains(reason, "NTP") {
			t.Fatalf("the forward-bound reason does not name the action (NTP): %q", reason)
		}
		if got := s.epochOutOfBandRejected.Load(); got != 0 {
			t.Fatalf("the out-of-band counter moved (%d) on a clock-skew refusal", got)
		}
	})

	// NEGATIVE CONTROL. A frame BELOW the floor is a genuine replay of a retired
	// incarnation, so it must carry NO epoch-specific reason — the generic
	// "stale nonce (replay)" wording is already correct there. Without this, the
	// assertions above are satisfied by a change that hands every refusal a
	// reason, which would relabel a real replay as something else.
	t.Run("below_floor_stays_a_replay", func(t *testing.T) {
		var s heartbeatAuthState
		const floor = uint64(9_600_000_000_000_000)
		if ok, _ := s.admitAuthed(true, floor, 0x7003, 1); !ok {
			t.Fatal("setup: the first in-range epoch must be admitted and set the floor")
		}
		ok, reason := s.admitAuthed(true, floor-1, 0x7004, 1)
		if ok {
			t.Fatal("an epoch below the floor must be refused")
		}
		if reason != "" {
			t.Fatalf("a below-floor frame IS a replay of a retired incarnation, so it must "+
				"keep the generic replay wording; got a distinct reason %q", reason)
		}
		if s.epochOutOfBandRejected.Load() != 0 || s.epochRaiseDeclinedAheadOfClock.Load() != 0 {
			t.Fatal("a below-floor replay moved one of the two non-replay counters")
		}
	})
}
