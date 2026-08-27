package cluster

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// #6669 r18 — WIRING binders for the guards the finding-1 enumeration proved
// decorative.
//
// The recurring defect on this PR is one shape, found four times: THE INNER
// GUARD IS BOUND AND THE WIRING TO IT IS NOT. Each of those tests calls the
// helper directly and asserts the helper behaves; none asserts that production
// REACHES the helper. Measured, with the whole pkg/cluster suite GREEN under
// each revert:
//
//   - heartbeatSender.send reverted to a per-sender nonce — the Manager-scoped
//     nonce is bypassed and TestHeartbeatNonceIsIncarnationScoped_6169 still
//     PASSES, because it calls m.heartbeatNonce() itself and builds two senders
//     it never uses (`_ = s1; _ = s2`).
//   - the three epoch counters moved back under `receiver != nil` in
//     HeartbeatStats — the WRITES are bound, the EXPOSURE is not.
//
// So these tests assert through the PRODUCTION path — a real UDP socket and
// the real readLoop for the send site, and Manager.HeartbeatStats() for the
// stats site — and never re-invoke the helper the site is supposed to call.

// sendCapture brings up a real sender and a real receiver on loopback and
// returns both, plus the receiver's Manager. It is deliberately the same shape
// as wireEpochNodes: the point of these tests is that nothing about the frame
// is synthesised by the test.
func sendCapture(t *testing.T) (senderMgr *Manager, sendConn *net.UDPConn, peer *net.UDPAddr, recv *heartbeatReceiver) {
	t.Helper()

	senderMgr = keyedEpochManager(t, filepath.Join(t.TempDir(), "ha-boot-epoch"))
	recvMgr := epochGateManagerWithKey(epochTestPSK)
	recvMgr.nodeID = 1

	recvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("receiver socket: %v", err)
	}
	sendConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		recvConn.Close()
		t.Fatalf("sender socket: %v", err)
	}
	recv = newHeartbeatReceiver(recvMgr, recvConn, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	recvMgr.mu.Lock()
	recvMgr.hbReceiver = recv
	recvMgr.mu.Unlock()
	recv.start()
	t.Cleanup(recv.stop)
	t.Cleanup(func() { sendConn.Close() })

	senderMgr.heartbeatBootEpoch()
	awaitFirstRefine(t, senderMgr, "the sender's boot-epoch refinement")
	return senderMgr, sendConn, recvConn.LocalAddr().(*net.UDPAddr), recv
}

// boundEpochSessions reads how many peer sessions the receiver has bound at the
// current floor. That is the production-visible consequence of the send site's
// nonce scope: one incarnation that keeps ONE session spends ONE slot, and one
// that re-draws per heartbeatSender spends a slot per restart.
func boundEpochSessions(r *heartbeatReceiver) int {
	r.auth.mu.Lock()
	defer r.auth.mu.Unlock()
	return r.auth.highEpochSessionCount
}

// awaitReceived blocks until the receiver has counted at least n frames, or
// fails. It is a rendezvous on the receiver's own counter, not a sleep.
func awaitReceived(t *testing.T, r *heartbeatReceiver, n uint64, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r.received.Load() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s: receiver saw %d frames, want >= %d", what, r.received.Load(), n)
}

// TestSendSiteUsesTheIncarnationNonce_6669 binds the SEND SITE, not the
// accessor.
//
// A daemon mints a new heartbeatSender on every VRF rebind and HA comms
// restart. If send() draws its own session, one incarnation emits a session per
// restart under ONE boot epoch, which is exactly the ring churn the epoch floor
// exists to stop — and the existing nonce test cannot see it, because it never
// runs send().
//
// PRODUCTION EDIT THAT MAKES THIS FAIL (single line, heartbeat.go
// heartbeatSender.send): replace
//
//	session, counter := s.mgr.heartbeatNonce()
//
// with a per-sender draw (e.g. `session, counter := randomSessionID(),
// s.sendErrors.Add(1)`). The second incarnation then spends a second slot at
// the same floor and the assertion below reports 2.
func TestSendSiteUsesTheIncarnationNonce_6669(t *testing.T) {
	senderMgr, sendConn, peer, recv := sendCapture(t)

	// Incarnation A: the first heartbeatSender.
	s1 := newHeartbeatSender(senderMgr, sendConn, peer, DefaultHeartbeatInterval)
	s1.send()
	awaitReceived(t, recv, 1, "first sender's frame")

	if got := boundEpochSessions(recv); got != 1 {
		t.Fatalf("after the first sender: %d session(s) bound at the floor, want 1", got)
	}

	// A HEARTBEAT RESTART on the SAME daemon: a brand-new heartbeatSender over
	// the same Manager. This is the VRF-rebind / comms-restart shape.
	s2 := newHeartbeatSender(senderMgr, sendConn, peer, DefaultHeartbeatInterval)
	s2.send()
	awaitReceived(t, recv, 2, "second sender's frame")

	if got := boundEpochSessions(recv); got != 1 {
		t.Fatalf("after a heartbeat restart: %d sessions bound at ONE boot epoch, want 1. "+
			"heartbeatSender.send is drawing its own nonce instead of the Manager's, so every "+
			"VRF rebind and comms restart mints a fresh session under one epoch — the ring churn "+
			"the epoch floor exists to bound", got)
	}
}

// TestEpochCountersAreExposedWithoutAReceiver_6669 binds the EXPOSURE path.
//
// The counters are written on the admission path and read through
// Manager.HeartbeatStats(). A receiver-scoped READ reports real, nonzero
// counters as zero during the window between StopHeartbeat and the next
// StartHeartbeat — a VRF rebind — which is exactly when an operator is most
// likely to be looking. The existing stats test covers only PeerEpochLatched,
// EpochlessAdmitted and EpochDowngradeRejected.
//
// PRODUCTION EDIT THAT MAKES THIS FAIL (heartbeat_manager.go HeartbeatStats):
// move the three assignments below back under `if receiver != nil {`. The
// counters keep their values; the accessor stops reporting them.
func TestEpochCountersAreExposedWithoutAReceiver_6669(t *testing.T) {
	e := newLatchEnv(t)

	// Drive the counters through the REAL admission path rather than by
	// touching the atomics, so this cannot pass against a gate that never runs.
	// An epoch beyond year 2200 is out-of-band; one inside the plausible band
	// but past the forward bound is ahead-of-clock.
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xC001, 1, epochPlausibleMax+1)) {
		t.Fatal("an out-of-band epoch was admitted; the fixture must produce a refusal")
	}
	ahead := uint64(epochNowNanos()) + bootEpochMaxSkew*4
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xC002, 1, ahead)) {
		t.Fatal("an ahead-of-clock epoch was admitted; the fixture must produce a refusal")
	}

	// The receiver is what a VRF rebind removes.
	e.m.mu.Lock()
	e.m.hbReceiver = nil
	e.m.mu.Unlock()

	st := e.m.HeartbeatStats()
	if st.EpochOutOfBandRejected == 0 {
		t.Fatal("HeartbeatStats reports EpochOutOfBandRejected=0 with no receiver installed, " +
			"but the counter was incremented on the admission path: the exposure is " +
			"receiver-scoped, so a VRF rebind blanks a real refusal count")
	}
	if st.EpochAheadOfClockRejected == 0 {
		t.Fatal("HeartbeatStats reports EpochAheadOfClockRejected=0 with no receiver installed, " +
			"but the counter was incremented on the admission path")
	}
}

// TestEpochCountersStillExposedWithAReceiver_6669 is the negative control for
// the test above, in its own body: the fix must be "read the process-scoped
// state" and not "always report the same thing regardless of state". If the
// counters were hard-wired non-zero, this would still pass — so it asserts the
// UNTOUCHED counter is zero while the driven ones are not.
func TestEpochCountersStillExposedWithAReceiver_6669(t *testing.T) {
	e := newLatchEnv(t)

	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xC101, 1, epochPlausibleMax+1)) {
		t.Fatal("an out-of-band epoch was admitted; the fixture must produce a refusal")
	}

	st := e.m.HeartbeatStats()
	if st.EpochOutOfBandRejected == 0 {
		t.Fatal("EpochOutOfBandRejected=0 WITH a receiver installed; the counter is not being read")
	}
	if st.EpochAheadOfClockRejected != 0 {
		t.Fatalf("EpochAheadOfClockRejected = %d with nothing driving it, want 0: the accessor is "+
			"not reporting real state", st.EpochAheadOfClockRejected)
	}
}

// TestRunningSenderDoesNotRecoverByWaiting_6669 is the guard that makes the
// corrected claim true and the old one false (#6669 r18, Codex finding 6 —
// the production side of the decorative guard 1d).
//
// TestInBoundFarFutureEpochLockoutIsBounded_6169's "BOUND 1 — the lockout
// cannot exceed the slack ... with no operator action at all" feeds
// captureIncarnation(0xEE03, inBound+1, …) — a NEW session at a NEW epoch. The
// rejected sender is 0xEE02 and is never re-fed. So it proves a FRESH
// incarnation above the floor is admitted, which nobody disputed, and asserts
// nothing whatsoever about the sender that is actually locked out.
//
// The running sender resolves its epoch once at boot and caches it for the life
// of the process, so its frames are byte-identical however long anyone waits.
// This test re-feeds THAT SAME incarnation with the receiver's clock advanced
// PAST the floor and asserts it is STILL REFUSED — which is what makes
// "recovery is a sender restart" true and "climbs past it unattended" false.
//
// PRODUCTION EDIT THAT MAKES THIS FAIL: none is needed or possible — this
// pins a RESIDUAL, not a guard, and it is the assertion the corrected comment
// and README sentence now rest on. Its fail-on-revert is TEXTUAL: restore
// either "self-limiting window" (heartbeat_epoch.go) or "climbs past it
// unattended" (README.md) and the claim contradicts this test's measured
// result. That is the honest description; calling it a behavioural guard would
// be the same overstatement this test exists to retire.
func TestRunningSenderDoesNotRecoverByWaiting_6669(t *testing.T) {
	e := newLatchEnv(t)
	now := uint64(epochNowNanos())

	// A peer whose clock is ahead but INSIDE the skew allowance: latched.
	inBound := now + bootEpochMaxSkew/2
	e.liveRun(e.captureIncarnation(0xEE01, inBound, epochFramesPerIncarnation),
		"peer with a clock inside the skew allowance")
	if got := e.r.auth.peerEpochFloor(); got != inBound {
		t.Fatalf("floor = %d, want %d", got, inBound)
	}

	// The peer is repaired and comes back at real time: BELOW the floor.
	// THIS is the incarnation that is locked out, and the one the existing
	// test never returns to.
	repaired := e.captureIncarnation(0xEE02, now, epochFramesPerIncarnation)
	for i, f := range repaired {
		if e.feed(f) {
			t.Fatalf("repaired peer frame %d admitted; expected refusal below the floor", i)
		}
	}

	// TIME PASSES — well beyond the whole slack. Injected, never slept: the
	// claim under test is about elapsed wall-clock time, so the clock is the
	// variable and it is set explicitly.
	withPinnedEpochClock(t, int64(inBound+bootEpochMaxSkew))

	// The SAME incarnation sends again. Its epoch is cached from boot, so the
	// frames it emits now are the frames it emitted before.
	stillRunning := e.captureIncarnation(0xEE02, now, epochFramesPerIncarnation)
	admitted := 0
	for _, f := range stillRunning {
		if e.feed(f) {
			admitted++
		}
	}
	if admitted != 0 {
		t.Fatalf("%d/%d frames from the ALREADY-RUNNING sender were admitted after the wall clock "+
			"passed the floor. If that is genuinely the behaviour, the README sentence about the "+
			"seed climbing past the floor unattended is true and this test is wrong — but the "+
			"sender caches its epoch at boot (bootEpochOnce), so it cannot be",
			admitted, len(stillRunning))
	}

	// And the documented recovery DOES work: a sender RESTART seeds from the
	// advanced clock and is admitted on the raise path. Without this half the
	// test would read as "the peer is permanently stuck", which is the opposite
	// overstatement.
	e.liveRun(e.captureIncarnation(0xEE03, inBound+bootEpochMaxSkew/2, epochFramesPerIncarnation),
		"a RESTARTED sender seeded from the advanced clock")
}

// TestStartHeartbeatResolvesTheBootEpoch_6669 binds the CALL, not the callee.
//
// heartbeat_epoch_latch_test.go's TestStartHeartbeatReturnsWithAUsableEpoch
// calls m.heartbeatBootEpoch() itself and marshals its own "first" frame, so it
// pins what the resolver returns and asserts nothing about StartHeartbeat
// invoking it. Deleting the `m.initHeartbeatEpochState()` line outright leaves
// the whole pkg/cluster suite GREEN — measured.
//
// This drives the REAL entry point and reads the published cell WITHOUT calling
// the resolver, which is the whole point: touching heartbeatBootEpoch() here
// would publish the value the test is trying to observe and mask the deletion.
// The sender only emits on a ticker tick (heartbeatSender.run), so nothing
// races the read.
//
// PRODUCTION EDIT THAT MAKES THIS FAIL (single line, heartbeat_manager.go
// StartHeartbeat): delete `m.initHeartbeatEpochState()`. Nothing then publishes
// an epoch and bootEpoch stays 0.
func TestStartHeartbeatResolvesTheBootEpoch_6669(t *testing.T) {
	m := keyedEpochManager(t, filepath.Join(t.TempDir(), "ha-boot-epoch"))

	if got := m.bootEpoch.Load(); got != 0 {
		t.Fatalf("precondition: bootEpoch = %d before StartHeartbeat, want 0 — the fixture must "+
			"start unresolved or this test cannot observe the call", got)
	}

	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", ""); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	t.Cleanup(m.StopHeartbeat)

	if got := m.bootEpoch.Load(); got == 0 {
		t.Fatal("bootEpoch = 0 after StartHeartbeat returned: nothing invoked " +
			"initHeartbeatEpochState, so this node's first frames carry NO epoch. A latched peer " +
			"reads an epoch-less frame from an epoch-capable build as a rollback and refuses it")
	}
}
