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
	recv = newHeartbeatReceiver(recvMgr, recvConn, DefaultHeartbeatThreshold, DefaultHeartbeatInterval)
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
