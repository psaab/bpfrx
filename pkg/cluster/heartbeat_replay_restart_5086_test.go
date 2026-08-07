package cluster

import (
	"testing"
	"time"
)

// #5086: the heartbeat anti-replay tracker must not be reset by a heartbeat
// restart.
//
// #5477 gave the receiver a bounded set of retired-session watermarks so a
// captured A->B->A alternation is rejected. That tracker lived on the
// heartbeatReceiver, and EVERY StartHeartbeat builds a new receiver —
// including RestartHeartbeat on a DHCP-triggered VRF rebind and the HA
// comms (re)start, both routine runtime events. The replacement receiver
// therefore began with an EMPTY tracker, so every captured frame from a
// retired peer incarnation looked never-seen and was admitted again,
// refreshing peer liveness for the whole captured run. The fix anchors the
// state to the Manager (process lifetime).
//
// The tests below drive the REAL readLoop auth gate and the REAL liveness
// machinery (r.lastSeen -> checkTimeout -> handlePeerTimeout).

// replay5086Env is one node's view: a Manager plus whichever heartbeat
// receiver is currently installed.
type replay5086Env struct {
	t   *testing.T
	m   *Manager
	r   *heartbeatReceiver
	key []byte
}

func newReplay5086Env(t *testing.T) *replay5086Env {
	t.Helper()
	m := epochGateManager()
	e := &replay5086Env{t: t, m: m, key: m.controlLinkAuthKey()}
	e.restartHeartbeat()
	return e
}

// restartHeartbeat models what StartHeartbeat/RestartHeartbeat do to the
// receiver: the old one is dropped and a brand-new one is built by
// newHeartbeatReceiver and installed on the Manager. The sockets are not
// created (no goroutines are started); this test drives the read path
// directly.
func (e *replay5086Env) restartHeartbeat() {
	e.t.Helper()
	e.r = newHeartbeatReceiver(e.m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval)
	// start() would set this; back-date it past the cold-boot grace so
	// peer-lost decisions are not suppressed by the #4386 startup floor.
	e.r.startedAt = time.Now().Add(-2 * heartbeatStartupGrace)
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
}

// feed pushes one raw frame through the gate readLoop applies, by CALLING it —
// heartbeatReceiver.admitFrame is the single implementation both use, so the
// accept-side consequences (lastSeen, handlePeerHeartbeat) are production's,
// not a copy of them. It reports whether the frame was accepted.
//
// This helper too used to restate the gate; see admitFrame for why a restated
// gate let the receiver's epoch read be severed with the suite green.
func (e *replay5086Env) feed(frame []byte) bool {
	e.t.Helper()
	pkt, err := UnmarshalHeartbeat(frame)
	if err != nil {
		e.t.Fatalf("unmarshal: %v", err)
	}
	return e.r.admitFrame(frame, pkt)
}

// capture builds the authenticated frames an on-link attacker records off the
// wire for one peer incarnation (session) — a run of n heartbeats.
func (e *replay5086Env) capture(session uint64, n int) [][]byte {
	e.t.Helper()
	frames := make([][]byte, 0, n)
	for c := 1; c <= n; c++ {
		frames = append(frames, MarshalHeartbeatAuth(samplePkt(), e.key, session, uint64(c)))
	}
	return frames
}

// peerDiedAgo rewrites lastSeen so the last GENUINE heartbeat is `age` old,
// modelling a peer that stopped transmitting `age` ago.
func (e *replay5086Env) peerDiedAgo(age time.Duration) {
	e.r.lastSeen.Store(MonotonicNanos() - age.Nanoseconds())
}

// TestHeartbeatReplayRejectedAfterHeartbeatRestart_5086 is the #5086
// fail-on-revert gate. An attacker records authenticated heartbeats from two
// retired peer incarnations A and B. The peer then DIES. A routine heartbeat
// restart happens on the surviving node (VRF rebind / comms restart). The
// attacker replays A->B->A->B... into the new receiver.
//
// Every replayed frame must be REJECTED, none may refresh peer liveness, and
// the peer must still be declared dead on the normal schedule
// (threshold * interval).
//
// RED-on-revert: the fix is binding the receiver's auth state to the Manager
// (heartbeat.go newHeartbeatReceiver `auth: mgr.heartbeatAuthState()` +
// Manager.hbAuth). Reverting it to a per-receiver tracker — e.g.
// `auth: &heartbeatAuthState{}` in newHeartbeatReceiver — makes the restarted
// receiver start empty, every replayed frame is admitted as never-seen,
// lastSeen is refreshed, and the peer is NEVER declared dead.
func TestHeartbeatReplayRejectedAfterHeartbeatRestart_5086(t *testing.T) {
	e := newReplay5086Env(t)

	const (
		sessA = 0xA11CE
		sessB = 0xB0B
	)
	capturedA := e.capture(sessA, 10)
	capturedB := e.capture(sessB, 10)

	// Phase 1 — the genuine peer runs incarnation A, reboots into B. The
	// attacker records both runs off the wire; this node accepts them.
	for _, f := range capturedA {
		if !e.feed(f) {
			t.Fatal("genuine incarnation A must be accepted")
		}
	}
	for _, f := range capturedB {
		if !e.feed(f) {
			t.Fatal("genuine reboot into incarnation B must be accepted")
		}
	}
	if !e.m.PeerAlive() {
		t.Fatal("peer must be alive after genuine heartbeats")
	}

	// Phase 2 — the peer DIES. Two full timeout windows pass with no genuine
	// traffic, then a routine heartbeat restart installs a new receiver.
	timeout := time.Duration(DefaultHeartbeatThreshold) * DefaultHeartbeatInterval
	e.peerDiedAgo(2 * timeout)
	lastSeenAtDeath := e.r.lastSeen.Load()

	e.restartHeartbeat()
	e.r.lastSeen.Store(lastSeenAtDeath) // liveness carries across the restart

	// Phase 3 — the attacker replays the captured A->B->A alternation.
	admitted := 0
	for round := 0; round < 3; round++ {
		for i := range capturedA {
			if e.feed(capturedA[i]) {
				admitted++
			}
			if e.feed(capturedB[i]) {
				admitted++
			}
		}
	}
	if admitted != 0 {
		t.Errorf("#5086: %d/%d replayed heartbeats were ADMITTED after a heartbeat restart; "+
			"a heartbeat restart must not reset the retired-session anti-replay state",
			admitted, 3*2*len(capturedA))
	}
	if got := e.r.lastSeen.Load(); got != lastSeenAtDeath {
		t.Errorf("#5086: replayed heartbeats refreshed peer liveness across a restart "+
			"(lastSeen %d -> %d); a replay must never refresh lastSeen", lastSeenAtDeath, got)
	}

	// Phase 4 — the peer is dead and nothing genuine has arrived, so the
	// normal peer-dead schedule must fire.
	e.r.checkTimeout()
	if e.m.PeerAlive() {
		t.Error("#5086: peer still reported ALIVE after a replay-only window — " +
			"a dead peer kept alive by replay defeats failover; the survivor never takes over")
	}
}

// TestHeartbeatRestartStillAcceptsGenuinePeer_5086 is the NEGATIVE CONTROL.
// Preserving anti-replay state across a heartbeat restart must not make the
// guard reject genuine traffic — that would convert a security bug into an
// availability bug (a peer wrongly declared dead is a split-brain risk).
//
// Three genuine post-restart cases must all still be accepted:
//
//	a) the peer never restarted and simply keeps counting (the common case);
//	b) the peer genuinely rebooted into a brand-new session;
//	c) that new session's counter restarts at 1, far BELOW the retired
//	   session's watermark — proving the guard keys on (session, counter) and
//	   not on a global monotonic counter that a real reboot would violate.
func TestHeartbeatRestartStillAcceptsGenuinePeer_5086(t *testing.T) {
	const (
		sessOld = 0xD00D
		sessNew = 0xFEED
	)

	// (a) live peer keeps counting across OUR heartbeat restart.
	t.Run("live peer continues across restart", func(t *testing.T) {
		e := newReplay5086Env(t)
		for _, f := range e.capture(sessOld, 50) {
			if !e.feed(f) {
				t.Fatal("genuine heartbeat must be accepted")
			}
		}
		e.restartHeartbeat()

		// The peer is alive and unaware we restarted: it keeps advancing the
		// SAME session past the watermark we remember.
		for c := 51; c <= 60; c++ {
			f := MarshalHeartbeatAuth(samplePkt(), e.key, sessOld, uint64(c))
			if !e.feed(f) {
				t.Fatalf("#5086 negative control: live peer's heartbeat (session %#x counter %d) "+
					"was REJECTED after a local heartbeat restart — preserved anti-replay state "+
					"must not lock out a peer that never restarted", uint64(sessOld), c)
			}
		}
		e.r.checkTimeout()
		if !e.m.PeerAlive() {
			t.Error("#5086 negative control: a live peer must stay ALIVE across a local heartbeat restart")
		}
	})

	// (b)+(c) genuine peer reboot after our restart: new session, counter
	// restarts at 1 — below the retired session's watermark.
	t.Run("genuine peer reboot after restart", func(t *testing.T) {
		e := newReplay5086Env(t)
		for _, f := range e.capture(sessOld, 50) {
			if !e.feed(f) {
				t.Fatal("genuine heartbeat must be accepted")
			}
		}
		e.restartHeartbeat()

		// The peer really rebooted: fresh random session, counter back to 1.
		first := MarshalHeartbeatAuth(samplePkt(), e.key, sessNew, 1)
		if !e.feed(first) {
			t.Fatal("#5086 negative control: a genuine peer REBOOT (new session, counter 1) " +
				"must be accepted on its FIRST frame after a local heartbeat restart — " +
				"rejecting it would wedge failover")
		}
		for c := 2; c <= 10; c++ {
			if !e.feed(MarshalHeartbeatAuth(samplePkt(), e.key, sessNew, uint64(c))) {
				t.Fatalf("#5086 negative control: rebooted peer counter %d must be accepted", c)
			}
		}
		e.r.checkTimeout()
		if !e.m.PeerAlive() {
			t.Error("#5086 negative control: a genuinely rebooted peer must be ALIVE")
		}
	})
}

// TestHeartbeatAuthStateOutlivesReceiver_5086 pins the structural invariant
// directly at the fix site: successive receivers built by newHeartbeatReceiver
// for the same Manager share ONE auth state, and its memory is a fixed
// per-Manager allocation that does not grow with restart count.
func TestHeartbeatAuthStateOutlivesReceiver_5086(t *testing.T) {
	m := NewManager(0, 42)

	first := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval)
	if first.auth == nil {
		t.Fatal("receiver auth state must never be nil")
	}
	// Record a peer session on the first receiver.
	if !first.auth.admitAuthed(false, 0, 0x1234, 7) {
		t.Fatal("first sighting of a session must be admitted")
	}
	first.auth.notePeerAuthenticated()

	// 100 heartbeat restarts.
	var last *heartbeatReceiver
	for i := 0; i < 100; i++ {
		last = newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval)
		if last.auth != first.auth {
			t.Fatalf("restart %d: receiver must share the Manager's auth state, not a fresh one", i)
		}
	}

	// The retired-session watermark survived every restart.
	if last.auth.admitAuthed(false, 0, 0x1234, 7) {
		t.Error("#5086: a replayed (session, counter) must stay rejected across heartbeat restarts")
	}
	if !last.auth.peerAuthenticated() {
		t.Error("#5086: the sticky peer-authenticated flag must survive heartbeat restarts")
	}
	// Memory bound: one fixed ring per Manager regardless of restart count.
	if got := len(m.hbAuth.replay.marks); got != heartbeatReplaySessions {
		t.Errorf("replay ring = %d marks, want the fixed %d", got, heartbeatReplaySessions)
	}
}
