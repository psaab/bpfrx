package cluster

import (
	"net"
	"testing"
	"time"
)

// newAckTestSync builds a SessionSync with a small, explicit silence window so
// "the peer has been quiet" is deterministic without sleeping.
func newAckTestSync(t *testing.T) *SessionSync {
	t.Helper()
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.peerSilenceLimit = 50 * time.Millisecond
	return ss
}

// installAckTestConn wires conn into a fabric slot through the production
// install path and then backdates the peer-receive clock past the silence
// window, which installConn refreshes.
func installAckTestConn(t *testing.T, ss *SessionSync, fabricIdx int, conn net.Conn) {
	t.Helper()
	ss.installConn(fabricIdx, conn)
	ss.lastPeerRxMono.Store(MonotonicNanos() - int64(time.Second))
}

// pipeConn returns one end of a net.Pipe and registers both ends for cleanup.
func pipeConn(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a
}

// TestPeerHeartbeatAckEverIsPeerIncarnationScoped_5718 is the #5718 C01a
// fail-on-revert for the FULL-DISCONNECT edge.
//
// peerHeartbeatAckEver is a capability probe of the PEER PROCESS: it latches
// when the peer replies syncMsgHeartbeatAck, and both readers then switch from
// "assume healthy" to "enforce". The two readers are sync_conn_read.go's
// missed-heartbeat teardown and sync.go's PeerHealthy() silence window; both
// consult this single flag, so binding the flag binds both.
//
// The defect the fix removes: the flag was SessionSync-lifetime, written once
// and never cleared, so it survived the end of the peer incarnation that
// earned it. A peer DOWNGRADE (new build acks -> latch true -> peer rolls back
// to a build that never sends syncMsgHeartbeatAck) left the latch armed
// against a peer that can never satisfy it, so a perfectly healthy old peer
// was treated as failing: PeerHealthy() demands inbound traffic that never
// comes, which fails computeUserspaceTransferReadiness with "session sync
// disconnected" and blocks manual failover.
func TestPeerHeartbeatAckEverIsPeerIncarnationScoped_5718(t *testing.T) {
	ss := newAckTestSync(t)

	// Peer incarnation #1 connects, and has been quiet for far longer than the
	// silence window (the state a heartbeat-capable peer must not be in).
	connA := pipeConn(t)
	installAckTestConn(t, ss, 0, connA)

	// Incarnation #1 proves it understands heartbeats.
	ss.handleMessage(connA, syncMsgHeartbeatAck, nil)
	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("syncMsgHeartbeatAck from an installed connection must latch the peer heartbeat-ack capability")
	}
	// Enforcement is now armed for THIS peer: it acks, so silence is a fault.
	if ss.PeerHealthy() {
		t.Fatal("an ack-capable peer that has been silent past the silence window must read unhealthy")
	}

	// Incarnation #1 ends. Full disconnect (conn1 was never set, so removing
	// conn0 leaves no active connection) must end the capability with it.
	ss.handleDisconnect(connA)
	if ss.peerHeartbeatAckEver.Load() {
		t.Fatal("full disconnect must clear peerHeartbeatAckEver: the capability " +
			"belongs to the peer incarnation that proved it, not to this " +
			"SessionSync. Leaving it latched arms the missed-heartbeat teardown " +
			"(sync_conn_read.go) and PeerHealthy's silence window against the " +
			"NEXT peer, which may be a downgraded build that never acks")
	}

	// Peer incarnation #2 is a DOWNGRADED build: it never sends
	// syncMsgHeartbeatAck, so it is legitimately quiet.
	connB := pipeConn(t)
	installAckTestConn(t, ss, 0, connB)

	if !ss.PeerHealthy() {
		t.Fatal("a reconnected peer that has not proved heartbeat-ack support must " +
			"read HEALTHY (probe-then-enforce). Reading unhealthy here is the " +
			"#5718 C01a downgrade defect: a stale capability latch from the " +
			"previous peer incarnation blocks manual-failover readiness with " +
			"\"session sync disconnected\" for a peer that is fine")
	}
}

// TestPeerHeartbeatAckEverClearedOnSupersession_5718 is the fold F1
// fail-on-revert: the SUPERSESSION edge, which handleDisconnect structurally
// cannot see.
//
// A peer that reboots hard sends no FIN/RST, so our TCP connection stays
// ESTABLISHED and fabricConnectLoop will not redial a slot it believes is
// connected. The peer's NEW process dials in, acceptLoop admits it, and
// installConn replaces the slot's connection. The superseded connection's
// receiveLoop then calls handleDisconnect, which finds the slot already
// holding the NEW conn and returns down the "ignoring stale disconnect"
// default branch WITHOUT clearing anything.
//
// So the full-disconnect clear alone leaves the previous incarnation's
// capability enforced against the new one — the same peer-downgrade blackhole
// C01a exists to prevent, reached through a different edge.
func TestPeerHeartbeatAckEverClearedOnSupersession_5718(t *testing.T) {
	ss := newAckTestSync(t)

	// Peer incarnation #1: connected on fabric 0 and proves ack support.
	connA := pipeConn(t)
	installAckTestConn(t, ss, 0, connA)
	ss.handleMessage(connA, syncMsgHeartbeatAck, nil)
	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("setup: incarnation #1 must latch the capability")
	}

	// Peer incarnation #2 (a downgraded build) dials in on the same fabric
	// while our half-open connection to incarnation #1 is still registered.
	connB := pipeConn(t)
	ss.installConn(0, connB)

	// handleDisconnect for the superseded connection runs afterwards, from the
	// old receiveLoop's defer. It must not be what the fix depends on: the
	// slot now holds connB, so this call takes the stale-disconnect branch and
	// changes nothing.
	ss.handleDisconnect(connA)

	if ss.peerHeartbeatAckEver.Load() {
		t.Fatal("a connection SUPERSEDING a live one in its fabric slot starts a new " +
			"peer incarnation and must clear peerHeartbeatAckEver. handleDisconnect " +
			"cannot do it: by the time the superseded connection's receiveLoop " +
			"reports the drop, the slot already holds the new conn, so it returns " +
			"down the stale-disconnect branch. Leaving the latch armed enforces " +
			"the OLD incarnation's capability against a peer that may never ack")
	}

	// The new incarnation must therefore read healthy despite being silent.
	ss.lastPeerRxMono.Store(MonotonicNanos() - int64(time.Second))
	if !ss.PeerHealthy() {
		t.Fatal("after a supersession the new peer incarnation must read HEALTHY " +
			"until it proves ack support itself (probe-then-enforce)")
	}
}

// TestPeerHeartbeatAckStaleConnCannotRearm_5718 pins the ordering half of the
// fold F1 fix.
//
// installConn's clear is not sufficient on its own: a heartbeat-ack frame that
// was already read off the superseded connection is still in flight in that
// connection's receiveLoop. If handleMessage latched unconditionally, that
// stale frame would re-arm the capability for the incoming incarnation
// immediately after the clear — restoring exactly the state the clear removed.
//
// The membership test and the store therefore both run under s.mu in
// noteHeartbeatAck, atomic with installConn's clear, and an ack from a
// connection that is no longer installed is ignored.
func TestPeerHeartbeatAckStaleConnCannotRearm_5718(t *testing.T) {
	ss := newAckTestSync(t)

	connA := pipeConn(t)
	installAckTestConn(t, ss, 0, connA)

	connB := pipeConn(t)
	ss.installConn(0, connB)
	if ss.peerHeartbeatAckEver.Load() {
		t.Fatal("setup: the supersession must leave the capability cleared")
	}

	// The superseded connection's in-flight ack arrives after the swap.
	ss.handleMessage(connA, syncMsgHeartbeatAck, nil)
	if ss.peerHeartbeatAckEver.Load() {
		t.Fatal("an ack from a SUPERSEDED connection must not latch the capability: " +
			"it speaks for the previous peer incarnation, and honouring it " +
			"re-arms the enforcement paths against the new one")
	}

	// The current incarnation's own ack still latches — the gate rejects stale
	// connections, not acks in general.
	ss.handleMessage(connB, syncMsgHeartbeatAck, nil)
	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("an ack from the CURRENTLY installed connection must latch the capability")
	}
}

// TestPeerHeartbeatAckNotLatchedBeforeInstall_5718 covers the third writer
// path: handleNewConnection processes a handshake-pending frame BEFORE the
// connection is installed into a fabric slot.
//
// An ack can never legitimately be a peer's first frame — we only send
// syncMsgHeartbeat after a read deadline elapses on an established connection
// — so an unsolicited ack arriving before the connection is wired in must not
// arm an enforcement path on its behalf.
func TestPeerHeartbeatAckNotLatchedBeforeInstall_5718(t *testing.T) {
	ss := newAckTestSync(t)

	pending := pipeConn(t)
	ss.handleMessage(pending, syncMsgHeartbeatAck, nil)
	if ss.peerHeartbeatAckEver.Load() {
		t.Fatal("an ack from a connection that is not installed in a fabric slot " +
			"must not latch the capability")
	}

	// nil is the unit-test / no-connection shape and must be inert too.
	ss.handleMessage(nil, syncMsgHeartbeatAck, nil)
	if ss.peerHeartbeatAckEver.Load() {
		t.Fatal("an ack with no originating connection must not latch the capability")
	}
}

// TestPeerHeartbeatAckEverSurvivesPartialDisconnect_5718 is the scope control
// for the full-disconnect clear: the reset must be scoped to the PEER
// INCARNATION, not to any connection event.
//
// A single fabric link flapping while the other stays up is the SAME peer
// process. Clearing the capability there would silently disarm the
// missed-heartbeat teardown and the silence window on every fabric-link blip —
// a fail-open that a reset-on-every-disconnect implementation would exhibit
// and the tests above alone would not catch.
func TestPeerHeartbeatAckEverSurvivesPartialDisconnect_5718(t *testing.T) {
	ss := newAckTestSync(t)

	conn0 := pipeConn(t)
	conn1 := pipeConn(t)

	// Both fabric links up to one peer incarnation, which proves ack support.
	ss.installConn(0, conn0)
	ss.installConn(1, conn1)
	ss.handleMessage(conn0, syncMsgHeartbeatAck, nil)
	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("setup: capability must be latched before the partial disconnect")
	}

	// Fabric 0 drops; fabric 1 survives. Same peer process, so the capability
	// it proved is still true.
	ss.handleDisconnect(conn0)

	ss.mu.Lock()
	stillConnected := ss.conn1 != nil
	ss.mu.Unlock()
	if !stillConnected {
		t.Fatal("setup: fabric 1 must survive a fabric 0 disconnect")
	}
	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("a PARTIAL disconnect (one fabric link down, the other still up) " +
			"must NOT clear peerHeartbeatAckEver: the peer process never " +
			"changed. Clearing on any disconnect disarms the missed-heartbeat " +
			"teardown and PeerHealthy's silence window on every link blip")
	}
}

// TestPeerHeartbeatAckEverSurvivesSecondFabricComingUp_5718 is the scope
// control for the SUPERSESSION clear.
//
// A second fabric link coming up beside a surviving one is not a supersession:
// its slot was empty, so no live connection was replaced, and it is the same
// peer process that is already acking on the other link. Clearing there would
// disarm both enforcement paths every time a flapped fabric link came back —
// the mirror image of the partial-disconnect fail-open above.
func TestPeerHeartbeatAckEverSurvivesSecondFabricComingUp_5718(t *testing.T) {
	ss := newAckTestSync(t)

	conn0 := pipeConn(t)
	ss.installConn(0, conn0)
	ss.handleMessage(conn0, syncMsgHeartbeatAck, nil)
	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("setup: capability must be latched before fabric 1 comes up")
	}

	// Fabric 1 comes up into an EMPTY slot beside the live fabric 0.
	conn1 := pipeConn(t)
	ss.installConn(1, conn1)

	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("a fabric link coming up into an EMPTY slot beside a live one must " +
			"NOT clear peerHeartbeatAckEver: nothing was superseded and the peer " +
			"process never changed. Clearing on every install disarms the " +
			"missed-heartbeat teardown and PeerHealthy's silence window whenever " +
			"a flapped fabric link returns")
	}
}
