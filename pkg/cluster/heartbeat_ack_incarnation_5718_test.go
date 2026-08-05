package cluster

import (
	"net"
	"testing"
	"time"
)

// TestPeerHeartbeatAckEverIsPeerIncarnationScoped_5718 is the #5718 C01a
// fail-on-revert.
//
// peerHeartbeatAckEver is a capability probe of the PEER PROCESS: it latches
// when the peer replies syncMsgHeartbeatAck, and both readers then switch from
// "assume healthy" to "enforce". The two readers are
// sync_conn_read.go's missed-heartbeat teardown and sync.go's PeerHealthy()
// silence window; both consult this single flag, so binding the flag binds
// both.
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
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	// Small, explicit silence window so "peer has been quiet" is deterministic
	// without sleeping.
	ss.peerSilenceLimit = 50 * time.Millisecond

	connA1, connA2 := net.Pipe()
	defer connA1.Close()
	defer connA2.Close()

	// Peer incarnation #1 connects, and has been quiet for far longer than the
	// silence window (the state a heartbeat-capable peer must not be in).
	ss.mu.Lock()
	ss.conn0 = connA1
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()
	ss.lastPeerRxMono.Store(MonotonicNanos() - int64(time.Second))

	// Incarnation #1 proves it understands heartbeats.
	ss.handleMessage(nil, syncMsgHeartbeatAck, nil)
	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("syncMsgHeartbeatAck must latch the peer heartbeat-ack capability")
	}
	// Enforcement is now armed for THIS peer: it acks, so silence is a fault.
	if ss.PeerHealthy() {
		t.Fatal("an ack-capable peer that has been silent past the silence window must read unhealthy")
	}

	// Incarnation #1 ends. Full disconnect (conn1 was never set, so removing
	// conn0 leaves no active connection) must end the capability with it.
	ss.handleDisconnect(connA1)
	if ss.peerHeartbeatAckEver.Load() {
		t.Fatal("full disconnect must clear peerHeartbeatAckEver: the capability " +
			"belongs to the peer incarnation that proved it, not to this " +
			"SessionSync. Leaving it latched arms the missed-heartbeat teardown " +
			"(sync_conn_read.go) and PeerHealthy's silence window against the " +
			"NEXT peer, which may be a downgraded build that never acks")
	}

	// Peer incarnation #2 is a DOWNGRADED build: it never sends
	// syncMsgHeartbeatAck, so it is legitimately quiet.
	connB1, connB2 := net.Pipe()
	defer connB1.Close()
	defer connB2.Close()
	ss.mu.Lock()
	ss.conn0 = connB1
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()
	ss.lastPeerRxMono.Store(MonotonicNanos() - int64(time.Second))

	if !ss.PeerHealthy() {
		t.Fatal("a reconnected peer that has not proved heartbeat-ack support must " +
			"read HEALTHY (probe-then-enforce). Reading unhealthy here is the " +
			"#5718 C01a downgrade defect: a stale capability latch from the " +
			"previous peer incarnation blocks manual-failover readiness with " +
			"\"session sync disconnected\" for a peer that is fine")
	}
}

// TestPeerHeartbeatAckEverSurvivesPartialDisconnect_5718 is the scope control
// for the test above: the reset must be scoped to the PEER INCARNATION, not to
// any connection event.
//
// A single fabric link flapping while the other stays up is the SAME peer
// process. Clearing the capability there would silently disarm the
// missed-heartbeat teardown and the silence window on every fabric-link blip —
// a fail-open that a reset-on-every-disconnect implementation would exhibit
// and the test above alone would not catch.
func TestPeerHeartbeatAckEverSurvivesPartialDisconnect_5718(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.peerSilenceLimit = 50 * time.Millisecond

	conn0a, conn0b := net.Pipe()
	defer conn0a.Close()
	defer conn0b.Close()
	conn1a, conn1b := net.Pipe()
	defer conn1a.Close()
	defer conn1b.Close()

	// Both fabric links up to one peer incarnation, which proves ack support.
	ss.mu.Lock()
	ss.conn0 = conn0a
	ss.conn1 = conn1a
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()
	ss.handleMessage(nil, syncMsgHeartbeatAck, nil)
	if !ss.peerHeartbeatAckEver.Load() {
		t.Fatal("setup: capability must be latched before the partial disconnect")
	}

	// Fabric 0 drops; fabric 1 survives. Same peer process, so the capability
	// it proved is still true.
	ss.handleDisconnect(conn0a)

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
