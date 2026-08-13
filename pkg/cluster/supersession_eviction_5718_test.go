package cluster

import (
	"net"
	"testing"
)

// installedFabrics reports which fabric slots currently hold a connection.
func (s *SessionSync) installedFabrics() (conn0, conn1 net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn0, s.conn1
}

// TestRetiredIncarnationConnDoesNotFakeConnectivity_5718 is the #5718 fold r4b
// fail-on-revert for the half of BLOCKER 1 that incarnation-aware SELECTION
// does not reach.
//
// preferredFabricLocked fixed where outbound traffic goes. It did not change
// what is INSTALLED, and slot occupancy is what several other paths read:
//
//	handleDisconnect:   connected := s.conn0 != nil || s.conn1 != nil
//	fabricConnectLoop:  connected = s.connN != nil   (skips the redial)
//	installConn:        d.wasDisconnected = both slots nil
//
// So after a hard peer reboot supersedes ONE fabric, the retired incarnation's
// socket sits in the other slot — ESTABLISHED, because a hard reboot sends no
// FIN/RST — and when the one LIVE connection then drops, handleDisconnect finds
// that slot non-nil and takes the "still connected" branch. The node has zero
// live connections to the peer and reports:
//
//   - stats.Connected true, so PeerHealthy() returns true (the capability latch
//     was cleared by the incarnation advance, so its silence check is skipped);
//   - no full-disconnect teardown: barrier and failover waiters are never
//     released with failoverAckDisconnected and instead wait out their own
//     timeouts, OnPeerDisconnected never fires, the in-progress bulk receive is
//     never reset, and peerHeartbeatAckEver is never cleared for the next peer;
//   - no redial of the occupied fabric, so the link is not re-established even
//     after the peer comes back.
//
// Evicting the retired incarnation's connections when the incarnation advances
// restores the invariant these readers already assume — installed means
// "belongs to the peer incarnation in force" — instead of teaching each reader
// separately to consult a generation.
//
// Both fabric orderings run: the eviction is a two-armed check keyed on which
// slot is kept, so a single-direction fixture leaves one arm free.
func TestRetiredIncarnationConnDoesNotFakeConnectivity_5718(t *testing.T) {
	for _, tc := range []struct{ superseded, survivor int }{{0, 1}, {1, 0}} {
		t.Run(fabricPairName(tc.superseded, tc.survivor), func(t *testing.T) {
			ss := newAckTestSync(t)

			// Peer incarnation A holds BOTH fabric slots.
			aSup, aSurv := pipeConn(t), pipeConn(t)
			ss.installConn(tc.superseded, aSup)
			ss.installConn(tc.survivor, aSurv)

			// A's node reboots hard. Its replacement dials one fabric; A's
			// other socket never sees a FIN or an RST.
			b := pipeConn(t)
			ss.installConn(tc.superseded, b)

			// The retired incarnation must be out of the registry, not merely
			// out-ranked by preferredFabricLocked.
			conns := map[int]net.Conn{}
			conns[0], conns[1] = ss.installedFabrics()
			if conns[tc.survivor] != nil {
				t.Errorf("the retired incarnation's fabric-%d connection is still INSTALLED. "+
					"Incarnation-aware selection stops it carrying traffic but leaves it in "+
					"the registry, and fabricConnectLoop skips a fabric whose slot is non-nil "+
					"— so the link to the live peer is never re-established on that fabric, "+
					"and the cluster silently runs on one", tc.survivor)
			}

			// Now the one LIVE connection drops. This must be a FULL
			// disconnect: there is nothing left to talk to.
			ss.handleDisconnect(b)

			if ss.stats.Connected.Load() {
				t.Errorf("after the only CURRENT-incarnation connection dropped, the node still "+
					"reports Connected because the retired incarnation's fabric-%d socket is "+
					"still installed. handleDisconnect's `connected := s.conn0 != nil || "+
					"s.conn1 != nil` counts a connection to a process that no longer exists, "+
					"so the full-disconnect teardown never runs: barrier and failover waiters "+
					"are not released with failoverAckDisconnected and instead block until "+
					"their own timeouts, OnPeerDisconnected never fires, and the in-progress "+
					"bulk receive is never reset", tc.survivor)
			}
			if ss.PeerHealthy() {
				t.Errorf("PeerHealthy() reports a HEALTHY peer with zero live connections. It is "+
					"Connected plus the capability latch — and the incarnation advance cleared "+
					"the latch, so the silence check is skipped and only the phantom "+
					"connectivity from the retired fabric-%d slot remains. A manual failover "+
					"readiness check would pass against a peer that cannot be reached",
					tc.survivor)
			}
		})
	}
}

// TestInstallConnNeverLeavesTheRegistryEmpty_5718 is the behaviour that makes
// the eviction's exemption from TestOnlyHandleDisconnectEmptiesTheRegistry_5718
// sound.
//
// evictStaleIncarnationConnsLocked nils a slot, which is exactly what that
// structural guard exists to forbid. It is allowed because it can never empty
// the registry: it runs after the incoming connection is installed and skips
// that connection's slot. If the skip is ever lost, installConn can return with
// BOTH slots nil while peerHeartbeatAckEver is still latched — the registry
// reaching empty without handleDisconnect's clear, which is the precise failure
// the structural guard was written to prevent and which it would no longer
// detect.
func TestInstallConnNeverLeavesTheRegistryEmpty_5718(t *testing.T) {
	for _, tc := range []struct{ superseded, survivor int }{{0, 1}, {1, 0}} {
		t.Run(fabricPairName(tc.superseded, tc.survivor), func(t *testing.T) {
			ss := newAckTestSync(t)

			aSup, aSurv := pipeConn(t), pipeConn(t)
			ss.installConn(tc.superseded, aSup)
			ss.installConn(tc.survivor, aSurv)
			ss.handleMessage(aSup, syncMsgHeartbeatAck, nil)

			b := pipeConn(t)
			ss.installConn(tc.superseded, b)

			c0, c1 := ss.installedFabrics()
			if c0 == nil && c1 == nil {
				t.Fatalf("installConn returned with an EMPTY registry after superseding fabric %d. "+
					"The stale-incarnation eviction must never remove the connection that was "+
					"just installed, or the registry reaches empty without handleDisconnect "+
					"having run — and installConn omits the capability clear precisely because "+
					"an empty registry is supposed to prove that clear already happened",
					tc.superseded)
			}
			if got := ss.connInSlot(tc.superseded); got != b {
				t.Fatalf("the just-installed fabric-%d connection must survive the eviction", tc.superseded)
			}
		})
	}
}

// TestEvictionRefusesToEmptyTheRegistry_5718 binds the #5718 fold r6 intrinsic
// precondition, and it is deliberately NOT routed through installConn.
//
// TestInstallConnNeverLeavesTheRegistryEmpty_5718 above proves the LIVE call
// site is safe. It cannot prove the FUNCTION is, because installConn installs
// before it evicts and therefore never presents an empty keep slot. That gap
// is what makes the allowlist exemption in
// TestOnlyHandleDisconnectEmptiesTheRegistry_5718 weaker than it reads: the
// exemption is by function NAME, so a second call site inherits it without
// inheriting the property it was granted for. A caller naming a slot it had not
// filled COULD evict every other slot and return with the registry empty —
// whenever those other slots hold retired-stamped connections — exactly the
// state the structural guard exists to forbid, and all three existing tests
// would stay green. (Not "would": with an empty keep slot and a CURRENT
// connection in the other slot nothing is stale, so nothing is evicted and the
// registry stays nonempty. The refusal is not a prediction about the call, it
// is a refusal to proceed when the postcondition cannot be established.)
//
// So drive the helper directly, in the shapes a caller can get wrong, and
// assert it declines. Reverting the keep-slot refusal reds all three subtests.
func TestEvictionRefusesToEmptyTheRegistry_5718(t *testing.T) {
	// The keep-slot lookup is a two-armed switch, so a fixture that only ever
	// populates ONE slot leaves the other arm free: a regression confined to
	// `case 1` would pass while `case 0` still refused. Each case below places
	// the stale connection in the slot the caller is NOT keeping, so keepIdx=0
	// exercises the conn0 arm and keepIdx=1 exercises the conn1 arm, both with
	// their keep slot genuinely empty.
	for _, tc := range []struct {
		name     string
		keepIdx  int
		staleIdx int
	}{
		// The keep slot names a real fabric, but the caller has not installed
		// into it yet. Only the OTHER slot is occupied, and it is stale.
		{"keep slot 0 empty", 0, 1},
		{"keep slot 1 empty", 1, 0},
		// The keep slot names no fabric at all, so neither skip applies and the
		// one occupied slot is an eviction candidate with nothing to preserve.
		{"keep index out of range", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := newAckTestSync(t)
			stale := pipeConn(t)

			ss.mu.Lock()
			// Stand up the state a wrong caller would hand the helper: a
			// connection stamped with a retired incarnation, and no connection
			// in the slot the caller claims to be keeping.
			switch tc.staleIdx {
			case 0:
				ss.conn0, ss.conn0Gen = stale, 1
			case 1:
				ss.conn1, ss.conn1Gen = stale, 1
			}
			ss.peerIncarnation = 2
			ss.mu.Unlock()

			ss.mu.Lock()
			evicted := ss.evictStaleIncarnationConnsLocked(tc.keepIdx)
			ss.mu.Unlock()

			if evicted {
				t.Errorf("evictStaleIncarnationConnsLocked reported an eviction with keepIdx=%d, "+
					"whose keep slot holds nothing. The only justification for exempting this "+
					"function from TestOnlyHandleDisconnectEmptiesTheRegistry_5718 is that it "+
					"cannot cause the nonempty-to-empty transition; evicting here does exactly "+
					"that", tc.keepIdx)
			}
			c0, c1 := ss.installedFabrics()
			if c0 == nil && c1 == nil {
				t.Fatalf("the fabric registry is EMPTY after evictStaleIncarnationConnsLocked(%d). "+
					"installConn omits its capability clear on the full-disconnect edge because "+
					"an empty registry is supposed to PROVE handleDisconnect already ran. A "+
					"second path that empties it makes that proof false, and the retired "+
					"incarnation's capability latch is then enforced against the next peer",
					tc.keepIdx)
			}
			if got := ss.connInSlot(tc.staleIdx); got != stale {
				t.Errorf("the stale connection must be left installed in fabric %d when the "+
					"helper declines; declining has to be a no-op, not a partial eviction",
					tc.staleIdx)
			}
		})
	}
}

// TestSecondFabricComingUpIsNotEvicted_5718 is the over-reach guard for the
// eviction and must stay GREEN when it is reverted.
//
// A fabric link coming up into an EMPTY slot beside a live one is the same peer
// process taking its second link. Evicting there would tear down a healthy
// fabric on every routine link recovery. Both orderings run so neither arm of
// the eviction check can be mutated to fire unconditionally unnoticed.
//
// This pins the ROUTINE reading DELIBERATELY. A peer that REBOOTED and whose
// replacement enters through this same empty slot is observationally identical
// here — no local signal separates them — and it is tracked as #6910, blocked
// on #6669's peer-supplied boot epoch. Do not "fix" this test into failing to
// close that case: making the empty-slot install evict would tear down a
// healthy fabric on every link flap. See pkg/cluster/README.md, "ACCEPTED
// RESIDUAL".
func TestSecondFabricComingUpIsNotEvicted_5718(t *testing.T) {
	for _, tc := range []struct{ first, second int }{{0, 1}, {1, 0}} {
		t.Run(fabricPairName(tc.first, tc.second), func(t *testing.T) {
			ss := newAckTestSync(t)

			firstConn := pipeConn(t)
			ss.installConn(tc.first, firstConn)
			secondConn := pipeConn(t)
			ss.installConn(tc.second, secondConn)

			conns := map[int]net.Conn{}
			conns[0], conns[1] = ss.installedFabrics()
			if conns[tc.first] != firstConn {
				t.Fatalf("fabric %d's LIVE connection was evicted when fabric %d came up into an "+
					"EMPTY slot. Nothing was superseded and the peer process never changed, so "+
					"this tears down a healthy fabric link on every routine link recovery",
					tc.first, tc.second)
			}
			if conns[tc.second] != secondConn {
				t.Fatalf("fabric %d must hold the connection just installed", tc.second)
			}
		})
	}
}
