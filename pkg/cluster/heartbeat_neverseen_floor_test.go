package cluster

import (
	"testing"
	"time"
)

// #4386 cold-boot split-brain regression coverage.
//
// The heartbeat "peer never seen" path (lastSeen == 0) used to confirm the
// peer absent and drive single-node election after only threshold*interval
// (~500ms). On a SIMULTANEOUS cold boot the local config apply phase (FRR
// reload, fabric creation, RETH MAC down/up) disrupts the control-link UDP RX
// for 10-15+ seconds, so the first heartbeats from a live peer are dropped and
// lastSeen stays 0 on BOTH nodes. Both then promoted at T0+500ms and both
// claimed the RETH virtual MAC — a 10-15s split-brain. The fix holds the
// never-seen promotion behind heartbeatStartupGrace, the same cold-boot grace
// the seen-then-lost path already uses.

// TestNeverSeenConfirmedFloor pins the startup-floor boundary. Within the
// grace the never-seen decision is held; at/after the grace it fires, so a
// genuinely-absent peer (single-node deployment) still promotes — the floor
// delays the decision, it never blocks it permanently.
func TestNeverSeenConfirmedFloor(t *testing.T) {
	const grace = 30 * time.Second
	cases := []struct {
		name       string
		sinceStart time.Duration
		want       bool
	}{
		{"steady-state timeout is NOT enough at boot", 500 * time.Millisecond, false},
		{"mid config-apply disruption window", 5 * time.Second, false},
		{"just under grace", grace - time.Millisecond, false},
		{"exactly at grace still promotes (no permanent no-master)", grace, true},
		{"well past grace promotes", grace + 10*time.Second, true},
	}
	for _, tc := range cases {
		if got := neverSeenConfirmed(tc.sinceStart, grace); got != tc.want {
			t.Errorf("%s: neverSeenConfirmed(%v, %v) = %v, want %v",
				tc.name, tc.sinceStart, grace, got, tc.want)
		}
	}
}

// coldBootManager builds a cluster-mode manager with one non-preempt RG that
// starts secondary (blocked from initial promotion by controlInterface +
// non-preempt + !peerEverSeen), mirroring a fresh boot before any peer
// heartbeat has been received.
func coldBootManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg.ControlInterface = "em0" // enables cluster-mode election gating
	m.UpdateConfig(cfg)
	if m.IsLocalPrimary(0) {
		t.Fatal("setup: node should start secondary before any peer heartbeat")
	}
	return m
}

func peerEverSeen(m *Manager) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerEverSeen
}

// TestColdBootNeverSeenFloorSuppressesPromotion is the RED-on-revert guard for
// #4386. A receiver that has never seen a peer, still inside the cold-boot
// grace, must NOT confirm the peer absent — so it does not promote and cannot
// join a dual-primary. After the grace it MUST promote (single-node still
// works). Reverting the never-seen floor to the old threshold*interval check
// promotes at ~500ms, making the within-grace assertion fail.
func TestColdBootNeverSeenFloorSuppressesPromotion(t *testing.T) {
	// Within the grace (simulating the 5s config-apply RX disruption): no
	// heartbeat ever seen, but we must hold — a live peer is likely just
	// slow to be heard. On the buggy path 5s > 500ms → promote → split-brain.
	m := coldBootManager(t)
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-5 * time.Second)
	// r.lastSeen defaults to 0 (never seen).
	r.checkTimeout()
	if peerEverSeen(m) {
		t.Fatal("never-seen peer confirmed absent within the cold-boot grace (split-brain risk)")
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node promoted to primary within the cold-boot grace on a never-seen peer")
	}

	// Past the grace with the peer STILL never seen: a genuinely-absent peer
	// (single-node deployment) must eventually promote — the floor must not
	// become a permanent no-master.
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	r.checkTimeout()
	if !peerEverSeen(m) {
		t.Fatal("never-seen peer not confirmed absent after the grace elapsed (permanent no-master)")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("node did not promote after the cold-boot grace with a genuinely-absent peer")
	}
}

// TestSeenThenLostPathUnchangedByNeverSeenFloor confirms the fix only touches
// the never-seen branch. A peer that WAS seen (lastSeen != 0) then went silent
// is still governed by the existing cold-boot grace, then declared lost via
// the unchanged staleness path.
func TestSeenThenLostPathUnchangedByNeverSeenFloor(t *testing.T) {
	newSeenLostManager := func() *Manager {
		m := coldBootManager(t)
		m.mu.Lock()
		m.peerEverSeen = true // peer was heard at least once
		m.peerAlive = true
		m.mu.Unlock()
		return m
	}
	timeout := time.Duration(DefaultHeartbeatThreshold) * DefaultHeartbeatInterval

	// Within the grace: a stale heartbeat is suppressed (same grace as
	// before) so a recovering node does not declare its live peer dead.
	m := newSeenLostManager()
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-5 * time.Second)
	r.lastSeen.Store(MonotonicNanos() - (timeout + time.Second).Nanoseconds())
	r.checkTimeout()
	m.mu.RLock()
	aliveInGrace := m.peerAlive
	m.mu.RUnlock()
	if !aliveInGrace {
		t.Fatal("seen-then-lost peer declared dead inside the cold-boot grace")
	}

	// Past the grace: the staleness path fires exactly as before the fix —
	// peer is marked lost at threshold*interval staleness.
	m = newSeenLostManager()
	r = newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	r.lastSeen.Store(MonotonicNanos() - (timeout + time.Second).Nanoseconds())
	r.checkTimeout()
	m.mu.RLock()
	aliveAfterGrace := m.peerAlive
	m.mu.RUnlock()
	if aliveAfterGrace {
		t.Fatal("seen-then-lost peer not declared dead after the grace (lost-peer path regressed)")
	}
}
