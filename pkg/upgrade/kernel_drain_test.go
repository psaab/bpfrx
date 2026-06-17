package upgrade

import (
	"testing"
	"time"
)

// DrainAndConfirm: happy path — pre-checks pass, ForceSecondary, then the strong
// drain predicate holds -> nil.
func TestDrainAndConfirmHappy(t *testing.T) {
	f := &fakeCluster{peerAlive: true, compatible: true, peerReady: true, drainAfter: 1}
	if err := DrainAndConfirm(f, 5*time.Second, false); err != nil {
		t.Fatalf("DrainAndConfirm: %v", err)
	}
	if !f.forced {
		t.Fatal("expected ForceSecondary to be called")
	}
}

// Refuse to drain when the peer is not alive (no node to take over).
func TestDrainAndConfirmRefusesDeadPeer(t *testing.T) {
	f := &fakeCluster{peerAlive: false, compatible: true, peerReady: true, drainAfter: 1}
	if err := DrainAndConfirm(f, time.Second, false); err == nil {
		t.Fatal("expected refusal when peer not alive")
	}
	if f.forced {
		t.Fatal("must NOT force secondary when peer is dead")
	}
}

// Refuse to drain when the peer is not takeover-ready (would strand VIPs).
func TestDrainAndConfirmRefusesPeerNotReady(t *testing.T) {
	f := &fakeCluster{peerAlive: true, compatible: true, peerReady: false, drainAfter: 1}
	if err := DrainAndConfirm(f, time.Second, false); err == nil {
		t.Fatal("expected refusal when peer not takeover-ready")
	}
	if f.forced {
		t.Fatal("must NOT force secondary when peer not takeover-ready")
	}
}

// Refuse to drain on incompatible HA protocol (mixed-protocol split risk).
func TestDrainAndConfirmRefusesIncompatibleProtocol(t *testing.T) {
	f := &fakeCluster{peerAlive: true, compatible: false, peerReady: true, drainAfter: 1}
	if err := DrainAndConfirm(f, time.Second, false); err == nil {
		t.Fatal("expected refusal on incompatible HA protocol")
	}
}

// allowMixedHA relaxes the exact-equality HA precheck: the LANE-2 image-roll
// mixed-base gate has already validated window-compat, so a drain against an
// in-window-but-not-equal peer must proceed (r3 Codex HIGH).
func TestDrainAndConfirmAllowMixedHA(t *testing.T) {
	f := &fakeCluster{peerAlive: true, compatible: false, peerReady: true, drainAfter: 1}
	if err := DrainAndConfirm(f, 5*time.Second, true); err != nil {
		t.Fatalf("allowMixedHA must skip the HA-compat precheck: %v", err)
	}
	if !f.forced {
		t.Fatal("expected ForceSecondary under allowMixedHA")
	}
}

// Drain that never completes within the deadline -> error AND failback (r2
// Codex: must not leave the node force-demoted with VIPs stranded).
func TestDrainAndConfirmTimesOutAndFailsBack(t *testing.T) {
	f := &fakeCluster{peerAlive: true, compatible: true, peerReady: true, drainAfter: 1000}
	if err := DrainAndConfirm(f, 50*time.Millisecond, false); err == nil {
		t.Fatal("expected timeout when drain never completes")
	}
	if !f.forced {
		t.Fatal("expected ForceSecondary to have been attempted")
	}
	if !f.resetCalled {
		t.Fatal("expected FAILBACK (ResetFailover) on drain timeout — must not strand VIPs")
	}
}

// RejoinAndConfirm: ResetFailover then peer-alive + sync -> nil.
func TestRejoinAndConfirmHappy(t *testing.T) {
	f := &fakeCluster{peerAlive: true, synced: true}
	if err := RejoinAndConfirm(f, 5*time.Second); err != nil {
		t.Fatalf("RejoinAndConfirm: %v", err)
	}
	if !f.resetCalled {
		t.Fatal("expected ResetFailover to be called")
	}
}

// Rejoin that cannot re-establish sync within the deadline -> error (so the
// orchestrator does not advance to the peer — the "never both down" gate).
func TestRejoinAndConfirmTimesOutOnNoSync(t *testing.T) {
	f := &fakeCluster{peerAlive: true, synced: false}
	if err := RejoinAndConfirm(f, 50*time.Millisecond); err == nil {
		t.Fatal("expected timeout when sync never re-establishes")
	}
	if !f.resetCalled {
		t.Fatal("ResetFailover should still have been attempted")
	}
}
