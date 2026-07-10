package cluster

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestUpgradeDrainReportConfirmed asserts the ISSU report certifies the drain
// and hands the operator the stop/swap instruction ONLY when the peer takeover
// was actually observed.
func TestUpgradeDrainReportConfirmed(t *testing.T) {
	joined := strings.Join(UpgradeDrainReport(true), "\n")
	if !strings.Contains(joined, "traffic drained to peer") {
		t.Errorf("confirmed report missing drain confirmation:\n%s", joined)
	}
	if !strings.Contains(joined, "systemctl stop xpfd") {
		t.Errorf("confirmed report missing stop/swap instruction:\n%s", joined)
	}
	if strings.Contains(joined, "WARNING") || strings.Contains(joined, "Do NOT stop") {
		t.Errorf("confirmed report must not warn:\n%s", joined)
	}
}

// TestUpgradeDrainReportUnconfirmed is the #5039 fail-on-revert guard: when the
// handoff is NOT confirmed the report must never certify the drain nor tell the
// operator to stop the only forwarding owner from desired state alone.
func TestUpgradeDrainReportUnconfirmed(t *testing.T) {
	joined := strings.Join(UpgradeDrainReport(false), "\n")
	if !strings.Contains(joined, "NOT confirmed") {
		t.Errorf("unconfirmed report missing the not-confirmed warning:\n%s", joined)
	}
	if !strings.Contains(joined, "Do NOT stop xpfd yet") {
		t.Errorf("unconfirmed report must warn against stopping xpfd:\n%s", joined)
	}
	if !strings.Contains(joined, "show chassis cluster status") {
		t.Errorf("unconfirmed report must direct the operator to verify handoff:\n%s", joined)
	}
	// The false certification the pre-#5039 command printed unconditionally.
	if strings.Contains(joined, "has been drained to peer") ||
		strings.Contains(joined, "traffic drained to peer") {
		t.Errorf("unconfirmed report must NOT certify the drain completed:\n%s", joined)
	}
}

func newHandoffTestManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	m.groups[1] = &RedundancyGroupState{GroupID: 1, State: StatePrimary}
	return m
}

// TestWaitForUpgradeHandoffConfirmedImmediately: local yielded + peer owns
// primary + peer alive → confirmed without waiting out the deadline.
func TestWaitForUpgradeHandoffConfirmedImmediately(t *testing.T) {
	m := newHandoffTestManager(t)
	m.mu.Lock()
	m.peerAlive = true
	m.groups[1].State = StateSecondary
	m.peerGroups[1] = PeerGroupState{GroupID: 1, State: StatePrimary}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("expected handoff confirmed when peer primary + local secondary")
	}
}

// TestWaitForUpgradeHandoffTimesOutWithoutPeerPrimary: local drained but the
// peer never reports primary → must time out unconfirmed (the desired-vs-applied
// gap #5039 is about — a dropped election event leaves the peer non-primary).
func TestWaitForUpgradeHandoffTimesOutWithoutPeerPrimary(t *testing.T) {
	m := newHandoffTestManager(t)
	m.mu.Lock()
	m.peerAlive = true
	m.groups[1].State = StateSecondary
	m.peerGroups[1] = PeerGroupState{GroupID: 1, State: StateSecondary}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("handoff must NOT confirm until the peer owns primary")
	}
}

// TestWaitForUpgradeHandoffNotConfirmedWhileLocalStillPrimary: this node has
// not actually yielded, so even a peer claiming primary (split) must not report
// a completed drain.
func TestWaitForUpgradeHandoffNotConfirmedWhileLocalStillPrimary(t *testing.T) {
	m := newHandoffTestManager(t)
	m.mu.Lock()
	m.peerAlive = true
	m.groups[1].State = StatePrimary
	m.peerGroups[1] = PeerGroupState{GroupID: 1, State: StatePrimary}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("handoff must NOT confirm while this node is still primary")
	}
}

// TestWaitForUpgradeHandoffNotConfirmedWhenPeerDead: no live peer means there is
// no one to have taken over, regardless of stale peer-group state.
func TestWaitForUpgradeHandoffNotConfirmedWhenPeerDead(t *testing.T) {
	m := newHandoffTestManager(t)
	m.mu.Lock()
	m.peerAlive = false
	m.groups[1].State = StateSecondary
	m.peerGroups[1] = PeerGroupState{GroupID: 1, State: StatePrimary}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("handoff must NOT confirm when the peer is not alive")
	}
}
