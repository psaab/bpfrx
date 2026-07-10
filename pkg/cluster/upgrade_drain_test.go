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
	// No copy-pasteable stop command on the unconfirmed path — a hurried
	// operator must not be handed a stop command that blackholes traffic.
	if strings.Contains(joined, "systemctl stop") {
		t.Errorf("unconfirmed report must NOT include a systemctl stop command:\n%s", joined)
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

// newMultiRGManager builds the default-shaped 3-RG cluster (RG0/RG1/RG2), all
// relinquished to Secondary locally (post-ForceSecondary applied state).
func newMultiRGManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	for _, gid := range []int{0, 1, 2} {
		m.groups[gid] = &RedundancyGroupState{GroupID: gid, State: StateSecondary}
	}
	m.peerAlive = true
	return m
}

// TestWaitForUpgradeHandoffMultiRGPartialDrainNotConfirmed is the #5039
// partial-drain guard: in a 3-RG config the peer has taken over only RG0 (e.g.
// control-plane, no data VIP) while RG1/RG2 lag or their election events on
// this node were dropped. The command MUST report NOT confirmed — an any-one
// predicate would falsely certify the drain and blackhole the still-node0 data
// RGs. RED if the predicate reverts to any-one.
func TestWaitForUpgradeHandoffMultiRGPartialDrainNotConfirmed(t *testing.T) {
	m := newMultiRGManager(t)
	m.mu.Lock()
	m.peerGroups[0] = PeerGroupState{GroupID: 0, State: StatePrimary}
	m.peerGroups[1] = PeerGroupState{GroupID: 1, State: StateSecondary}
	m.peerGroups[2] = PeerGroupState{GroupID: 2, State: StateSecondaryHold}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("handoff must NOT confirm when only some relinquished RGs are peer-primary")
	}
}

// TestWaitForUpgradeHandoffMultiRGFullDrainConfirmed: only once the peer owns
// primary for EVERY relinquished RG is the drain confirmed.
func TestWaitForUpgradeHandoffMultiRGFullDrainConfirmed(t *testing.T) {
	m := newMultiRGManager(t)
	m.mu.Lock()
	for _, gid := range []int{0, 1, 2} {
		m.peerGroups[gid] = PeerGroupState{GroupID: gid, State: StatePrimary}
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("handoff must confirm when ALL relinquished RGs are peer-primary")
	}
}

// TestWaitForUpgradeHandoffMultiRGMissingPeerEntryNotConfirmed: a relinquished
// RG with no peer-group entry at all (peer has not reported taking it) must
// block confirmation just like a non-primary entry.
func TestWaitForUpgradeHandoffMultiRGMissingPeerEntryNotConfirmed(t *testing.T) {
	m := newMultiRGManager(t)
	m.mu.Lock()
	m.peerGroups[0] = PeerGroupState{GroupID: 0, State: StatePrimary}
	m.peerGroups[1] = PeerGroupState{GroupID: 1, State: StatePrimary}
	// RG2 intentionally has no peer entry.
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("handoff must NOT confirm while a relinquished RG has no peer-primary entry")
	}
}

// TestWaitForUpgradeHandoffSkipsDisabledRG: a disabled RG is not part of the
// drain and must not require a peer-primary entry.
func TestWaitForUpgradeHandoffSkipsDisabledRG(t *testing.T) {
	m := NewManager(0, 1)
	m.groups[0] = &RedundancyGroupState{GroupID: 0, State: StateSecondary}
	m.groups[1] = &RedundancyGroupState{GroupID: 1, State: StateDisabled}
	m.mu.Lock()
	m.peerAlive = true
	m.peerGroups[0] = PeerGroupState{GroupID: 0, State: StatePrimary}
	// RG1 is disabled — no peer entry required.
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("disabled RG must be skipped; handoff should confirm on the enabled RG")
	}
}

// TestWaitForUpgradeHandoffNoEnabledRGsNotConfirmed: a config with zero enabled
// RGs has nothing to drain and must not falsely confirm.
func TestWaitForUpgradeHandoffNoEnabledRGsNotConfirmed(t *testing.T) {
	m := NewManager(0, 1)
	m.groups[0] = &RedundancyGroupState{GroupID: 0, State: StateDisabled}
	m.mu.Lock()
	m.peerAlive = true
	m.peerGroups[0] = PeerGroupState{GroupID: 0, State: StatePrimary}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if m.WaitForUpgradeHandoff(ctx, 5*time.Millisecond) {
		t.Fatal("a config with no enabled RGs must not confirm a drain")
	}
}
