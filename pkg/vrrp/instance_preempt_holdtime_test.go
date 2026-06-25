package vrrp

import (
	"net"
	"testing"
	"time"
)

// Tests for the VRRP preempt hold-time (#2850). A higher-priority backup that
// is reclaiming mastership from a still-live lower-priority master must, when a
// hold-time is configured, wait hold-time before promoting (so dynamic routing
// converges). With no hold-time the takeover stays immediate (today's
// behavior). Dead-master takeover and graceful priority-0 resignation are never
// delayed.
//
// These wiring tests drive stepBackup() directly (see instance_preempt_gate_test.go
// for why run() is unsafe in a unit test). The masterDownTimer/preemptHoldTimer
// pairs are pre-armed (expired vs long) so the select is deterministic.

// newHoldTestInstance builds a BACKUP instance with a configured priority,
// preempt, and preempt hold-time (seconds). GARP suppressed, local IP set.
func newHoldTestInstance(t *testing.T, priority, holdSec int) *vrrpInstance {
	t.Helper()
	vi := newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          priority,
		Preempt:           true,
		PreemptHoldTime:   holdSec,
		AdvertiseInterval: 30,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 16), nil)
	vi.setLocalIP(net.IPv4(10, 0, 0, 1))
	vi.suppressGARP.Store(true)
	vi.setState(StateBackup)
	return vi
}

// expiredMasterDown returns an already-fired masterDownTimer plus a long advert
// and long preemptHold timer, so a stepBackup select deterministically takes
// the masterDownTimer.C case.
func expiredMasterDown(t *testing.T) (masterDown, advert, preemptHold *time.Timer) {
	t.Helper()
	masterDown = time.NewTimer(0)
	t.Cleanup(func() { masterDown.Stop() })
	// Let it actually fire.
	time.Sleep(2 * time.Millisecond)
	advert = time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	preemptHold = time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })
	return masterDown, advert, preemptHold
}

// TestHoldTime_PreemptLiveLowerMasterDeferred is the PRIMARY fail-on-revert
// guard. A priority-200 node with hold-time set, observing a LIVE priority-100
// master, must NOT promote when the masterDownTimer fires — it arms the hold
// timer instead and stays BACKUP. Reverting the hold-time arming makes this
// promote immediately and fail.
func TestHoldTime_PreemptLiveLowerMasterDeferred(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100 // live lower-priority master
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := expiredMasterDown(t)
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP (preempt deferred by hold-time)", vi.getState())
	}
	// The hold timer must now be armed (not the long-future value): firing it
	// in the next step must promote. Reset it to fire promptly and drive the
	// hold-elapsed case.
	stopAndDrainTimer(preemptHold)
	preemptHold.Reset(0)
	time.Sleep(2 * time.Millisecond)
	masterDownLong := time.NewTimer(time.Hour)
	defer masterDownLong.Stop()
	vi.stepBackup(masterDownLong, advert, preemptHold)
	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (hold-time elapsed → takeover)", vi.getState())
	}
}

// TestHoldTime_NoHoldImmediatePreempt proves the unchanged behavior: with NO
// hold-time configured, the masterDownTimer fire promotes immediately even when
// preempting a live lower-priority master.
func TestHoldTime_NoHoldImmediatePreempt(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 0) // no hold-time
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := expiredMasterDown(t)
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (no hold-time → immediate preempt)", vi.getState())
	}
}

// TestHoldTime_DeadMasterImmediateTakeover: a configured hold-time must NOT
// delay takeover of a genuinely dead/silent master (no recent advert). There is
// nothing forwarding to blackhole, so the masterDownTimer fire promotes
// immediately.
func TestHoldTime_DeadMasterImmediateTakeover(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	// lastMasterSeen left zero → no live master (dead-master takeover).

	masterDown, advert, preemptHold := expiredMasterDown(t)
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (dead master → hold-time does not apply)", vi.getState())
	}
}

// TestHoldTime_StaleMasterImmediateTakeover: a master last heard beyond the
// master-down horizon is stale (silent death) and must not be held either.
func TestHoldTime_StaleMasterImmediateTakeover(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now().Add(-time.Hour) // stale
	vi.mu.Unlock()

	masterDown, advert, preemptHold := expiredMasterDown(t)
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (stale master beyond horizon → immediate)", vi.getState())
	}
}

// TestHoldTime_ReturningWorthyMasterCancelsHold: while the hold is armed, a
// returning >= -priority master advert (handleBackupRx) must cancel the pending
// preemption. After the cancel, firing the (now-stopped, manually drained) hold
// timer would NOT promote — but the real proof is that handleBackupRx drained
// it. We assert the timer is no longer pending by Reset-detecting it.
func TestHoldTime_ReturningWorthyMasterCancelsHold(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := expiredMasterDown(t)
	vi.stepBackup(masterDown, advert, preemptHold)
	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP (hold armed)", vi.getState())
	}

	// A worthy master returns (priority 200 == ours, ≥ ours). handleBackupRx
	// must reset masterDownTimer AND cancel the hold.
	masterDownLong := time.NewTimer(time.Hour)
	defer masterDownLong.Stop()
	vi.handleBackupRx(&VRRPPacket{Priority: 200, SrcIP: net.IPv4(10, 0, 0, 9)}, masterDownLong, preemptHold)

	// The hold was stopped+drained. Stop() now returns false (already stopped)
	// and the channel is empty — proving the pending fire was cancelled.
	if preemptHold.Stop() {
		t.Error("preemptHold was still active after a worthy master returned; hold should have been cancelled")
	}
	select {
	case <-preemptHold.C:
		t.Error("preemptHold had a pending fire after cancellation; hold should have been drained")
	default:
	}
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (worthy master returned, no preemption)", vi.getState())
	}
}

// TestHoldTime_ResignBypassesHold: a priority-0 (graceful resign) advert must
// arm the one-shot bypass so the imminent masterDownTimer expiry promotes
// immediately, not after the hold-time. Planned failover stays zero-delay.
func TestHoldTime_ResignBypassesHold(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	// Feed a priority-0 resignation: arms skipNextPreemptHold, resets
	// masterDownTimer to ~1ms.
	masterDown := time.NewTimer(time.Hour)
	defer masterDown.Stop()
	advert := time.NewTimer(time.Hour)
	defer advert.Stop()
	preemptHold := time.NewTimer(time.Hour)
	defer preemptHold.Stop()
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 9)}, masterDown, preemptHold)

	// Now drive the masterDownTimer expiry: the resign bypass must make it
	// promote immediately despite the configured hold-time and the recorded
	// (recent, lower) master.
	stopAndDrainTimer(masterDown)
	masterDown.Reset(0)
	time.Sleep(2 * time.Millisecond)
	vi.stepBackup(masterDown, advert, preemptHold)
	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (resign bypasses hold-time)", vi.getState())
	}
}

// TestHoldTime_ResignBypassClearedByWorthyMaster guards the one-shot bypass
// race: a priority-0 resign arms skipNextPreemptHold + the 1ms masterDownTimer,
// but a worthy (>= priority) master returns BEFORE that 1ms fires. The
// accept-worthy-master branch must clear the bypass (and re-arm
// masterDownTimer to the full interval). A LATER live-lower master must then be
// HELD by the hold-time, not skipped — proving the stale bypass did not leak.
func TestHoldTime_ResignBypassClearedByWorthyMaster(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown := time.NewTimer(time.Hour)
	defer masterDown.Stop()
	advert := time.NewTimer(time.Hour)
	defer advert.Stop()
	preemptHold := time.NewTimer(time.Hour)
	defer preemptHold.Stop()

	// 1) priority-0 resign arms skipNextPreemptHold + 1ms masterDownTimer.
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 9)}, masterDown, preemptHold)
	vi.mu.RLock()
	if !vi.skipNextPreemptHold {
		vi.mu.RUnlock()
		t.Fatal("skipNextPreemptHold not armed after resign")
	}
	vi.mu.RUnlock()

	// 2) A worthy (>= ours) master returns before the 1ms fires. This must
	//    clear the bypass and re-arm masterDownTimer to the full interval.
	vi.handleBackupRx(&VRRPPacket{Priority: 200, SrcIP: net.IPv4(10, 0, 0, 9)}, masterDown, preemptHold)
	vi.mu.RLock()
	leaked := vi.skipNextPreemptHold
	vi.mu.RUnlock()
	if leaked {
		t.Fatal("skipNextPreemptHold leaked past a worthy-master return (race not fixed)")
	}

	// 3) Later, a live LOWER-priority master is present and the masterDownTimer
	//    fires. The hold-time MUST apply (state stays BACKUP, hold armed) —
	//    if the stale bypass had leaked, this would promote immediately.
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	stopAndDrainTimer(masterDown)
	masterDown.Reset(0)
	time.Sleep(2 * time.Millisecond)
	vi.stepBackup(masterDown, advert, preemptHold)
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (hold-time must apply; bypass must not have leaked)", vi.getState())
	}
}

// TestPreemptHoldDuration: the seconds→Duration conversion and the 0/unset
// sentinel.
func TestPreemptHoldDuration(t *testing.T) {
	if d := newHoldTestInstance(t, 200, 0).preemptHoldDuration(); d != 0 {
		t.Errorf("preemptHoldDuration(0) = %v, want 0", d)
	}
	if d := newHoldTestInstance(t, 200, 45).preemptHoldDuration(); d != 45*time.Second {
		t.Errorf("preemptHoldDuration(45) = %v, want 45s", d)
	}
}
