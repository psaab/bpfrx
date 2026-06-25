package vrrp

import (
	"net"
	"testing"
	"time"
)

// Tests for the sync-hold preempt peer-priority gate (#2082). The
// preemptNowCh consumer must only transition a BACKUP to MASTER on the
// non-force shortcut when its effective priority strictly exceeds the
// observed master's (RFC 5798 §6.4.2), so a lower-priority preempt-enabled
// node no longer transiently becomes a second MASTER on sync-hold release
// while a higher-priority peer is legitimately MASTER.
//
// The wiring tests drive stepBackup() directly (NOT run()): run()'s preamble
// unconditionally spawns a receiver goroutine that nil-derefs vi.conn on a
// test instance. becomeMaster() is fail-soft on a fake interface (addVIPs
// Warn+returns on netlink failure, sendAdvert/sendPacket no-op on nil
// rawConn), and suppressGARP avoids the async GARP goroutine.

// newGateTestInstance builds a BACKUP instance suitable for driving stepBackup
// in a unit test: GARP suppressed (no stray goroutine), state BACKUP, a
// local IP set so the handlers behave normally.
func newGateTestInstance(t *testing.T, priority int, preempt bool) *vrrpInstance {
	t.Helper()
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  priority,
		Preempt:   preempt,
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.setLocalIP(net.IPv4(10, 0, 0, 1))
	vi.suppressGARP.Store(true)
	vi.setState(StateBackup)
	return vi
}

// longTimers returns a masterDown/advert/preemptHold timer triple armed far in
// the future so that, in a stepBackup select, only a pre-loaded preemptNowCh
// (or rxCh) case is ready — making the select deterministic. Do NOT use
// already-expired timers in these wiring tests (that makes the select
// nondeterministic).
func longTimers(t *testing.T) (masterDown, advert, preemptHold *time.Timer) {
	t.Helper()
	masterDown = time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert = time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	preemptHold = time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })
	return masterDown, advert, preemptHold
}

// TestPreemptNow_LowerPriorityStaysBackup is the PRIMARY regression guard. A
// priority-100 preempt-enabled node that has just heard a live priority-200
// master must NOT become MASTER on the non-force sync-hold preempt kick.
//
// This MUST FAIL on the pre-fix code (`if vi.getPreempt() || force` →
// unconditional becomeMaster) — it tests the run-loop wiring, not the helper
// in isolation.
func TestPreemptNow_LowerPriorityStaysBackup(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 200
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	if stop := vi.stepBackup(masterDown, advert, preemptHold); stop {
		t.Fatal("stepBackup returned stop=true unexpectedly")
	}

	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (lower-priority non-force preempt must be blocked)", vi.getState())
	}
}

// TestPreemptNow_HigherPriorityBecomesMaster: a priority-200 node observing a
// priority-100 master passes the gate and becomes MASTER immediately (the
// legitimate fast preempt is preserved — no failover-timing regression).
func TestPreemptNow_HigherPriorityBecomesMaster(t *testing.T) {
	vi := newGateTestInstance(t, 200, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (higher priority must preempt)", vi.getState())
	}
}

// TestPreemptNow_EqualPriorityStaysBackup: equal priority does not preempt
// (RFC 5798 §6.4.2; no IP tie-break in the preempt gate). Wiring-level.
func TestPreemptNow_EqualPriorityStaysBackup(t *testing.T) {
	vi := newGateTestInstance(t, 150, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 150
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (equal priority must not preempt)", vi.getState())
	}
}

// TestPreemptNow_ForceBypassesGate: ForceRGMaster (force=true) is
// cluster-authoritative and bypasses the gate — a priority-100 node observing
// a priority-200 master still becomes MASTER when forced.
func TestPreemptNow_ForceBypassesGate(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 200
	vi.lastMasterSeen = time.Now()
	vi.forcePreemptOnce = true
	vi.mu.Unlock()

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (force must bypass the priority gate)", vi.getState())
	}
}

// TestPreemptNow_ForceBypassesGate_EvenWithoutPreempt: force=true must promote
// even when preempt is NOT configured (the ForceRGMaster one-shot semantics).
func TestPreemptNow_ForceBypassesGate_EvenWithoutPreempt(t *testing.T) {
	vi := newGateTestInstance(t, 100, false)
	vi.mu.Lock()
	vi.lastMasterPriority = 200
	vi.lastMasterSeen = time.Now()
	vi.forcePreemptOnce = true
	vi.mu.Unlock()

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (force must promote even with preempt=false)", vi.getState())
	}
}

// TestPreemptNow_NoPreemptStaysBackup: a non-force kick on a node with
// preempt=false never promotes (helper returns false on !preempt). Guards
// against a future change that drops the preempt check.
func TestPreemptNow_NoPreemptStaysBackup(t *testing.T) {
	vi := newGateTestInstance(t, 200, false)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (preempt=false must never preempt on the shortcut)", vi.getState())
	}
}

// TestPreemptNow_NoObservedMasterBecomesMaster: cold-start — never heard a
// master — the gate treats it as "no live master to respect" and the
// preempt-enabled node becomes MASTER on the kick (wiring-level).
func TestPreemptNow_NoObservedMasterBecomesMaster(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	// lastMasterSeen left zero.

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	vi.stepBackup(masterDown, advert, preemptHold)

	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (cold-start, no observed master)", vi.getState())
	}
}

// TestPreemptNow_DeniedGateLeavesMasterDownTimerArmed verifies invariant (a):
// a denied gate never stops the masterDownTimer, so the ungated RFC election
// remains armed and can still promote the node when the real master dies. A
// denied stepBackup is followed by a second stepBackup whose masterDownTimer
// has expired — that must promote to MASTER.
func TestPreemptNow_DeniedGateLeavesMasterDownTimerArmed(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 200
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	// First: denied non-force preempt kick. Use a long masterDown timer so
	// the select deterministically picks preemptNowCh.
	masterDownLong := time.NewTimer(time.Hour)
	defer masterDownLong.Stop()
	advert := time.NewTimer(time.Hour)
	defer advert.Stop()
	preemptHold := time.NewTimer(time.Hour)
	defer preemptHold.Stop()
	vi.triggerPreemptNow()
	vi.stepBackup(masterDownLong, advert, preemptHold)
	if vi.getState() != StateBackup {
		t.Fatalf("state = %s after denied gate, want BACKUP", vi.getState())
	}

	// Now simulate the masterDownTimer firing (real master died): a fresh,
	// already-expired masterDown timer drives the second iteration. The gate
	// never stopped the timer, so the RFC election promotes us. No hold-time
	// is configured (PreemptHoldTime 0) so takeover stays immediate (#2850).
	masterDownExpired := time.NewTimer(0)
	defer masterDownExpired.Stop()
	vi.stepBackup(masterDownExpired, advert, preemptHold)
	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (masterDown election must still promote after a denied gate)", vi.getState())
	}
}

// --- shouldPreemptObservedMaster helper unit tests ---

func TestShouldPreempt_NoObservedMaster(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	// lastMasterSeen zero → no live master → true (cold-start).
	if !vi.shouldPreemptObservedMaster() {
		t.Error("want true (no observed master / cold-start)")
	}
}

func TestShouldPreempt_StaleMaster(t *testing.T) {
	// Default RETH-ish interval; with a short advert, masterDownInterval is
	// tens of ms. Set lastMasterSeen well in the past so it is stale.
	vi := newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          100,
		Preempt:           true,
		AdvertiseInterval: 30,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)
	vi.mu.Lock()
	vi.lastMasterPriority = 200
	vi.lastMasterSeen = time.Now().Add(-1 * time.Hour)
	vi.mu.Unlock()
	if !vi.shouldPreemptObservedMaster() {
		t.Error("want true (stale master beyond masterDownInterval → silent-death rescue)")
	}
}

func TestShouldPreempt_LiveHigherMasterDenies(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 200
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if vi.shouldPreemptObservedMaster() {
		t.Error("want false (live higher-priority master → must not preempt)")
	}
}

func TestShouldPreempt_LiveLowerMasterAllows(t *testing.T) {
	vi := newGateTestInstance(t, 200, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if !vi.shouldPreemptObservedMaster() {
		t.Error("want true (strictly higher than the observed master → preempt)")
	}
}

func TestShouldPreempt_EqualPriorityNoPreempt(t *testing.T) {
	vi := newGateTestInstance(t, 150, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 150
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if vi.shouldPreemptObservedMaster() {
		t.Error("want false (equal priority does not preempt, RFC 5798 §6.4.2; no IP tie-break)")
	}
}

func TestShouldPreempt_NoPreemptConfigured(t *testing.T) {
	vi := newGateTestInstance(t, 200, false)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if vi.shouldPreemptObservedMaster() {
		t.Error("want false (preempt not configured)")
	}
}

// TestShouldPreempt_OwnerExemptFromTrackDemotion: priority 255 (address owner)
// is exempt from track-down demotion, so the owner's effective priority stays
// 255 and beats any observed master.
func TestShouldPreempt_OwnerExemptFromTrackDemotion(t *testing.T) {
	vi := newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          255,
		Preempt:           true,
		TrackInterface:    "ge-0-0-9",
		TrackPriorityCost: 100,
		AdvertiseInterval: 30,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)
	vi.mu.Lock()
	vi.trackDown = true // would normally demote, but 255 is exempt
	vi.lastMasterPriority = 200
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if !vi.shouldPreemptObservedMaster() {
		t.Error("want true (owner-255 is track-exempt; effective 255 > 200)")
	}
}

// TestShouldPreempt_TrackDemotedNodeDenied: a track-demoted node whose
// effective priority falls at/below the observed master must not preempt.
func TestShouldPreempt_TrackDemotedNodeDenied(t *testing.T) {
	// Priority 200, cost 150 while track down → effective 50, clamped not
	// needed (50 ≥ 1). Observed master at 100 → 50 > 100 false → denied.
	vi := newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		TrackInterface:    "ge-0-0-9",
		TrackPriorityCost: 150,
		AdvertiseInterval: 30,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 1), nil)
	vi.mu.Lock()
	vi.trackDown = true
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if vi.shouldPreemptObservedMaster() {
		t.Error("want false (track-demoted effective 50 ≤ observed master 100)")
	}
	// Sanity: the effective priority matches getPriority().
	if got := vi.getPriority(); got != 50 {
		t.Errorf("getPriority() = %d, want 50 (track demotion); gate must use the same effective value", got)
	}
}

// --- recordMasterAdvert tests ---

func TestRecordMasterAdvert_RecordsNonZero(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	masterDown := time.NewTimer(time.Hour)
	defer masterDown.Stop()
	preemptHold := time.NewTimer(time.Hour)
	defer preemptHold.Stop()

	before := time.Now()
	vi.handleBackupRx(&VRRPPacket{Priority: 200, SrcIP: net.IPv4(10, 0, 0, 2)}, masterDown, preemptHold)

	vi.mu.RLock()
	gotPri := vi.lastMasterPriority
	gotSeen := vi.lastMasterSeen
	vi.mu.RUnlock()
	if gotPri != 200 {
		t.Errorf("lastMasterPriority = %d, want 200", gotPri)
	}
	if gotSeen.Before(before) {
		t.Errorf("lastMasterSeen = %v, want ≥ %v", gotSeen, before)
	}
}

// TestRecordMasterAdvert_IgnoresPriorityZero: a priority-0 (resignation)
// advert must NOT update lastMaster* — post-resign takeover flows through the
// ungated masterDownTimer path, so recording a stale-high value is irrelevant
// and recording 0 would wrongly mark "no live master".
func TestRecordMasterAdvert_IgnoresPriorityZero(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	masterDown := time.NewTimer(time.Hour)
	defer masterDown.Stop()
	preemptHold := time.NewTimer(time.Hour)
	defer preemptHold.Stop()

	// Seed a recorded master.
	vi.mu.Lock()
	vi.lastMasterPriority = 200
	seeded := time.Now().Add(-time.Minute)
	vi.lastMasterSeen = seeded
	vi.mu.Unlock()

	// Feed a priority-0 advert (resignation).
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 2)}, masterDown, preemptHold)

	vi.mu.RLock()
	gotPri := vi.lastMasterPriority
	gotSeen := vi.lastMasterSeen
	vi.mu.RUnlock()
	if gotPri != 200 {
		t.Errorf("lastMasterPriority = %d, want 200 unchanged (priority-0 not recorded)", gotPri)
	}
	if !gotSeen.Equal(seeded) {
		t.Errorf("lastMasterSeen = %v, want unchanged %v (priority-0 not recorded)", gotSeen, seeded)
	}
}

// TestRecordMasterAdvert_MasterRxAlsoRecords: handleMasterRx records too, so a
// node that observes a peer while it is itself MASTER tracks the peer priority.
func TestRecordMasterAdvert_MasterRxAlsoRecords(t *testing.T) {
	vi := newGateTestInstance(t, 200, true)
	vi.setState(StateMaster)
	masterDown := time.NewTimer(time.Hour)
	defer masterDown.Stop()
	advert := time.NewTimer(time.Hour)
	defer advert.Stop()

	vi.handleMasterRx(&VRRPPacket{Priority: 100, SrcIP: net.IPv4(10, 0, 0, 2)}, masterDown, advert)

	vi.mu.RLock()
	gotPri := vi.lastMasterPriority
	vi.mu.RUnlock()
	if gotPri != 100 {
		t.Errorf("lastMasterPriority = %d, want 100 (handleMasterRx must record)", gotPri)
	}
}
