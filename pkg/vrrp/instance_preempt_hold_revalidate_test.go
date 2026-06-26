package vrrp

import (
	"testing"
	"time"
)

// Tests for re-validation of an armed preempt hold-time (#2900). Once the
// preempt hold-time countdown is armed (#2850), two state changes during the
// hold window are not visible on the wire and so must be honored explicitly:
//
//   1. Expiry must re-validate: when the hold elapses, the instance only takes
//      over if preemption is still enabled AND its effective priority is still
//      strictly greater than the live master's (RFC 5798 §6.4.2). A master that
//      went silent during the hold reads as stale → takeover (dead master).
//   2. A config update during the hold (updateConfig) must tear an armed hold
//      down so a later preempt-disable / priority-demotion cannot fire a
//      spurious takeover at the old expiry.
//
// These drive stepBackup() directly (see instance_preempt_holdtime_test.go for
// why run() is unsafe in a unit test).

// armHold runs the masterDownTimer-expiry step that arms the hold and asserts
// the instance stayed BACKUP with the hold armed. It returns the long-lived
// advert/preemptHold timers so the caller can drive the next step.
func armHold(t *testing.T, vi *vrrpInstance) (advert, preemptHold *time.Timer) {
	t.Helper()
	masterDown, advert, preemptHold := expiredMasterDown(t)
	vi.stepBackup(masterDown, advert, preemptHold)
	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP (hold armed)", vi.getState())
	}
	vi.mu.RLock()
	armed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if !armed {
		t.Fatalf("preemptHoldArmed = false, want true after arming the hold")
	}
	return advert, preemptHold
}

// fireHold resets the (armed) hold timer to fire promptly and runs the
// hold-elapsed step with a long masterDownTimer.
func fireHold(t *testing.T, vi *vrrpInstance, advert, preemptHold *time.Timer) *time.Timer {
	t.Helper()
	stopAndDrainTimer(preemptHold)
	preemptHold.Reset(0)
	time.Sleep(2 * time.Millisecond)
	masterDownLong := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDownLong.Stop() })
	vi.stepBackup(masterDownLong, advert, preemptHold)
	return masterDownLong
}

// TestHoldExpiry_PreemptDisabledMidHold_NoTakeover: arm the hold against a live
// lower master, disable preempt during the hold, then fire the hold. The
// instance must NOT become MASTER (RFC 5798 §6.4.2 — a non-preempting node does
// not preempt). Reverting the expiry re-validation makes this promote and fail.
func TestHoldExpiry_PreemptDisabledMidHold_NoTakeover(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	advert, preemptHold := armHold(t, vi)

	// Preempt disabled mid-hold (e.g. operator `delete ... preempt`).
	vi.suppressPreempt()
	// Keep the live lower master "fresh" so the only reason to abort is the
	// preempt-disable, not staleness.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	fireHold(t, vi, advert, preemptHold)
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (preempt disabled mid-hold → no takeover)", vi.getState())
	}
}

// TestHoldExpiry_PriorityDemotedMidHold_NoTakeover: arm the hold against a live
// lower (priority 100) master while we advertise 200; a track-interface goes
// down during the hold and demotes our effective priority below the live
// master. On expiry we must NOT take over (we no longer outrank it). Reverting
// the expiry re-validation makes this promote and fail.
func TestHoldExpiry_PriorityDemotedMidHold_NoTakeover(t *testing.T) {
	vi := newHoldTestInstance(t, 110, 60)
	// Configure interface tracking so a link-down demotes our priority.
	vi.mu.Lock()
	vi.cfg.TrackInterface = "eth1"
	vi.cfg.TrackPriorityCost = 50 // 110 - 50 = 60 effective, below the 100 master
	vi.lastMasterPriority = 100   // live lower master (we are 110 > 100 → preempt)
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	advert, preemptHold := armHold(t, vi)

	// Tracked link goes down mid-hold → effective priority 60 < 100.
	vi.setTrackDown(true)
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now() // keep the master fresh
	vi.mu.Unlock()

	fireHold(t, vi, advert, preemptHold)
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (priority demoted below live master → no takeover)", vi.getState())
	}
}

// TestHoldExpiry_StillValid_Takeover: the control case — preempt stays enabled
// and our priority stays above the live master. On expiry we DO become MASTER.
func TestHoldExpiry_StillValid_Takeover(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	advert, preemptHold := armHold(t, vi)
	// No change during the hold — premise still holds.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	fireHold(t, vi, advert, preemptHold)
	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (preempt + higher priority still valid → takeover)", vi.getState())
	}
}

// TestHoldExpiry_SilentMasterMidHold_Takeover: the master goes silent during
// the hold (no advert beyond the master-down horizon). This is a dead-master
// takeover, not a preemption, and must still promote — the re-validation gate
// must not suppress it.
func TestHoldExpiry_SilentMasterMidHold_Takeover(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	advert, preemptHold := armHold(t, vi)

	// Master fell silent: last advert is now beyond the master-down horizon.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now().Add(-time.Hour)
	vi.mu.Unlock()

	fireHold(t, vi, advert, preemptHold)
	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (master went silent → dead-master takeover)", vi.getState())
	}
}

// TestHoldConfigUpdate_PreemptDisabled_StopsArmedHold: arm the hold, then call
// updateConfig with Preempt=false. The configUpdatedCh case in stepBackup must
// disarm the in-flight hold (no later spurious takeover). Reverting the
// updateConfig timer-stop leaves the hold armed and this fails.
func TestHoldConfigUpdate_PreemptDisabled_StopsArmedHold(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	advert, preemptHold := armHold(t, vi)

	// Config update: preempt disabled. updateConfig signals configUpdatedCh.
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           false,
		PreemptHoldTime:   60,
		AdvertiseInterval: 30,
	})

	// Run the BACKUP select once; it must take the configUpdatedCh case and
	// disarm the hold. masterDownTimer is long so it does not race the signal.
	masterDownLong := time.NewTimer(time.Hour)
	defer masterDownLong.Stop()
	vi.stepBackup(masterDownLong, advert, preemptHold)

	vi.mu.RLock()
	armed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if armed {
		t.Fatal("preemptHoldArmed = true after config update disabling preempt; hold should have been disarmed")
	}
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (config update during hold must not take over)", vi.getState())
	}
	// The hold timer must be stopped+drained: Stop() returns false and the
	// channel is empty. (It was armed at time.Hour, then disarmed.)
	if preemptHold.Stop() {
		t.Error("preemptHold still active after config update; hold should have been stopped")
	}
	select {
	case <-preemptHold.C:
		t.Error("preemptHold had a pending fire after disarm; hold should have been drained")
	default:
	}
}
