package vrrp

import (
	"net"
	"testing"
	"time"
)

// Tests for the address-owner preempt override (#4116). RFC 5798 §6.1 requires
// the IP address owner (priority 255) to preempt a lower-priority master
// "irrespective of the setting of" the preempt flag. Before the fix an owner
// configured with `no-preempt` that returned after a peer took over reset its
// master-down timer on every lower-priority advert (handleBackupRx) and stayed
// BACKUP forever, though it OWNS the VIP.
//
// These drive the same seams as instance_preempt_gate_test.go (getPreempt,
// shouldPreemptObservedMaster, handleBackupRx, stepBackup) — no run() (its
// preamble spawns a receiver that nil-derefs vi.conn).

// TestGetPreempt_OwnerAlwaysPreempts: getPreempt() returns true for the address
// owner (priority 255) regardless of the configured preempt flag, and honors
// the configured flag for every non-owner. RED on the pre-fix code, where an
// owner with no-preempt returned false.
func TestGetPreempt_OwnerAlwaysPreempts(t *testing.T) {
	cases := []struct {
		name     string
		priority int
		preempt  bool
		want     bool
	}{
		{"owner-no-preempt", 255, false, true}, // #4116: owner always preempts
		{"owner-preempt", 255, true, true},     // owner, preempt configured
		{"non-owner-no-preempt", 200, false, false},
		{"non-owner-preempt", 200, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vi := newGateTestInstance(t, tc.priority, tc.preempt)
			if got := vi.getPreempt(); got != tc.want {
				t.Errorf("getPreempt() = %v, want %v (priority=%d preempt=%v)",
					got, tc.want, tc.priority, tc.preempt)
			}
		})
	}
}

// TestGetPreempt_OwnerPreemptsDespiteSyncHoldSuppression: sync hold suppresses
// cfg.Preempt (suppressPreempt sets it false) while preserving desiredPreempt.
// The owner override keys on cfg.Priority, so getPreempt() still returns true
// under sync-hold suppression — the owner is not held BACKUP by sync hold.
func TestGetPreempt_OwnerPreemptsDespiteSyncHoldSuppression(t *testing.T) {
	vi := newGateTestInstance(t, 255, true)
	vi.suppressPreempt() // sync hold: cfg.Preempt = false
	if !vi.getPreempt() {
		t.Error("getPreempt() = false for owner-255 under sync-hold suppression; want true (#4116)")
	}
	// A non-owner under suppression correctly reports no preempt.
	non := newGateTestInstance(t, 200, true)
	non.suppressPreempt()
	if non.getPreempt() {
		t.Error("getPreempt() = true for non-owner under sync-hold suppression; want false")
	}
}

// TestShouldPreempt_OwnerNoPreemptStillPreempts: the sync-hold-release /
// preempt-hold re-validation gate (shouldPreemptObservedMaster) lets the owner
// through even with preempt disabled. RED on the pre-fix `if !preempt` gate.
func TestShouldPreempt_OwnerNoPreemptStillPreempts(t *testing.T) {
	vi := newGateTestInstance(t, 255, false) // owner, no-preempt
	vi.mu.Lock()
	vi.lastMasterPriority = 200 // a live lower-priority master
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if !vi.shouldPreemptObservedMaster() {
		t.Error("want true (owner-255 preempts irrespective of the no-preempt flag, RFC 5798 §6.1, #4116)")
	}
}

// TestShouldPreempt_NonOwnerNoPreemptStillDenied: the owner override must NOT
// leak to non-owners — a priority-200 no-preempt node facing a lower master
// still does not preempt on the shortcut (no-preempt honored).
func TestShouldPreempt_NonOwnerNoPreemptStillDenied(t *testing.T) {
	vi := newGateTestInstance(t, 200, false)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if vi.shouldPreemptObservedMaster() {
		t.Error("want false (non-owner no-preempt must still honor the no-preempt flag)")
	}
}

// TestOwnerPreempt_NoPreemptBecomesMasterOnKick: wiring-level. An owner (255,
// no-preempt) that has heard a live LOWER-priority (100) master becomes MASTER
// on the non-force sync-hold preempt kick. RED on the pre-fix code (the gate
// denied a no-preempt node → the owner stayed BACKUP).
func TestOwnerPreempt_NoPreemptBecomesMasterOnKick(t *testing.T) {
	vi := newGateTestInstance(t, 255, false)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	if stop := vi.stepBackup(masterDown, advert, preemptHold); stop {
		t.Fatal("stepBackup returned stop=true unexpectedly")
	}
	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (owner-255 must preempt even with preempt disabled)", vi.getState())
	}
}

// TestOwnerPreempt_ReclaimsFromLowerMaster is the PRIMARY end-to-end guard for
// the reported defect (the handleBackupRx master-down-reset gate, instance.go).
// An owner (255, no-preempt) in BACKUP that hears a live LOWER-priority master
// must NOT reset its master-down timer, so the timer expires and the next
// stepBackup promotes it to MASTER.
//
// RED on revert: the pre-fix getPreempt() returns false for the owner, so the
// gate `!getPreempt() || pkt.Priority >= pri` is true and resets the timer to
// masterDownInterval() (~3s at the default 1s advert interval) — the short
// deadline never fires within the wait and the owner never reclaims.
func TestOwnerPreempt_ReclaimsFromLowerMaster(t *testing.T) {
	vi := newGateTestInstance(t, 255, false)

	// Master-down timer armed short, mimicking a BACKUP tenure about to end.
	// The default advert interval makes masterDownInterval() ~3s, so a RESET
	// (the pre-fix bug) pushes the fire far past this deadline; the fix leaves
	// it intact so it still fires ~40ms out.
	mdt := time.NewTimer(40 * time.Millisecond)
	defer mdt.Stop()
	hold := time.NewTimer(time.Hour)
	defer hold.Stop()

	// Owner hears the peer's LOWER-priority (100) advert.
	vi.handleBackupRx(&VRRPPacket{Priority: 100, SrcIP: net.IPv4(10, 0, 0, 2)}, mdt, hold)

	// The gate must NOT have reset the timer for the owner.
	select {
	case <-mdt.C:
		// fired promptly → timer was not reset → correct
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("owner-255 master-down timer was reset by a lower-priority advert; " +
			"the owner would never reclaim MASTER (RFC 5798 §6.1, #4116)")
	}

	// The fired master-down timer now drives the BACKUP select → becomeMaster.
	// Re-arm an already-expired timer so the select deterministically promotes.
	mdt.Reset(0)
	advert := time.NewTimer(time.Hour)
	defer advert.Stop()
	if stop := vi.stepBackup(mdt, advert, hold); stop {
		t.Fatal("stepBackup returned stop=true unexpectedly")
	}
	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (owner reclaims after master-down expiry)", vi.getState())
	}
}

// TestNonOwnerNoPreempt_LowerAdvertResetsMasterDownTimer is the no-regression
// twin of the reclaim test: a NON-owner (200, no-preempt) hearing a lower
// advert DOES reset its master-down timer (no-preempt honored), so a short
// deadline is pushed out and does not fire. Passes both pre- and post-fix —
// it guards against the owner override leaking to non-owners.
func TestNonOwnerNoPreempt_LowerAdvertResetsMasterDownTimer(t *testing.T) {
	vi := newGateTestInstance(t, 200, false)

	mdt := time.NewTimer(40 * time.Millisecond)
	defer mdt.Stop()
	hold := time.NewTimer(time.Hour)
	defer hold.Stop()

	vi.handleBackupRx(&VRRPPacket{Priority: 100, SrcIP: net.IPv4(10, 0, 0, 2)}, mdt, hold)

	// The gate reset the timer to masterDownInterval() (~3s), so the original
	// 40ms deadline is gone — it must NOT fire within a generous window.
	select {
	case <-mdt.C:
		t.Fatal("non-owner no-preempt master-down timer fired; a lower advert must reset it (no-preempt honored)")
	case <-time.After(300 * time.Millisecond):
		// did not fire → correctly reset far out → no-preempt honored
	}
}

// TestOwnerPreempt_PreemptEnabledUnchanged: an owner with preempt ENABLED is
// unaffected by the override (it already preempted). Sanity that the override
// composes rather than changing enabled-preempt behavior.
func TestOwnerPreempt_PreemptEnabledUnchanged(t *testing.T) {
	vi := newGateTestInstance(t, 255, true)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown, advert, preemptHold := longTimers(t)
	vi.triggerPreemptNow()
	vi.stepBackup(masterDown, advert, preemptHold)
	if vi.getState() != StateMaster {
		t.Errorf("state = %s, want MASTER (owner-255 preempt-enabled unchanged)", vi.getState())
	}
}
