package daemon

import (
	"testing"
	"time"
)

func TestRGStateMachine_ClusterOnly(t *testing.T) {
	s := newRGStateMachine()

	// Initial: inactive.
	if s.IsActive() {
		t.Error("new state machine should be inactive")
	}

	// Cluster Primary → active.
	tr := s.SetCluster(true)
	if !tr.Changed || !tr.Active {
		t.Errorf("SetCluster(true): Changed=%v Active=%v, want true/true", tr.Changed, tr.Active)
	}
	if !s.IsActive() {
		t.Error("should be active after cluster Primary")
	}

	// Cluster Primary again (idempotent) → no change.
	tr = s.SetCluster(true)
	if tr.Changed {
		t.Error("duplicate SetCluster(true) should not change")
	}

	// Cluster Secondary → inactive (no VRRP instances).
	tr = s.SetCluster(false)
	if !tr.Changed || tr.Active {
		t.Errorf("SetCluster(false): Changed=%v Active=%v, want true/false", tr.Changed, tr.Active)
	}
}

func TestRGStateMachine_VRRPOnly(t *testing.T) {
	s := newRGStateMachine()

	// VRRP MASTER → active.
	tr := s.SetVRRP("reth0", true)
	if !tr.Changed || !tr.Active {
		t.Errorf("SetVRRP(true): Changed=%v Active=%v, want true/true", tr.Changed, tr.Active)
	}

	// VRRP BACKUP → inactive.
	tr = s.SetVRRP("reth0", false)
	if !tr.Changed || tr.Active {
		t.Errorf("SetVRRP(false): Changed=%v Active=%v, want true/false", tr.Changed, tr.Active)
	}
}

func TestRGStateMachine_CombinedActivation(t *testing.T) {
	s := newRGStateMachine()

	// VRRP MASTER (no cluster) → active.
	tr := s.SetVRRP("reth0", true)
	if !tr.Changed || !tr.Active {
		t.Fatal("VRRP MASTER alone should activate")
	}

	// Cluster Primary (VRRP already MASTER) → no change.
	tr = s.SetCluster(true)
	if tr.Changed {
		t.Error("cluster Primary should not change when already active via VRRP")
	}
	if !tr.Active {
		t.Error("should still be active")
	}

	// VRRP BACKUP (cluster still Primary) → no change.
	tr = s.SetVRRP("reth0", false)
	if tr.Changed {
		t.Error("VRRP BACKUP should not deactivate when cluster is Primary")
	}
	if !tr.Active {
		t.Error("should still be active via cluster Primary")
	}

	// Cluster Secondary (VRRP is BACKUP) → deactivate.
	tr = s.SetCluster(false)
	if !tr.Changed || tr.Active {
		t.Error("both cluster=Secondary and VRRP=BACKUP should deactivate")
	}
}

func TestRGStateMachine_DualInactiveWindowPrevention(t *testing.T) {
	// Simulates the failover scenario:
	// 1. Old primary: cluster Secondary (VRRP still MASTER briefly)
	// 2. New primary: cluster Primary (VRRP MASTER comes later)
	s := newRGStateMachine()

	// Initial: cluster Primary, VRRP MASTER.
	s.SetCluster(true)
	s.SetVRRP("reth0", true)
	if !s.IsActive() {
		t.Fatal("initial state should be active")
	}

	// Cluster goes Secondary, but VRRP is still MASTER.
	tr := s.SetCluster(false)
	if tr.Changed {
		t.Error("should stay active — VRRP is still MASTER")
	}
	if !s.IsActive() {
		t.Error("should remain active while VRRP is MASTER")
	}

	// VRRP goes BACKUP → now deactivate.
	tr = s.SetVRRP("reth0", false)
	if !tr.Changed || tr.Active {
		t.Error("should deactivate when both cluster=Secondary and VRRP=BACKUP")
	}
}

func TestRGStateMachine_EpochMonotonic(t *testing.T) {
	s := newRGStateMachine()

	var lastEpoch uint64
	for i := 0; i < 10; i++ {
		tr := s.SetVRRP("reth0", i%2 == 0)
		if tr.Epoch <= lastEpoch {
			t.Errorf("epoch %d not monotonically increasing (prev=%d)", tr.Epoch, lastEpoch)
		}
		lastEpoch = tr.Epoch
	}
	for i := 0; i < 10; i++ {
		tr := s.SetCluster(i%2 == 0)
		if tr.Epoch <= lastEpoch {
			t.Errorf("epoch %d not monotonically increasing (prev=%d)", tr.Epoch, lastEpoch)
		}
		lastEpoch = tr.Epoch
	}
}

func TestRGStateMachine_Reconcile(t *testing.T) {
	s := newRGStateMachine()

	// Set up initial state: cluster Primary, one VRRP MASTER.
	s.SetCluster(true)
	s.SetVRRP("reth0", true)
	if !s.IsActive() {
		t.Fatal("should be active initially")
	}

	// Simulate dropped VRRP BACKUP event: VRRP actually went BACKUP,
	// but the event was dropped. State machine still thinks VRRP is MASTER.
	// Reconcile with actual state: cluster=Primary, VRRP=BACKUP.
	tr := s.Reconcile(true, map[string]bool{"reth0": false})
	// Still active because cluster is Primary (clusterPri || anyVrrpMaster).
	if tr.Changed {
		t.Error("should not change — cluster Primary keeps it active")
	}
	if !s.IsActive() {
		t.Error("should still be active via cluster Primary")
	}

	// Now simulate dropped cluster Secondary event too.
	tr = s.Reconcile(false, map[string]bool{"reth0": false})
	if !tr.Changed || tr.Active {
		t.Error("should deactivate — both cluster=Secondary and VRRP=BACKUP")
	}
	if s.IsActive() {
		t.Error("should be inactive after reconciliation")
	}
}

func TestRGStateMachine_ReconcileCorrectsDrift(t *testing.T) {
	s := newRGStateMachine()

	// State machine thinks inactive, but actual state says active.
	// This simulates a dropped VRRP MASTER event.
	tr := s.Reconcile(false, map[string]bool{"reth0": true})
	if !tr.Changed || !tr.Active {
		t.Error("reconcile should activate — VRRP is actually MASTER")
	}

	// Reconcile again — no change.
	tr = s.Reconcile(false, map[string]bool{"reth0": true})
	if tr.Changed {
		t.Error("second reconcile should not change")
	}
}

func TestRGStateMachine_ReconcileMultiInstance(t *testing.T) {
	s := newRGStateMachine()

	// State machine knows reth1 but not reth1.50 (dropped event).
	s.SetVRRP("reth1", true)
	if !s.IsActive() {
		t.Fatal("should be active")
	}

	// Reconcile reveals reth1 is BACKUP, reth1.50 is MASTER.
	tr := s.Reconcile(false, map[string]bool{
		"reth1":    false,
		"reth1.50": true,
	})
	// Still active (anyVrrpMaster=true via reth1.50).
	if tr.Changed {
		t.Error("should remain active — reth1.50 is MASTER")
	}

	// allMaster should be false (reth1 is BACKUP).
	if s.AllVRRPMaster() {
		t.Error("allMaster should be false — reth1 is BACKUP")
	}
}

func TestRGStateMachine_MultiInstanceVRRP(t *testing.T) {
	s := newRGStateMachine()

	// Instance A MASTER → active.
	tr := s.SetVRRP("reth1", true)
	if !tr.Changed || !tr.Active {
		t.Fatal("first MASTER instance should activate")
	}

	// Instance B still BACKUP → still active (anyMaster=true).
	tr = s.SetVRRP("reth1.50", false)
	if tr.Changed {
		t.Error("should remain active while reth1 is MASTER")
	}

	// Instance A BACKUP → now deactivate (no master instances).
	tr = s.SetVRRP("reth1", false)
	if !tr.Changed || tr.Active {
		t.Error("should deactivate when all instances are BACKUP")
	}

	// allMaster check: only one of two is MASTER.
	s.SetVRRP("reth1", true)
	if s.AllVRRPMaster() {
		t.Error("should not be allMaster when reth1.50 is BACKUP")
	}

	// Both MASTER → allMaster.
	s.SetVRRP("reth1.50", true)
	if !s.AllVRRPMaster() {
		t.Error("should be allMaster when both instances are MASTER")
	}
}

func TestRGStateMachine_DesiredVsApplied(t *testing.T) {
	s := newRGStateMachine()

	// Initial: no pending apply.
	if s.NeedsApply() {
		t.Error("new state machine should not need apply")
	}

	// Activate — desired changes but not yet applied.
	s.SetCluster(true)
	if !s.NeedsApply() {
		t.Error("should need apply after activation")
	}
	if !s.DesiredActive() {
		t.Error("desired should be active")
	}

	// Mark applied — now in sync.
	s.MarkApplied(true)
	if s.NeedsApply() {
		t.Error("should not need apply after MarkApplied")
	}

	// Deactivate — needs apply again.
	s.SetCluster(false)
	if !s.NeedsApply() {
		t.Error("should need apply after deactivation")
	}

	// Mark wrong value — still needs apply.
	s.MarkApplied(true)
	if !s.NeedsApply() {
		t.Error("should still need apply when applied != desired")
	}

	// Mark correct value.
	s.MarkApplied(false)
	if s.NeedsApply() {
		t.Error("should not need apply after correct MarkApplied")
	}
}

func TestRGStateMachine_ApplyIfCurrent_StaleDetection(t *testing.T) {
	s := newRGStateMachine()

	// Activate via cluster.
	tr1 := s.SetCluster(true)
	if !tr1.Changed || !tr1.Active {
		t.Fatal("cluster Primary should activate")
	}

	// Before applying tr1, a VRRP BACKUP event supersedes.
	// First set VRRP MASTER so we can go to BACKUP.
	s.SetVRRP("reth0", true) // epoch advances
	tr3 := s.SetVRRP("reth0", false)

	// Now also deactivate cluster — should deactivate (epoch advanced again).
	tr4 := s.SetCluster(false)
	if !tr4.Changed || tr4.Active {
		t.Fatal("should deactivate after both sources false")
	}

	// Try to apply the stale tr1 (activation) — should be rejected.
	if s.ApplyIfCurrent(tr1) {
		t.Error("ApplyIfCurrent should reject stale transition (tr1)")
	}

	// Apply the stale tr3 — should also be rejected.
	if s.ApplyIfCurrent(tr3) {
		t.Error("ApplyIfCurrent should reject stale transition (tr3)")
	}

	// Apply the current tr4 — should succeed.
	if !s.ApplyIfCurrent(tr4) {
		t.Error("ApplyIfCurrent should accept current transition")
	}

	// Verify applied state matches.
	if s.NeedsApply() {
		t.Error("should not need apply after successful ApplyIfCurrent")
	}
}

func TestRGStateMachine_CurrentDesired(t *testing.T) {
	s := newRGStateMachine()

	active, epoch := s.CurrentDesired()
	if active {
		t.Error("initial state should be inactive")
	}
	if epoch != 0 {
		t.Error("initial epoch should be 0")
	}

	s.SetCluster(true)
	active, epoch = s.CurrentDesired()
	if !active {
		t.Error("should be active after cluster Primary")
	}
	if epoch != 1 {
		t.Errorf("epoch should be 1, got %d", epoch)
	}

	// Interleaved: VRRP goes MASTER then BACKUP while we hold stale active=true.
	s.SetVRRP("reth0", true) // epoch 2
	s.SetVRRP("reth0", false) // epoch 3, still active via cluster

	active, epoch = s.CurrentDesired()
	if !active {
		t.Error("should still be active — cluster is Primary")
	}
	if epoch != 3 {
		t.Errorf("epoch should be 3, got %d", epoch)
	}
}

func TestRGStateMachine_DesiredVsApplied_RetryOnFailure(t *testing.T) {
	s := newRGStateMachine()

	// Activate.
	s.SetCluster(true)
	if !s.NeedsApply() {
		t.Fatal("should need apply")
	}

	// Simulate failed apply (don't call MarkApplied).
	// NeedsApply should still be true.
	if !s.NeedsApply() {
		t.Error("should still need apply after failed attempt")
	}

	// Reconcile with same state — NeedsApply stays true.
	s.Reconcile(true, map[string]bool{})
	if !s.NeedsApply() {
		t.Error("reconcile should preserve pending apply")
	}

	// Mark applied.
	s.MarkApplied(true)
	if s.NeedsApply() {
		t.Error("should not need apply after MarkApplied")
	}

	// Reconcile again — no change, no pending apply.
	tr := s.Reconcile(true, map[string]bool{})
	if tr.Changed {
		t.Error("second reconcile should not change")
	}
	if s.NeedsApply() {
		t.Error("should not need apply when already applied")
	}
}

func TestRGStateMachine_CheckVRRPPosture_NoMismatch(t *testing.T) {
	s := newRGStateMachine()
	now := time.Now()

	// Cluster Primary + VRRP MASTER → no mismatch.
	s.SetCluster(true)
	s.SetVRRP("reth0", true)
	if got := s.CheckVRRPPosture(now); got != vrrpPostureOK {
		t.Errorf("expected OK, got %d", got)
	}

	// Cluster Secondary + VRRP BACKUP → no mismatch.
	s.SetCluster(false)
	s.SetVRRP("reth0", false)
	if got := s.CheckVRRPPosture(now); got != vrrpPostureOK {
		t.Errorf("expected OK, got %d", got)
	}
}

func TestRGStateMachine_CheckVRRPPosture_NeedsMaster_DelayedAction(t *testing.T) {
	s := newRGStateMachine()
	now := time.Now()

	// Cluster Primary but VRRP BACKUP → mismatch detected.
	s.SetCluster(true)
	s.SetVRRP("reth0", false)

	// First check: starts timer, returns OK (no immediate action).
	if got := s.CheckVRRPPosture(now); got != vrrpPostureOK {
		t.Errorf("first check should return OK, got %d", got)
	}

	// Check before delay expires: still OK.
	if got := s.CheckVRRPPosture(now.Add(5 * time.Second)); got != vrrpPostureOK {
		t.Errorf("check at 5s should return OK, got %d", got)
	}

	// Check after delay expires: needs MASTER.
	if got := s.CheckVRRPPosture(now.Add(11 * time.Second)); got != vrrpPostureNeedsMaster {
		t.Errorf("check at 11s should return NeedsMaster, got %d", got)
	}

	// Timer was reset — next check starts fresh.
	if got := s.CheckVRRPPosture(now.Add(12 * time.Second)); got != vrrpPostureOK {
		t.Errorf("check after correction should return OK (timer reset), got %d", got)
	}
}

func TestRGStateMachine_CheckVRRPPosture_NeedsResign_DelayedAction(t *testing.T) {
	s := newRGStateMachine()
	now := time.Now()

	// Cluster Secondary but VRRP MASTER → mismatch.
	s.SetCluster(false)
	s.SetVRRP("reth0", true)

	// First check: starts timer.
	if got := s.CheckVRRPPosture(now); got != vrrpPostureOK {
		t.Errorf("first check should return OK, got %d", got)
	}

	// After delay: needs resign.
	if got := s.CheckVRRPPosture(now.Add(11 * time.Second)); got != vrrpPostureNeedsResign {
		t.Errorf("check at 11s should return NeedsResign, got %d", got)
	}
}

func TestRGStateMachine_CheckVRRPPosture_MismatchClears(t *testing.T) {
	s := newRGStateMachine()
	now := time.Now()

	// Create mismatch: cluster Primary, VRRP BACKUP.
	s.SetCluster(true)
	s.SetVRRP("reth0", false)

	// Start mismatch timer.
	s.CheckVRRPPosture(now)

	// VRRP becomes MASTER before delay expires → mismatch clears.
	s.SetVRRP("reth0", true)
	if got := s.CheckVRRPPosture(now.Add(5 * time.Second)); got != vrrpPostureOK {
		t.Errorf("should return OK after mismatch cleared, got %d", got)
	}

	// Verify timer was reset: create mismatch again.
	s.SetVRRP("reth0", false)
	s.CheckVRRPPosture(now.Add(6 * time.Second)) // start timer

	// Check at original now+11s — should NOT trigger because timer was reset at +6s.
	if got := s.CheckVRRPPosture(now.Add(11 * time.Second)); got != vrrpPostureOK {
		t.Errorf("should return OK — timer was reset at 6s, only 5s elapsed, got %d", got)
	}

	// Check at +17s (11s since reset at +6s) — should trigger.
	if got := s.CheckVRRPPosture(now.Add(17 * time.Second)); got != vrrpPostureNeedsMaster {
		t.Errorf("should return NeedsMaster after 11s from timer reset, got %d", got)
	}
}
