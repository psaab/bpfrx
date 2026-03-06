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
		t.Fatal("should be active (sole instance = allMaster)")
	}

	// Reconcile reveals reth1 is BACKUP, reth1.50 is MASTER.
	// allMaster is false (reth1 BACKUP) → deactivate (#132).
	tr := s.Reconcile(false, map[string]bool{
		"reth1":    false,
		"reth1.50": true,
	})
	if !tr.Changed || tr.Active {
		t.Error("should deactivate — not all instances are MASTER (#132)")
	}

	// allMaster should be false (reth1 is BACKUP).
	if s.AllVRRPMaster() {
		t.Error("allMaster should be false — reth1 is BACKUP")
	}
}

func TestRGStateMachine_MultiInstanceVRRP(t *testing.T) {
	s := newRGStateMachine()

	// Instance A MASTER (only instance) → active (allMaster: 1/1).
	tr := s.SetVRRP("reth1", true)
	if !tr.Changed || !tr.Active {
		t.Fatal("sole MASTER instance should activate")
	}

	// Instance B registered as BACKUP → deactivate (allMaster: 1/2, #132).
	tr = s.SetVRRP("reth1.50", false)
	if !tr.Changed || tr.Active {
		t.Error("should deactivate — not all instances are MASTER (#132)")
	}

	// Instance A BACKUP → already inactive (allMaster: 0/2).
	tr = s.SetVRRP("reth1", false)
	if tr.Changed {
		t.Error("should remain inactive — was already deactivated")
	}

	// allMaster check: only one of two is MASTER.
	s.SetVRRP("reth1", true)
	if s.AllVRRPMaster() {
		t.Error("should not be allMaster when reth1.50 is BACKUP")
	}

	// Both MASTER → allMaster and active.
	tr = s.SetVRRP("reth1.50", true)
	if !s.AllVRRPMaster() {
		t.Error("should be allMaster when both instances are MASTER")
	}
	if !tr.Changed || !tr.Active {
		t.Error("should activate when all instances become MASTER")
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

func TestRGStateMachine_CheckVRRPPosture_NoInstances(t *testing.T) {
	s := newRGStateMachine()
	now := time.Now()

	// Cluster says primary, but NO VRRP instances exist (e.g. interface
	// missing after reboot). Should never trigger posture correction.
	s.SetCluster(true)

	// First check — should return OK (no instances to correct).
	if got := s.CheckVRRPPosture(now); got != vrrpPostureOK {
		t.Errorf("no instances: expected OK, got %d", got)
	}

	// Even after delay — still OK because correction is impossible.
	if got := s.CheckVRRPPosture(now.Add(20 * time.Second)); got != vrrpPostureOK {
		t.Errorf("no instances after delay: expected OK, got %d", got)
	}

	// Cluster secondary, no instances — also OK.
	s.SetCluster(false)
	if got := s.CheckVRRPPosture(now.Add(30 * time.Second)); got != vrrpPostureOK {
		t.Errorf("secondary no instances: expected OK, got %d", got)
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

func TestRGStateMachine_CheckVRRPPosture_SteadyStateFasterDelay(t *testing.T) {
	s := newRGStateMachine()
	// Push startedAt into the past so we're past the startup window.
	s.startedAt = time.Now().Add(-time.Minute)
	now := time.Now()

	// Cluster Primary but VRRP BACKUP → mismatch.
	s.SetCluster(true)
	s.SetVRRP("reth0", false)

	// First check: starts mismatch timer.
	if got := s.CheckVRRPPosture(now); got != vrrpPostureOK {
		t.Errorf("first check should return OK, got %d", got)
	}

	// At 1s: still within steady-state delay (2s).
	if got := s.CheckVRRPPosture(now.Add(1 * time.Second)); got != vrrpPostureOK {
		t.Errorf("check at 1s should return OK (within 2s delay), got %d", got)
	}

	// At 3s: past steady-state delay → corrective action.
	if got := s.CheckVRRPPosture(now.Add(3 * time.Second)); got != vrrpPostureNeedsMaster {
		t.Errorf("check at 3s should return NeedsMaster (past 2s delay), got %d", got)
	}
}

func TestRGStateMachine_CheckVRRPPosture_StartupUsesLongerDelay(t *testing.T) {
	s := newRGStateMachine()
	// startedAt is ~now (default from newRGStateMachine), so we're in the startup window.
	now := time.Now()

	// Cluster Primary but VRRP BACKUP → mismatch.
	s.SetCluster(true)
	s.SetVRRP("reth0", false)

	// First check: starts mismatch timer.
	s.CheckVRRPPosture(now)

	// At 3s: would trigger in steady-state (2s delay) but NOT during startup (10s delay).
	if got := s.CheckVRRPPosture(now.Add(3 * time.Second)); got != vrrpPostureOK {
		t.Errorf("check at 3s during startup should return OK (10s delay), got %d", got)
	}

	// At 5s: still within startup delay.
	if got := s.CheckVRRPPosture(now.Add(5 * time.Second)); got != vrrpPostureOK {
		t.Errorf("check at 5s during startup should return OK, got %d", got)
	}

	// At 11s: past startup delay → corrective action.
	if got := s.CheckVRRPPosture(now.Add(11 * time.Second)); got != vrrpPostureNeedsMaster {
		t.Errorf("check at 11s during startup should return NeedsMaster, got %d", got)
	}
}

func TestRGStateMachine_CheckVRRPPosture_SteadyStateResign(t *testing.T) {
	s := newRGStateMachine()
	s.startedAt = time.Now().Add(-time.Minute)
	now := time.Now()

	// Cluster Secondary but VRRP MASTER → mismatch.
	s.SetCluster(false)
	s.SetVRRP("reth0", true)

	// Start timer.
	s.CheckVRRPPosture(now)

	// At 3s: past 2s steady-state delay → needs resign.
	if got := s.CheckVRRPPosture(now.Add(3 * time.Second)); got != vrrpPostureNeedsResign {
		t.Errorf("check at 3s should return NeedsResign (steady-state 2s delay), got %d", got)
	}
}

func TestRGStateMachine_CheckVRRPPosture_MismatchResetSteadyState(t *testing.T) {
	s := newRGStateMachine()
	s.startedAt = time.Now().Add(-time.Minute)
	now := time.Now()

	// Create mismatch: cluster Primary, VRRP BACKUP.
	s.SetCluster(true)
	s.SetVRRP("reth0", false)

	// Start mismatch timer.
	s.CheckVRRPPosture(now)

	// VRRP becomes MASTER at 1s → mismatch clears.
	s.SetVRRP("reth0", true)
	if got := s.CheckVRRPPosture(now.Add(1 * time.Second)); got != vrrpPostureOK {
		t.Errorf("should return OK after mismatch cleared, got %d", got)
	}

	// Mismatch again at 2s — timer should have been reset.
	s.SetVRRP("reth0", false)
	s.CheckVRRPPosture(now.Add(2 * time.Second)) // start timer

	// At 3s: only 1s since new mismatch — should NOT trigger (2s delay).
	if got := s.CheckVRRPPosture(now.Add(3 * time.Second)); got != vrrpPostureOK {
		t.Errorf("should return OK — only 1s since new mismatch, got %d", got)
	}

	// At 5s: 3s since new mismatch — past 2s delay.
	if got := s.CheckVRRPPosture(now.Add(5 * time.Second)); got != vrrpPostureNeedsMaster {
		t.Errorf("should return NeedsMaster after 3s from timer reset, got %d", got)
	}
}

// --- Strict VIP ownership tests (#104) ---

func TestStrictVIPOwnershipActivation(t *testing.T) {
	// In strict mode, rg_active is derived from VRRP master state ONLY.
	// Cluster Primary alone does NOT activate.
	s := newRGStateMachine()
	s.SetStrictVIPOwnership(true)

	// VRRP MASTER alone → active (same as default mode).
	tr := s.SetVRRP("reth0", true)
	if !tr.Changed || !tr.Active {
		t.Errorf("strict: VRRP MASTER should activate, Changed=%v Active=%v", tr.Changed, tr.Active)
	}

	// VRRP BACKUP → inactive.
	tr = s.SetVRRP("reth0", false)
	if !tr.Changed || tr.Active {
		t.Errorf("strict: VRRP BACKUP should deactivate, Changed=%v Active=%v", tr.Changed, tr.Active)
	}

	// Cluster Primary alone → NOT active in strict mode.
	tr = s.SetCluster(true)
	if tr.Active {
		t.Error("strict: cluster Primary alone should NOT activate")
	}
	if s.IsActive() {
		t.Error("strict: should remain inactive with only cluster Primary")
	}

	// VRRP MASTER with cluster Primary → active.
	tr = s.SetVRRP("reth0", true)
	if !tr.Changed || !tr.Active {
		t.Error("strict: VRRP MASTER should activate even with cluster Primary")
	}
}

func TestStrictVIPOwnershipClusterPrimaryNoVRRP(t *testing.T) {
	// Cluster = Primary, VRRP = BACKUP → NOT active in strict mode.
	// This is the key difference from default mode.
	s := newRGStateMachine()
	s.SetStrictVIPOwnership(true)

	s.SetCluster(true)
	s.SetVRRP("reth0", false)

	if s.IsActive() {
		t.Error("strict: cluster=Primary + VRRP=BACKUP should NOT be active")
	}
}

func TestStrictVIPOwnershipSecondaryVRRPMaster(t *testing.T) {
	// Cluster = Secondary, VRRP = MASTER → active in strict mode.
	// VRRP is sole authority — cluster state is irrelevant for activation.
	s := newRGStateMachine()
	s.SetStrictVIPOwnership(true)

	s.SetCluster(false)
	tr := s.SetVRRP("reth0", true)
	if !tr.Active {
		t.Error("strict: cluster=Secondary + VRRP=MASTER should be active")
	}
	if !s.IsActive() {
		t.Error("strict: should be active — VRRP MASTER is sole authority")
	}
}

func TestDefaultModeUnchanged(t *testing.T) {
	// Default mode: rg_active = clusterPri || anyVrrpMaster.
	// Cluster Primary alone activates (existing behavior).
	s := newRGStateMachine()
	// strictVIPOwnership defaults to false.

	tr := s.SetCluster(true)
	if !tr.Changed || !tr.Active {
		t.Error("default: cluster Primary alone should activate")
	}
	if !s.IsActive() {
		t.Error("default: should be active with cluster Primary")
	}

	// VRRP BACKUP doesn't deactivate (cluster still Primary).
	tr = s.SetVRRP("reth0", false)
	if tr.Changed {
		t.Error("default: VRRP BACKUP should not change when cluster is Primary")
	}
	if !s.IsActive() {
		t.Error("default: should still be active via cluster Primary")
	}
}

func TestStrictVIPOwnershipReconcile(t *testing.T) {
	// Reconcile should respect strict mode.
	s := newRGStateMachine()
	s.SetStrictVIPOwnership(true)

	// Set up: cluster Primary, VRRP MASTER → active.
	s.SetCluster(true)
	s.SetVRRP("reth0", true)
	if !s.IsActive() {
		t.Fatal("should be active")
	}

	// Reconcile with cluster=Primary, VRRP=BACKUP → inactive in strict mode.
	tr := s.Reconcile(true, map[string]bool{"reth0": false})
	if !tr.Changed || tr.Active {
		t.Error("strict reconcile: cluster=Primary + VRRP=BACKUP should deactivate")
	}

	// Reconcile with cluster=Secondary, VRRP=MASTER → active in strict mode.
	tr = s.Reconcile(false, map[string]bool{"reth0": true})
	if !tr.Changed || !tr.Active {
		t.Error("strict reconcile: cluster=Secondary + VRRP=MASTER should activate")
	}
}

func TestStrictVIPOwnershipDualInactiveWindowPrevention(t *testing.T) {
	// In strict mode, there's no dual-active window because cluster Primary
	// alone cannot activate. The only active state is VRRP MASTER.
	s := newRGStateMachine()
	s.SetStrictVIPOwnership(true)

	// Start as cluster Primary + VRRP MASTER.
	s.SetCluster(true)
	s.SetVRRP("reth0", true)
	if !s.IsActive() {
		t.Fatal("should be active initially")
	}

	// Cluster goes Secondary (failover) — VRRP still MASTER → stays active.
	tr := s.SetCluster(false)
	if tr.Changed {
		t.Error("strict: cluster Secondary should not change when VRRP is still MASTER")
	}
	if !s.IsActive() {
		t.Error("strict: should remain active — VRRP is MASTER")
	}

	// VRRP goes BACKUP → deactivate.
	tr = s.SetVRRP("reth0", false)
	if !tr.Changed || tr.Active {
		t.Error("strict: should deactivate when VRRP goes BACKUP")
	}
}

func TestStrictVIPOwnershipToggle(t *testing.T) {
	// Toggling strict mode and verifying behavior changes.
	s := newRGStateMachine()

	// Default mode: cluster Primary alone activates.
	s.SetCluster(true)
	if !s.IsActive() {
		t.Fatal("default: should be active with cluster Primary")
	}

	// Enable strict mode — cluster Primary alone no longer sufficient.
	s.SetStrictVIPOwnership(true)
	// Need to trigger a reconcile to recompute.
	tr := s.SetCluster(true) // same value, but triggers reconcile.
	if tr.Active {
		t.Error("strict: should be inactive — no VRRP MASTER")
	}

	// Verify IsStrictVIPOwnership getter.
	if !s.IsStrictVIPOwnership() {
		t.Error("IsStrictVIPOwnership should return true")
	}
}
