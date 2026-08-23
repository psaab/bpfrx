package daemon

import (
	"context"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestFenceDebtSurvivesAnInFlightApply6799 is the #6799 fail-on-revert test.
//
// The cluster fence (daemon_ha_sync.go, "fence: disabling all RGs") force-writes
// rg_active=false OUTSIDE the state machine's transition path and then calls
// InvalidateApplied() to re-arm the desired-vs-applied retry. #6530 added that
// re-arm for one reason, stated in its own comment: without it "a fenced-
// then-recovered primary would stay dark forever".
//
// The reconcile loop captured a transition, dropped the lock, ran SetRGActive
// off-lock (an IPC to the Rust helper — genuinely slow), and then recorded the
// result with an UNGUARDED MarkApplied. A fence landing inside that window armed
// the debt and the completing apply erased it: applied is set to the value the
// apply wrote, which now equals the desired value, so applyPending is cleared.
//
// The erasure is NOT temporary, which is why this is worse than the issue title
// says. reconcileLocked only SETS applyPending when applied != active, and after
// the erasure they agree — so nothing re-arms it, reconcileRGState's
// `tr.Changed || s.NeedsApply()` never fires again, and forwarding stays wherever
// the fence left it.
//
// The epoch cannot detect this and that is the load-bearing measurement:
// InvalidateApplied deliberately does not bump the epoch, so an epoch-only guard
// accepts the record. The invalidation counter is what makes it answerable.
//
// FAIL-ON-REVERT: dropping the invalidateSeq check from RecordApplied makes the
// record succeed and NeedsApply() go false.
func TestFenceDebtSurvivesAnInFlightApply6799(t *testing.T) {
	s := newRGStateMachine()

	// This node owns the RG: desired=true. The reconcile pass captures tr and
	// then drops the lock to perform the dataplane write.
	tr := s.SetCluster(true)
	if !tr.Active {
		t.Fatalf("premise: cluster primary must want the RG active, tr=%+v", tr)
	}

	// While SetRGActive(true) is in flight, the fence writes rg_active=false
	// and re-arms the retry debt.
	s.InvalidateApplied()
	if !s.NeedsApply() {
		t.Fatal("premise: InvalidateApplied must arm the retry debt")
	}

	// The in-flight apply now completes successfully and tries to record it.
	if s.RecordApplied(tr, tr.Active) {
		t.Error("an apply that was ALREADY IN FLIGHT when another writer re-armed the retry debt " +
			"must NOT be recorded: its success describes a world that no longer exists, and " +
			"recording it erases the debt (#6799)")
	}

	if !s.NeedsApply() {
		t.Fatal("the retry debt was ERASED by a completing in-flight apply. reconcileLocked only " +
			"sets applyPending when applied != active, so once cleared with the two in agreement " +
			"nothing re-arms it — the RG never re-drives and forwarding stays wherever the fence " +
			"left it, which is exactly the failure #6530 was written to prevent (#6799)")
	}
}

// TestEpochAloneCannotDetectTheFenceRace6799 pins WHY the fix is keyed on the
// invalidation counter rather than on the epoch, so a later simplification back
// to an epoch-only guard cannot look harmless.
//
// InvalidateApplied deliberately does not bump the epoch — its own comment
// explains that an epoch bump would not help, because the desired-value fallback
// would accept the record anyway. This asserts the premise that reasoning rests
// on: after a fence, the epoch is UNCHANGED and the desired value is UNCHANGED,
// so every epoch-or-desired test still passes. Only the invalidation counter
// moved.
//
// FAIL-ON-REVERT: making InvalidateApplied bump the epoch reds the epoch
// assertion — and would still not fix the defect, which is the point.
func TestEpochAloneCannotDetectTheFenceRace6799(t *testing.T) {
	s := newRGStateMachine()
	tr := s.SetCluster(true)

	beforeActive, beforeEpoch := s.CurrentDesired()
	s.InvalidateApplied()
	afterActive, afterEpoch := s.CurrentDesired()

	if afterEpoch != beforeEpoch {
		t.Errorf("premise broken: InvalidateApplied moved the epoch (%d -> %d). The #6799 guard is "+
			"keyed on the invalidation counter precisely because the epoch does NOT move here",
			beforeEpoch, afterEpoch)
	}
	if afterActive != beforeActive || afterActive != tr.Active {
		t.Errorf("premise broken: InvalidateApplied changed the DESIRED value (%v -> %v, tr wanted "+
			"%v). The fallback that accepts a record when the desired value still matches would "+
			"then not apply, and the race would be detectable without the counter",
			beforeActive, afterActive, tr.Active)
	}
	// Both epoch and desired are unchanged, so the pre-#6799 guards accept.
	if s.epoch != tr.Epoch {
		t.Fatalf("premise: epoch must still equal the transition's, %d vs %d", s.epoch, tr.Epoch)
	}
}

// TestRecordAppliedAcceptsAnUncontestedApply6799 is the tightening control.
//
// Without it, a "fix" that refuses every record satisfies the two cells above
// while permanently pinning applyPending true — every reconcile pass would
// re-drive SetRGActive forever and no RG would ever be reported converged, which
// also holds setLocalFailoverCommitReady low and blocks peer failover.
func TestRecordAppliedAcceptsAnUncontestedApply6799(t *testing.T) {
	s := newRGStateMachine()
	tr := s.SetCluster(true)

	if !s.RecordApplied(tr, tr.Active) {
		t.Fatal("an apply that nothing contested must be recorded; refusing every record pins the " +
			"retry armed forever and blocks the failover-readiness gate")
	}
	if s.NeedsApply() {
		t.Error("a recorded, uncontested apply must clear the retry debt")
	}
}

// TestRecordAppliedAcceptsAStaleEpochWhenDesiredStillMatches6799 is the second
// tightening control, and it guards the OTHER direction of over-reach.
//
// reconcileLocked bumps the epoch on EVERY 2s pass, so an epoch mismatch is
// routine rather than exceptional. A guard that refused on epoch alone would
// reject nearly every reconcile-loop apply — the retry would never clear, and
// the loop would re-drive SetRGActive on every tick forever. What matters is
// whether the value written is still the value wanted.
//
// FAIL-ON-REVERT: tightening the guard to `s.epoch != tr.Epoch -> refuse` reds
// this.
func TestRecordAppliedAcceptsAStaleEpochWhenDesiredStillMatches6799(t *testing.T) {
	s := newRGStateMachine()
	tr := s.SetCluster(true)

	// A routine reconcile pass bumps the epoch without changing the desired
	// value — exactly what the 2s loop does on a steady cluster.
	s.Reconcile(true, nil)
	if s.epoch == tr.Epoch {
		t.Fatal("premise: a reconcile pass must bump the epoch")
	}
	cur, _ := s.CurrentDesired()
	if cur != tr.Active {
		t.Fatalf("premise: the desired value must be unchanged, %v vs %v", cur, tr.Active)
	}

	if !s.RecordApplied(tr, tr.Active) {
		t.Error("a stale EPOCH with an unchanged desired value must still be recorded: the epoch " +
			"advances on every 2s pass, so refusing on it alone would reject nearly every apply " +
			"and pin the retry armed forever (#6799)")
	}
}

// TestRecordAppliedRefusesWhenDesiredMovedAway6799 covers the remaining branch:
// the epoch moved AND the desired value is no longer what was written. This is
// the original epoch-staleness the issue title names, and it must still refuse.
//
// One fixture per branch: without this row the `s.active != active` half of the
// guard is mutation-invisible, since the cells above only exercise the case
// where the desired value still matches.
func TestRecordAppliedRefusesWhenDesiredMovedAway6799(t *testing.T) {
	s := newRGStateMachine()
	tr := s.SetCluster(true) // wrote true

	// The cluster hands the RG away while the apply is in flight.
	s.SetCluster(false)
	cur, _ := s.CurrentDesired()
	if cur {
		t.Fatal("premise: the RG must no longer be wanted active")
	}

	if s.RecordApplied(tr, tr.Active) {
		t.Error("recording an apply of `true` when the machine now wants `false` claims a " +
			"convergence that is wrong in the CURRENT world; it must be refused so the next " +
			"pass re-drives the deactivation (#6799)")
	}
	if !s.NeedsApply() {
		t.Error("the retry must stay armed after a refused record")
	}
}

// midApplyFenceHA is a recorder whose SetRGActive fires a hook WHILE the write
// is in flight, so a test can land a concurrent fence inside the exact window
// the reconcile loop leaves open — between capturing the transition and
// recording the result. Deterministic: no goroutines, no sleeps.
type midApplyFenceHA struct {
	mu         sync.Mutex
	writes     []rgActiveWrite
	duringOnce func()
}

func (h *midApplyFenceHA) SetRGActive(_ context.Context, rgID int, active bool) error {
	h.mu.Lock()
	h.writes = append(h.writes, rgActiveWrite{rgID: rgID, active: active})
	fire := h.duringOnce
	h.duringOnce = nil
	h.mu.Unlock()
	if fire != nil {
		fire()
	}
	return nil
}

func (h *midApplyFenceHA) SetHAWatchdog(_ context.Context, _ int, _ uint64) error { return nil }
func (h *midApplyFenceHA) SetFabricForwarding(_ context.Context, _ dataplane.FabricID, _ dataplane.FabricFwdInfo) error {
	return nil
}
func (h *midApplyFenceHA) SyncFabricState(_ context.Context) error { return nil }

func (h *midApplyFenceHA) countOf(w rgActiveWrite) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, got := range h.writes {
		if got == w {
			n++
		}
	}
	return n
}

func (h *midApplyFenceHA) take() []rgActiveWrite {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]rgActiveWrite(nil), h.writes...)
	h.writes = nil
	return out
}

type midApplyFenceDP struct {
	*dataplane.Manager
	ha *midApplyFenceHA
}

func (r *midApplyFenceDP) HA() dataplane.HAController      { return r.ha }
func (r *midApplyFenceDP) Mode() dpuserspace.DataplaneMode { return dpuserspace.ModeUserspaceCompat }

// TestReconcilePassDoesNotEraseAFenceThatLandedMidApply6799 is the WIRING cell,
// and it is the one that matters. The rgStateMachine cells above bind what
// RecordApplied decides; they stay GREEN if reconcileRGState keeps calling the
// unguarded MarkApplied — which is exactly what it did, and is the whole defect.
// This drives the real reconcile path end to end.
//
// It differs from #6530's TestFenceRearmsReconcileRetry in the one way that
// matters: that test fences AFTER a pass completes, which is sequential and
// safe. Here the fence lands INSIDE the pass's off-lock SetRGActive — the window
// the reconcile loop opens by capturing a transition, dropping the lock, and
// recording a cached value when the write returns. In production that window is
// an IPC round-trip to the Rust helper.
//
// FAIL-ON-REVERT: restoring `s.MarkApplied(true)` in the activation arm erases
// the debt the fence just armed, NeedsApply goes false, and pass 2 never
// re-drives — the RG stays dark with nothing left to re-arm it.
func TestReconcilePassDoesNotEraseAFenceThatLandedMidApply6799(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-6799",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	if !cm.IsLocalPrimary(1) {
		t.Fatal("fixture: node 0 must be primary for RG1, or there is no activation to contest")
	}

	rec := &midApplyFenceHA{}
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cm,
		store:    store,
		vrrpMgr:  vrrp.NewManager(),
	}
	d.setDataplane(&midApplyFenceDP{Manager: dataplane.New(), ha: rec})

	// The fence lands while the FIRST rg_active write is in flight: it writes
	// rg_active=false out of band and re-arms the retry debt, exactly as
	// fenceAllRedundancyGroups does (#6530).
	rec.duringOnce = func() {
		d.getOrCreateRGState(1).InvalidateApplied()
	}

	d.reconcileRGState()

	if got := rec.countOf(rgActiveWrite{rgID: 1, active: true}); got == 0 {
		t.Fatalf("fixture: the reconcile pass never activated RG1 (writes=%v); the test would be "+
			"vacuous", rec.take())
	}
	rec.take()

	s := d.getOrCreateRGState(1)
	if !s.NeedsApply() {
		t.Fatal("the completing apply ERASED the retry debt a fence armed while it was in flight. " +
			"reconcileLocked only sets applyPending when applied != active, so once cleared with " +
			"the two in agreement nothing re-arms it: the RG never re-drives and forwarding stays " +
			"where the fence left it — #6530's failure, reopened (#6799)")
	}

	// The property that matters operationally: the NEXT pass re-drives.
	d.reconcileRGState()
	if got := rec.countOf(rgActiveWrite{rgID: 1, active: true}); got == 0 {
		t.Errorf("the reconcile pass after a mid-apply fence must RE-DRIVE SetRGActive(1, true); "+
			"writes=%v", rec.take())
	}
}

// TestReconcilePassStillConvergesWithoutAFence6799 is the wiring-level
// tightening control. Without it, a change that made the reconcile arm never
// record convergence would satisfy the cell above — and would leave every RG
// permanently retrying, re-driving SetRGActive on every 2s tick forever.
func TestReconcilePassStillConvergesWithoutAFence6799(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-6799",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)

	rec := &midApplyFenceHA{} // no duringOnce hook: nothing contests the apply
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cm,
		store:    store,
		vrrpMgr:  vrrp.NewManager(),
	}
	d.setDataplane(&midApplyFenceDP{Manager: dataplane.New(), ha: rec})

	d.reconcileRGState()
	if got := rec.countOf(rgActiveWrite{rgID: 1, active: true}); got == 0 {
		t.Fatalf("fixture: RG1 was never activated (writes=%v)", rec.take())
	}
	if s := d.getOrCreateRGState(1); s.NeedsApply() {
		t.Error("an UNCONTESTED reconcile apply must record convergence; leaving the retry armed " +
			"makes every 2s tick re-drive SetRGActive forever and holds the failover-readiness " +
			"gate low (#6799)")
	}
}
