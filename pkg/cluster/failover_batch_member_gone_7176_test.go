package cluster

import (
	"strings"
	"testing"
)

// #7176 (C179-065). ManualFailoverBatch had two silent-skip paths in its commit
// half and returned nil for both. They are NOT the same defect and this change
// deliberately treats them differently:
//
//   - MEMBER REMOVED from config during the unlocked pre-hook window: the
//     singular ManualFailover returns "redundancy group %d not found" for
//     exactly this condition; the batch silently skipped it. No contract backs
//     the batch's side, so it now reports — the two paths agree.
//   - MEMBER SUPERSEDED by a concurrent ResetFailover: BOTH paths skip and
//     return nil, and that is #5246 working as designed (the reset wins). It is
//     pinned by name in failover_races_5245_5246_test.go. Reporting success for
//     a partially-applied BATCH is a real operator hazard, but fixing it needs
//     an API change and is tracked by #8000 — not a silent reversal here.
//
// Both tests below exist so a later reader cannot mistake the second for an
// oversight and "fix" it.

// TestManualFailoverBatch_MissingMemberReports_7176 is the fix. Reverting the
// pre-scan to the old `if rg == nil { continue }` makes this RED.
func TestManualFailoverBatch_MissingMemberReports_7176(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	))
	drainEvents(m, 4)

	// A pre-hook that removes RG1 from config while the batch is parked in its
	// unlocked window — the exact race the batch's `rg == nil` arm exists for.
	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	var once bool
	m.SetPreManualFailoverHook(func(int) error {
		if !once {
			once = true
			close(hookStarted)
			<-hookRelease
		}
		return nil
	})

	errCh := make(chan error, 1)
	go func() { errCh <- m.ManualFailoverBatch([]int{0, 1}) }()
	<-hookStarted

	// RG1 disappears from config during the unlocked window.
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200})))
	close(hookRelease)

	err := <-errCh
	if err == nil {
		t.Fatal("ManualFailoverBatch returned success for a batch whose member was " +
			"removed during the pre-hook window — the operator is told the whole batch " +
			"took when part of it was never attempted (#7176 C179-065)")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v; want the singular path's \"not found\" wording so the two "+
			"siblings report the same condition the same way", err)
	}

	// ATOMICITY: no member may be left half-applied. The pre-scan runs before
	// any mutation, under the same lock as the writes, so RG0 must be untouched.
	for _, st := range m.GroupStates() {
		if st.GroupID == 0 && st.ManualFailover {
			t.Error("RG0 was mutated even though the batch failed — a rejected batch " +
				"must leave every member untouched, or the operator's retry starts from " +
				"a state neither they nor the code expects")
		}
	}
}

// TestManualFailoverBatch_AllPresentSucceeds_7176 is the paired control. Without
// it, a batch that refused everything would satisfy the cell above.
func TestManualFailoverBatch_AllPresentSucceeds_7176(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	))
	drainEvents(m, 4)

	if err := m.ManualFailoverBatch([]int{0, 1}); err != nil {
		t.Fatalf("ManualFailoverBatch on a healthy pair = %v, want nil", err)
	}
	moved := 0
	for _, st := range m.GroupStates() {
		if st.ManualFailover {
			moved++
		}
	}
	if moved != 2 {
		t.Errorf("%d of 2 members moved; the pre-scan must not block a healthy batch", moved)
	}
}

// TestManualFailoverBatch_SupersededStillReturnsNil_7176 pins the DELIBERATE
// asymmetry, so the next reader sees it is a decision rather than the other half
// of a half-done fix. See #8000 for the operator hazard this leaves open.
func TestManualFailoverBatch_SupersededStillReturnsNil_7176(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	))
	drainEvents(m, 4)

	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	var once bool
	m.SetPreManualFailoverHook(func(int) error {
		if !once {
			once = true
			close(hookStarted)
			<-hookRelease
		}
		return nil
	})

	errCh := make(chan error, 1)
	go func() { errCh <- m.ManualFailoverBatch([]int{0, 1}) }()
	<-hookStarted
	// Supersede RG1 — its generation bumps, the batch must skip it and, per
	// #5246, still report success.
	if err := m.ResetFailover(1); err != nil {
		t.Fatalf("ResetFailover: %v", err)
	}
	close(hookRelease)

	if err := <-errCh; err != nil {
		t.Fatalf("ManualFailoverBatch = %v; a member superseded by ResetFailover must "+
			"still return nil — that is #5246 working as designed and the singular path "+
			"does the same. If you are changing this deliberately, do it on #8000 and "+
			"update failover_races_5245_5246_test.go with it", err)
	}
}
