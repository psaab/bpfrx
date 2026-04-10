package daemon

import (
	"strings"
	"testing"
	"time"
)

func TestWaitLocalFailoverCommitReadyWaitsForPromotionSettle(t *testing.T) {
	d := &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 200 * time.Millisecond,
		localFailoverCommitDelay:   0,
	}

	done := make(chan error, 1)
	go func() {
		done <- d.waitLocalFailoverCommitReady([]int{0})
	}()

	time.Sleep(20 * time.Millisecond)
	d.setLocalFailoverCommitReady(0, true)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitLocalFailoverCommitReady() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for failover commit settle")
	}
}

func TestWaitLocalFailoverCommitReadyTimesOutWithoutPromotionSettle(t *testing.T) {
	d := &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 30 * time.Millisecond,
		localFailoverCommitDelay:   0,
	}

	err := d.waitLocalFailoverCommitReady([]int{0})
	if err == nil {
		t.Fatal("expected timeout waiting for failover commit settle")
	}
	if !strings.Contains(err.Error(), "timed out waiting for local failover activation settle") {
		t.Fatalf("waitLocalFailoverCommitReady() error = %v", err)
	}
}

func TestRecordRGActiveAppliedIfCurrentOrStableClearsSameDesiredStaleEpoch(t *testing.T) {
	s := newRGStateMachine()
	tr := s.SetCluster(true)
	if !s.NeedsApply() {
		t.Fatal("expected apply to be pending after cluster promotion")
	}

	// Simulate the reconcile loop or another goroutine advancing the epoch
	// without changing the desired active state.
	s.Reconcile(true, nil)

	if !recordRGActiveAppliedIfCurrentOrStable(s, tr, true) {
		t.Fatal("expected same-desired stale transition to be accepted")
	}
	if s.NeedsApply() {
		t.Fatal("expected apply pending to clear after same-desired stale transition")
	}
}

func TestRecordRGActiveAppliedIfCurrentOrStableRejectsChangedDesiredState(t *testing.T) {
	s := newRGStateMachine()
	tr := s.SetCluster(true)
	if !s.NeedsApply() {
		t.Fatal("expected apply to be pending after cluster promotion")
	}

	// Change the desired state before recording the apply result.
	s.SetCluster(false)

	if recordRGActiveAppliedIfCurrentOrStable(s, tr, true) {
		t.Fatal("expected changed desired state to reject stale apply result")
	}
	if !s.NeedsApply() {
		t.Fatal("expected apply pending to remain set after rejected stale apply")
	}
}
