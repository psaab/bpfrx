package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestUpdatePolicyScheduleStateLockedPropagatesError proves the daemon
// plumbing carries the dataplane republish error back to the caller
// (#3780). On revert the updater method is void and the daemon has no
// error to act on → a failed scheduler-window republish is silently
// dropped and the stale permit stays live.
func TestUpdatePolicyScheduleStateLockedPropagatesError(t *testing.T) {
	wantErr := errors.New("apply_snapshot failed")
	dp := &runtimeOnlyPolicyUpdaterTestDP{updateErr: wantErr}
	d := &Daemon{dp: dp}

	err := d.updatePolicyScheduleStateLocked(&config.Config{}, map[string]bool{"workhours": false})
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("updatePolicyScheduleStateLocked err = %v, want %v (a swallowed error is the #3780 fail-open)", err, wantErr)
	}
	if dp.updateCalls != 1 {
		t.Fatalf("updater calls = %d, want 1", dp.updateCalls)
	}

	// Success path returns nil.
	dp.updateErr = nil
	if err := d.updatePolicyScheduleStateLocked(&config.Config{}, map[string]bool{"workhours": true}); err != nil {
		t.Fatalf("successful update must return nil, got %v", err)
	}
}

// TestSchedulerRepublishMetricLatchesAndClears verifies the
// observability side of the #3780 self-heal: a failing scheduler
// republish latches xpf_scheduler_republish_failed=1 and a climbing
// stale-age, and both clear on recovery (or scheduler teardown).
//
// RED-on-revert: without recordSchedulerRepublishResult the metric stays
// 0 while a permit is live past its window — the fail-open is invisible.
func TestSchedulerRepublishMetricLatchesAndClears(t *testing.T) {
	d := &Daemon{}

	if d.SchedulerRepublishFailed() {
		t.Fatal("fresh daemon must not report a republish failure")
	}
	if got := d.SchedulerRepublishStaleSeconds(); got != 0 {
		t.Fatalf("stale seconds = %v, want 0 when healthy", got)
	}

	// First failure latches the gauge and records the streak start.
	d.recordSchedulerRepublishResult(errors.New("boom"))
	if !d.SchedulerRepublishFailed() {
		t.Fatal("a failing republish must set xpf_scheduler_republish_failed=1")
	}

	// Backdate the streak start so the stale-age gauge is deterministic.
	d.schedulerRepublishFirstFailNanos.Store(time.Now().Add(-3 * time.Second).UnixNano())
	if got := d.SchedulerRepublishStaleSeconds(); got < 2 {
		t.Fatalf("stale seconds = %v, want >= 2 while failing", got)
	}

	// A repeated failure must NOT reset the streak start (the age must
	// keep climbing to show how long enforcement has been stale).
	first := d.schedulerRepublishFirstFailNanos.Load()
	d.recordSchedulerRepublishResult(errors.New("boom again"))
	if d.schedulerRepublishFirstFailNanos.Load() != first {
		t.Fatal("a repeated failure must not reset the failure-streak start")
	}

	// Recovery clears both.
	d.recordSchedulerRepublishResult(nil)
	if d.SchedulerRepublishFailed() {
		t.Fatal("a successful republish must clear the failure gauge")
	}
	if got := d.SchedulerRepublishStaleSeconds(); got != 0 {
		t.Fatalf("stale seconds = %v, want 0 after recovery", got)
	}

	// Scheduler teardown (config change removing/replacing schedulers)
	// also clears the gauge.
	d.recordSchedulerRepublishResult(errors.New("boom"))
	d.clearSchedulerRepublishFailure()
	if d.SchedulerRepublishFailed() {
		t.Fatal("scheduler teardown must clear the republish-failure gauge")
	}
	if got := d.SchedulerRepublishStaleSeconds(); got != 0 {
		t.Fatalf("stale seconds = %v, want 0 after teardown", got)
	}
}
