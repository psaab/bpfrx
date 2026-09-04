package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestScheduler_RepublishFailureRetriesUntilConverged is the #3780
// self-heal contract. A scheduler window transition republishes
// enforcement via updateFn. When that republish FAILS the transition has
// not converged — a scheduled permit whose window just closed would keep
// forwarding (fail-open). The scheduler must latch the failure and
// re-fire updateFn on the NEXT tick even though the active-state map did
// not change, retrying until it succeeds.
//
// RED-on-revert: reverting the `|| s.republishPending` re-fire (or
// recordRepublishResultLocked) makes the retry never happen — the second
// evaluate would not call updateFn (calls stays at 1) and the stale
// permit would persist silently.
func TestScheduler_RepublishFailureRetriesUntilConverged(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}

	var (
		calls     int
		lastState map[string]bool
		failing   = true
	)
	updateFn := func(_ context.Context, state map[string]bool) error {
		calls++
		lastState = state
		if failing {
			return errors.New("republish failed")
		}
		return nil
	}

	// Prime inside the window (active). NewPrimed must not fire updateFn.
	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, initial := NewPrimed(schedCfg, updateFn, now)
	if !initial["workhours"] {
		t.Fatalf("workhours should start active inside window, got %v", initial)
	}
	if calls != 0 {
		t.Fatalf("NewPrimed must not fire updateFn, got %d calls", calls)
	}
	if s.RepublishPending() {
		t.Fatal("fresh scheduler must not report a pending republish")
	}

	// Window closes at 17:00 → state flips to inactive. The first
	// evaluate fires updateFn, which FAILS. The transition must stay
	// pending for retry.
	closeT := time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC)
	s.evaluate(context.Background(), closeT, true)
	if calls != 1 {
		t.Fatalf("window close should fire updateFn once, got %d", calls)
	}
	if lastState["workhours"] {
		t.Fatal("workhours should be inactive after the window closed")
	}
	if !s.RepublishPending() {
		t.Fatal("a failed republish must leave the transition pending for retry (fail-open otherwise)")
	}
	pending, failures, since := s.RepublishFailureStatus()
	if !pending || failures != 1 || since.IsZero() {
		t.Fatalf("failure status = (pending=%v failures=%d since=%v), want (true, 1, non-zero)", pending, failures, since)
	}

	// Next tick: the active state did NOT change (still outside window),
	// but because the prior republish failed, evaluate MUST re-fire
	// updateFn. This is the self-heal that revert kills.
	nextT := closeT.Add(1 * time.Minute)
	s.evaluate(context.Background(), nextT, true)
	if calls != 2 {
		t.Fatalf("pending republish must be retried on the next tick even without a state change, got %d calls", calls)
	}
	if !s.RepublishPending() {
		t.Fatal("a still-failing retry must stay pending")
	}

	// The transient failure clears; the retry converges and clears the
	// pending flag.
	failing = false
	s.evaluate(context.Background(), nextT.Add(1*time.Minute), true)
	if calls != 3 {
		t.Fatalf("pending republish must fire again, got %d calls", calls)
	}
	if s.RepublishPending() {
		t.Fatal("a successful republish must clear the pending flag")
	}

	// Converged steady state: no change, not pending → no further fires.
	s.evaluate(context.Background(), nextT.Add(2*time.Minute), true)
	if calls != 3 {
		t.Fatalf("converged steady state must not re-fire updateFn, got %d calls", calls)
	}
}

// TestScheduler_SuccessfulRepublishNeverLatchesPending guards the happy
// path: a state change whose republish succeeds must not leave the
// scheduler in a pending/retry state (which would churn an identical
// snapshot every tick forever).
func TestScheduler_SuccessfulRepublishNeverLatchesPending(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}
	var calls int
	updateFn := func(context.Context, map[string]bool) error {
		calls++
		return nil
	}
	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, _ := NewPrimed(schedCfg, updateFn, now)

	// Close the window: one successful republish, no pending.
	s.evaluate(context.Background(), time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC), true)
	if calls != 1 {
		t.Fatalf("window close should fire once, got %d", calls)
	}
	if s.RepublishPending() {
		t.Fatal("a successful republish must not latch pending")
	}
	// A subsequent no-change tick must not re-fire.
	s.evaluate(context.Background(), time.Date(2026, 2, 12, 17, 31, 0, 0, time.UTC), true)
	if calls != 1 {
		t.Fatalf("no-change tick after a successful republish must not re-fire, got %d", calls)
	}
}
