package scheduler

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestScheduler_RepublishFailClosedAfterBoundedAge is the #5669 fail-on-revert
// pin. The #3780 self-heal retries a failed republish every tick, but a
// PERSISTENTLY failing republish (a wedged control socket, an incompatible
// helper) leaves the stale window fail-OPEN — a scheduled PERMIT still
// forwarding past its close — for as long as the retry keeps failing, silently.
//
// Once the failure streak exceeds RepublishFailClosedAge the scheduler must
// escalate to fail-closed: emit the one-time alarm AND force every scheduled
// policy to the INACTIVE (deny) disposition in the authoritative + published
// state, refusing to reopen it even when its window legitimately reopens, until
// a republish succeeds again. (This bounds the SILENT fail-open window with a
// loud alarm + authoritative deny; it does not itself stop packets in a
// persistently-wedged dataplane — see the scope note below and the README.)
//
// RED-on-revert: removing the bounded-age latch in
// recordRepublishResultLocked makes RepublishFailClosed() never true — the
// scheduler keeps publishing the stale-window-driven state forever with no
// alarm, and the "must latch past the bound" assertion below fails.
// Target-count: this single test.
func TestScheduler_RepublishFailClosedAfterBoundedAge(t *testing.T) {
	// Capture WARN+ so the one-time fail-closed alarm is observable; the
	// per-name "state changed" logs are INFO and stay suppressed.
	var logBuf bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(oldLogger)

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
			return errors.New("republish failed: wedged control socket")
		}
		return nil
	}

	// Prime inside the window (active). NewPrimed must not fire updateFn.
	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, initial := NewPrimed(schedCfg, updateFn, now)
	if !initial["workhours"] {
		t.Fatalf("workhours should start active inside window, got %v", initial)
	}
	if s.RepublishFailClosed() {
		t.Fatal("a fresh scheduler must not be fail-closed")
	}

	// Window closes at 17:00 → desired flips to inactive. The first evaluate
	// fires updateFn, which FAILS and latches the #3780 pending retry. Not yet
	// fail-closed: a single failure is within the bounded age.
	closeT := time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC)
	s.evaluate(context.Background(), closeT, true)
	if !s.RepublishPending() {
		t.Fatal("a failed republish must latch pending for retry")
	}
	if s.RepublishFailClosed() {
		t.Fatal("a single failure inside the bounded age must NOT be fail-closed (would false-alarm on a transient stall)")
	}

	// Retry every 60 s with the republish still failing. Before the bounded age
	// elapses the scheduler must stay in silent-retry (not fail-closed).
	tick := closeT
	for tick.Sub(closeT) < RepublishFailClosedAge {
		tick = tick.Add(60 * time.Second)
		beforeBound := tick.Sub(closeT) < RepublishFailClosedAge
		s.evaluate(context.Background(), tick, true)
		if beforeBound && s.RepublishFailClosed() {
			t.Fatalf("must not fail-closed before the bounded age (streak=%s, bound=%s)",
				tick.Sub(closeT), RepublishFailClosedAge)
		}
	}

	// The streak has now reached the bounded age: the scheduler MUST have
	// latched fail-closed and emitted exactly one alarm.
	if !s.RepublishFailClosed() {
		t.Fatalf("republish failing for %s (>= bound %s) must latch fail-closed",
			tick.Sub(closeT), RepublishFailClosedAge)
	}
	if got := strings.Count(logBuf.String(), "FAIL-CLOSED"); got != 1 {
		t.Fatalf("fail-closed must emit exactly one alarm, got %d\nlog:\n%s", got, logBuf.String())
	}

	// The permit's window LEGITIMATELY reopens the next day (09:00-17:00),
	// desired active=true — but enforcement is still wedged, so fail-closed
	// must build an INACTIVE (deny) snapshot and report the permit inactive on
	// the authoritative state, refusing to reopen it, until a republish
	// succeeds again.
	//
	// Scope note (honest): this asserts the CONTROL-PLANE disposition — the
	// published snapshot and the authoritative ActiveState/IsActive both say
	// DENY. It does NOT prove the packet path stops forwarding: that same
	// snapshot is pushed through the same failing updateFn channel that defines
	// the streak, so in a persistently-wedged dataplane it never reaches the
	// helper and the stale permit keeps forwarding until the socket recovers.
	// The value of fail-closed is the loud alarm + authoritative deny +
	// deny-lands-first-on-recovery, not packet-path enforcement in a wedged
	// dataplane (see README "Bounded-age fail-closed").
	reopen := time.Date(2026, 2, 13, 10, 0, 0, 0, time.UTC)
	s.evaluate(context.Background(), reopen, true)
	if lastState["workhours"] {
		t.Fatal("fail-closed must build the permit INACTIVE (deny) in the published snapshot even when its window reopens")
	}
	if s.IsActive("workhours") {
		t.Fatal("fail-closed authoritative state must report the permit inactive (deny)")
	}

	// Republish recovers. The next successful publish clears fail-closed; the
	// scheduler then republishes the TRUE window state so the legitimately-open
	// permit reopens (no permanent false-deny).
	failing = false
	s.evaluate(context.Background(), reopen.Add(60*time.Second), true)
	if s.RepublishFailClosed() {
		t.Fatal("a successful republish must clear fail-closed")
	}
	if s.RepublishPending() {
		t.Fatal("a successful republish must clear the pending retry")
	}
	s.evaluate(context.Background(), reopen.Add(120*time.Second), true)
	if !lastState["workhours"] {
		t.Fatal("after recovery the reopened window must republish the permit ACTIVE (no permanent false-deny)")
	}
	if !s.IsActive("workhours") {
		t.Fatal("after recovery the reopened window must report active")
	}
}

// Note on gauge coverage (#6137 finding 3): the value the daemon's
// xpf_scheduler_republish_fail_closed gauge reads is the scheduler's own
// RepublishFailClosed() latch (the SSOT the daemon accessor delegates to after
// finding 2). Its 0→1 transition at the bound and 1→0 clear on recovery are
// already pinned by TestScheduler_RepublishFailClosedAfterBoundedAge above (it
// asserts RepublishFailClosed() directly). Deliberately NOT re-asserting
// "reads 1 at the bound" in a second test here keeps the latch-block
// fail-on-revert target-count at exactly one. The genuinely-new gauge coverage
// — that the DAEMON accessor reads this latch (SSOT) rather than a second
// daemon-side age timer — lives in pkg/daemon's
// TestSchedulerRepublishFailClosedGaugeReadsSSOTLatch_5669, which does not
// depend on the latch reaching true and so stays green on the revert.

// TestScheduler_WithinBoundTransientNeverFailsClosed is the control: a normal
// successful window transition and a transient failure that recovers INSIDE the
// bounded age must never trip fail-closed — no false-deny of a legitimate
// window, no false alarm. This test does NOT depend on the #5669 latch, so it
// stays green whether or not the fix is present (keeps the fail-on-revert
// target-count at 1).
func TestScheduler_WithinBoundTransientNeverFailsClosed(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}
	var (
		calls     int
		lastState map[string]bool
		failing   = false
	)
	updateFn := func(_ context.Context, state map[string]bool) error {
		calls++
		lastState = state
		if failing {
			return errors.New("transient republish failure")
		}
		return nil
	}

	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, _ := NewPrimed(schedCfg, updateFn, now)

	// A clean window close: one successful republish, never fail-closed.
	closeT := time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC)
	s.evaluate(context.Background(), closeT, true)
	if s.RepublishFailClosed() {
		t.Fatal("a successful window transition must never be fail-closed")
	}
	if lastState["workhours"] {
		t.Fatal("a closed window must publish the permit inactive")
	}

	// A transient failure that recovers well inside the bounded age must not
	// fail-closed. Reopen the window (desired active) so a spurious fail-closed
	// would be observable as a false-deny.
	reopen := time.Date(2026, 2, 13, 9, 30, 0, 0, time.UTC)
	failing = true
	s.evaluate(context.Background(), reopen, true) // republish fails once, latches pending
	if !s.RepublishPending() {
		t.Fatal("a failed republish should latch pending")
	}
	// A couple more failures, still comfortably within the bound.
	failing = true
	s.evaluate(context.Background(), reopen.Add(60*time.Second), true)
	if s.RepublishFailClosed() {
		t.Fatalf("a transient failure inside the bounded age (%s) must not fail-closed", RepublishFailClosedAge)
	}
	// Recover before the bound.
	failing = false
	s.evaluate(context.Background(), reopen.Add(120*time.Second), true)
	if s.RepublishFailClosed() || s.RepublishPending() {
		t.Fatal("recovery inside the bound must leave neither pending nor fail-closed")
	}
	if !lastState["workhours"] {
		t.Fatal("the legitimately-open window must publish ACTIVE after a within-bound transient recovers (no false-deny)")
	}
	if !s.IsActive("workhours") {
		t.Fatal("the legitimately-open window must be active after recovery")
	}
}
