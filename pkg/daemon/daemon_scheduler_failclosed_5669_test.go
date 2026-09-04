package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
)

// TestSchedulerRepublishFailClosedGaugeReadsSSOTLatch_5669 pins the #6137 review
// fold (finding 2): the daemon's xpf_scheduler_republish_fail_closed gauge
// (SchedulerRepublishFailClosed) reads the scheduler's OWN latch
// (scheduler.RepublishFailClosed) — the single source of truth that also drives
// the force-inactive/one-time-alarm decision — and NOT the daemon-side
// schedulerRepublishFirstFailNanos timer that previously recomputed the age
// independently (a second, continuous-time clock that could read 1 up to one
// 60 s tick before the scheduler actually latched).
//
// RED-on-revert: the pre-fold accessor returned
// (schedulerRepublishFailing && now-firstFail >= RepublishFailClosedAge). This
// test drives the daemon timer and the scheduler latch into DISAGREEMENT — the
// daemon timer is hot (failing since well past the bound) while the scheduler
// latch is NOT set — and asserts the gauge follows the latch (false). The
// retired timer-based implementation reads true here and fails the test.
func TestSchedulerRepublishFailClosedGaugeReadsSSOTLatch_5669(t *testing.T) {
	// Nil-safe: a daemon with no scheduler installed is not fail-closed.
	d := &Daemon{}
	if d.SchedulerRepublishFailClosed() {
		t.Fatal("a daemon with no scheduler must not report fail-closed")
	}

	// Install a healthy scheduler whose latch is NOT fail-closed.
	sched, _ := scheduler.NewPrimed(map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}, func(context.Context, map[string]bool) error { return nil }, time.Now())
	d.scheduler.Store(sched)
	if sched.RepublishFailClosed() {
		t.Fatal("precondition: a freshly-primed healthy scheduler must not be fail-closed")
	}
	if d.SchedulerRepublishFailClosed() {
		t.Fatal("gauge must be 0 while the scheduler latch is clear")
	}

	// Force the OLD daemon-side timer state to "past the bound": failing since
	// well over RepublishFailClosedAge ago. The retired implementation computed
	// fail-closed from exactly these two fields and would return true now.
	d.schedulerRepublishFailing.Store(true)
	d.schedulerRepublishFirstFailNanos.Store(
		time.Now().Add(-2 * scheduler.RepublishFailClosedAge).UnixNano())

	// SSOT wiring: the gauge must follow the scheduler's fail-closed latch
	// (still false), NOT the daemon timer (now hot). This is the finding-2
	// regression guard — it fails on the retired age-recompute accessor.
	if d.SchedulerRepublishFailClosed() {
		t.Fatal("gauge must read the scheduler's fail-closed latch (false here), not the daemon-side age timer")
	}

	// Sanity: the retired daemon-side timer state IS hot, proving the
	// disagreement above is real and the gauge deliberately ignored it.
	if !d.SchedulerRepublishFailed() {
		t.Fatal("precondition: the daemon-side republish-failing timer must be hot for this disagreement test")
	}
	if got := d.SchedulerRepublishStaleSeconds(); got < scheduler.RepublishFailClosedAge.Seconds() {
		t.Fatalf("precondition: stale-seconds = %v, want >= bound %v (timer past the bound)",
			got, scheduler.RepublishFailClosedAge.Seconds())
	}

	// A nil scheduler with the timer still hot is also not fail-closed (the
	// gauge is scheduler-latch driven, so tearing down the scheduler drops the
	// gauge regardless of the stale timer atomics).
	d.scheduler.Store(nil)
	if d.SchedulerRepublishFailClosed() {
		t.Fatal("gauge must be 0 once the scheduler is torn down, even with a stale daemon timer")
	}
}
