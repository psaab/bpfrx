package scheduler

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// pdt is a fixed UTC-7 zone standing in for a non-UTC operator timezone. The
// scheduler date-range boundary must land on LOCAL midnight in this zone, not
// UTC midnight (which is 07:00 local — a 7h shift).
var pdt = time.FixedZone("PDT", -7*3600)

// TestWithinDateRange_StartDateIsLocalMidnight is the #3988 RED-on-revert
// guard. In a UTC-7 zone a scheduler whose calendar range opens on 2026-07-01
// must NOT be active at 23:30 LOCAL on 2026-06-30 — the range has not started
// yet. With the fix (ParseInLocation using now.Location()) the start boundary
// is 2026-07-01 00:00 local, so 2026-06-30 23:30 local is before it and the
// scheduler is inactive.
//
// On revert to time.Parse (UTC default) the boundary becomes 2026-07-01 00:00
// UTC == 2026-06-30 17:00 local, so 23:30 local (00:30 UTC on 2026-07-01) is
// AFTER it — the scheduler activates ~6.5h early and this test goes RED.
//
// now is built in the fixed zone and the parse derives its zone from
// now.Location(), so the assertion is deterministic and does not depend on the
// host's TZ (which is UTC in CI).
func TestWithinDateRange_StartDateIsLocalMidnight(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "maint-window",
		StartDate: "2026-07-01",
		// Date-range-only scheduler: active for the whole local calendar range.
	}

	// 2026-06-30 23:30 local (still June 30 in the operator's wall-clock).
	nowBefore := time.Date(2026, 6, 30, 23, 30, 0, 0, pdt)
	if isWithinWindow(nowBefore, sched) {
		t.Errorf("start-date 2026-07-01 must NOT be active at %s (local June 30, before the range); "+
			"parsed as UTC the boundary shifts %+d and it fires early (#3988)", nowBefore, -7)
	}

	// 2026-07-01 00:30 local — just inside the range on the start date.
	nowInside := time.Date(2026, 7, 1, 0, 30, 0, 0, pdt)
	if !isWithinWindow(nowInside, sched) {
		t.Errorf("start-date 2026-07-01 must be active at %s (local July 1, inside the range)", nowInside)
	}
}

// TestWithinDateRange_StopDateInclusiveLocal confirms the inclusive stop-date
// boundary is also interpreted in local time. A range ending 2026-07-01 must
// still be active at 23:30 LOCAL on 2026-07-01 (the whole stop date is
// inclusive) and inactive at 00:30 LOCAL on 2026-07-02.
//
// On revert the UTC stop boundary (2026-07-02 00:00 UTC == 2026-07-01 17:00
// local) closes the window ~7h early on the stop date, so the first assertion
// goes RED.
func TestWithinDateRange_StopDateInclusiveLocal(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:     "maint-window",
		StopDate: "2026-07-01",
	}

	// 2026-07-01 23:30 local — the stop date is inclusive, still active.
	nowLastEvening := time.Date(2026, 7, 1, 23, 30, 0, 0, pdt)
	if !isWithinWindow(nowLastEvening, sched) {
		t.Errorf("stop-date 2026-07-01 (inclusive) must be active at %s (local July 1 evening); "+
			"parsed as UTC the boundary closes the window early (#3988)", nowLastEvening)
	}

	// 2026-07-02 00:30 local — the day after the stop date, inactive.
	nowNextDay := time.Date(2026, 7, 2, 0, 30, 0, 0, pdt)
	if isWithinWindow(nowNextDay, sched) {
		t.Errorf("stop-date 2026-07-01 must NOT be active at %s (local July 2, after the range)", nowNextDay)
	}
}

// TestWithinDateRange_UTCOffsetZeroUnchanged pins the "don't regress a
// UTC-offset-0 host" requirement: when now is in UTC, local == UTC and the
// boundary behaves exactly as before the fix.
func TestWithinDateRange_UTCOffsetZeroUnchanged(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "campaign",
		StartDate: "2026-03-01",
		StopDate:  "2026-03-31",
	}
	if isWithinWindow(time.Date(2026, 2, 28, 23, 30, 0, 0, time.UTC), sched) {
		t.Error("Feb 28 UTC must be before the March range (offset-0 unchanged)")
	}
	if !isWithinWindow(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), sched) {
		t.Error("March 1 00:00 UTC must be inside the range (offset-0 unchanged)")
	}
	if !isWithinWindow(time.Date(2026, 3, 31, 23, 59, 0, 0, time.UTC), sched) {
		t.Error("March 31 23:59 UTC must be inside the inclusive range (offset-0 unchanged)")
	}
	if isWithinWindow(time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC), sched) {
		t.Error("April 1 12:00 UTC must be after the inclusive range (offset-0 unchanged)")
	}
}

// TestWithinDateRange_DailyWindowZoneSafe documents that the daily
// start-time/stop-time window (which #3988 audited) is already interpreted in
// local wall-clock: 09:00-17:00 is active at 12:00 local and inactive at 20:00
// local regardless of the UTC offset, because both sides compare wall-clock
// components (see timeOfDay / parseTimeOfDay). This stays green before and
// after the fix — it is the audit evidence that no instant is formed there.
func TestWithinDateRange_DailyWindowZoneSafe(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "business-hours",
		StartTime: "09:00:00",
		StopTime:  "17:00:00",
	}
	if !isWithinWindow(time.Date(2026, 7, 1, 12, 0, 0, 0, pdt), sched) {
		t.Error("12:00 local must be inside the 09:00-17:00 daily window")
	}
	if isWithinWindow(time.Date(2026, 7, 1, 20, 0, 0, 0, pdt), sched) {
		t.Error("20:00 local must be outside the 09:00-17:00 daily window")
	}
}
