package scheduler

// #3849 runtime evaluation of per-day (monday..sunday) windows and the
// daily/per-day interaction. The compile-side descend is pinned in
// pkg/config; these pin the evaluator honoring what the compiler produced.

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func dayWin(start, stop string) *config.SchedulerDayWindow {
	return &config.SchedulerDayWindow{StartTime: start, StopTime: stop}
}

// 2026-03-02 is a Monday; 2026-03-03 a Tuesday.
var monNoon = time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)
var tueNoon = time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC)

func TestIsWithinWindow_PerDay_MondayOnly(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name: "mon-only",
		Days: map[string]*config.SchedulerDayWindow{
			"monday": dayWin("08:00:00", "17:00:00"),
		},
	}
	if !isWithinWindow(monNoon, sched) {
		t.Error("Monday noon should be active for a monday 08:00-17:00 window")
	}
	// Tuesday has no arm and there is no daily fallback -> closed.
	if isWithinWindow(tueNoon, sched) {
		t.Error("Tuesday should be inactive for a monday-only scheduler (fail closed)")
	}
	// Monday but outside the window.
	monEvening := time.Date(2026, 3, 2, 20, 0, 0, 0, time.UTC)
	if isWithinWindow(monEvening, sched) {
		t.Error("Monday 8pm should be outside the 08:00-17:00 window")
	}
}

func TestIsWithinWindow_PerDay_OverridesDaily(t *testing.T) {
	// Daily window 09:00-17:00, but Monday is a shorter 09:00-12:00.
	sched := &config.SchedulerConfig{
		Name:      "override",
		StartTime: "09:00:00",
		StopTime:  "17:00:00",
		Days: map[string]*config.SchedulerDayWindow{
			"monday": dayWin("09:00:00", "12:00:00"),
		},
	}
	// Monday 14:00 falls in the daily window but OUTSIDE the monday override.
	monAfternoon := time.Date(2026, 3, 2, 14, 0, 0, 0, time.UTC)
	if isWithinWindow(monAfternoon, sched) {
		t.Error("Monday 14:00 should follow the monday override (09-12), not the daily window")
	}
	// Tuesday 14:00 has no override, so the daily window (09-17) applies.
	tueAfternoon := time.Date(2026, 3, 3, 14, 0, 0, 0, time.UTC)
	if !isWithinWindow(tueAfternoon, sched) {
		t.Error("Tuesday 14:00 should follow the daily window (09-17)")
	}
}

func TestIsWithinWindow_PerDay_Exclude(t *testing.T) {
	// Daily all-day, but Monday explicitly excluded.
	sched := &config.SchedulerConfig{
		Name:   "holiday",
		AllDay: true,
		Days: map[string]*config.SchedulerDayWindow{
			"monday": {Exclude: true},
		},
	}
	if isWithinWindow(monNoon, sched) {
		t.Error("Monday must be inactive when explicitly excluded, even with daily all-day")
	}
	if !isWithinWindow(tueNoon, sched) {
		t.Error("Tuesday should follow the daily all-day window")
	}
}

func TestIsWithinWindow_PerDay_AllDay(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name: "mon-allday",
		Days: map[string]*config.SchedulerDayWindow{
			"monday": {AllDay: true},
		},
	}
	if !isWithinWindow(time.Date(2026, 3, 2, 3, 0, 0, 0, time.UTC), sched) {
		t.Error("Monday all-day should be active at 3am")
	}
	if isWithinWindow(tueNoon, sched) {
		t.Error("Tuesday should be inactive (no arm, no daily) for a monday-all-day scheduler")
	}
}

// TestIsWithinWindow_HalfWindowFailsClosed pins that a window missing one
// bound is treated as closed, not always-on.
func TestIsWithinWindow_HalfWindowFailsClosed(t *testing.T) {
	sched := &config.SchedulerConfig{Name: "half", StartTime: "09:00:00"} // no StopTime
	if isWithinWindow(monNoon, sched) {
		t.Error("a half-specified window (start without stop) must fail closed")
	}
}
