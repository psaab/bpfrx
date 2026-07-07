package config

import (
	"fmt"
	"strings"
	"time"
)

// ValidateTimeOfDay accepts a scheduler time-of-day in HH:MM:SS 24-hour
// form (the exact layout the runtime evaluator parses,
// pkg/scheduler.parseTimeOfDay). Rejecting a malformed time at commit is the
// fail-closed half of #3849: an unparseable start-time/stop-time must never
// reach the compiler and silently zero the window (which the old evaluator
// then treated as always-active).
func ValidateTimeOfDay(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a time of day, e.g. 09:00:00)")
	}
	if _, err := time.Parse("15:04:05", trimmed); err != nil {
		return fmt.Errorf("invalid time of day %q (expected 24-hour HH:MM:SS, e.g. 09:00:00 or 17:30:00)", raw)
	}
	return nil
}

// ValidateDate accepts a scheduler calendar date in YYYY-MM-DD form (the
// layout the runtime evaluator parses in withinDateRange).
func ValidateDate(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a date, e.g. 2026-03-01)")
	}
	if _, err := time.Parse("2006-01-02", trimmed); err != nil {
		return fmt.Errorf("invalid date %q (expected YYYY-MM-DD, e.g. 2026-03-01)", raw)
	}
	return nil
}
