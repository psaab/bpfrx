package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Scheduler periodically evaluates time windows for named schedulers
// and notifies a callback when any scheduler's active state changes.
type Scheduler struct {
	mu         sync.RWMutex
	schedulers map[string]*config.SchedulerConfig
	active     map[string]bool
	updateFn   func(activeState map[string]bool)
}

// New creates a Scheduler with the given scheduler configs and update callback.
// updateFn is called whenever any scheduler's active state changes, receiving
// the current active state of all schedulers.
func New(schedulers map[string]*config.SchedulerConfig, updateFn func(activeState map[string]bool)) *Scheduler {
	s := &Scheduler{
		schedulers: schedulers,
		active:     make(map[string]bool),
		updateFn:   updateFn,
	}
	// Compute initial state.
	s.evaluate(time.Now())
	return s
}

// Run starts the evaluation loop, checking every 60 seconds. It blocks until
// the context is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	slog.Info("scheduler: starting evaluation loop")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler: stopping evaluation loop")
			return
		case t := <-ticker.C:
			s.evaluate(t)
		}
	}
}

// IsActive reports whether the named scheduler is currently active.
func (s *Scheduler) IsActive(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active[name]
}

// ActiveState returns a copy of the current active state for all schedulers.
func (s *Scheduler) ActiveState() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]bool, len(s.active))
	for k, v := range s.active {
		out[k] = v
	}
	return out
}

// Update replaces the scheduler configurations and re-evaluates immediately.
func (s *Scheduler) Update(schedulers map[string]*config.SchedulerConfig) {
	s.mu.Lock()
	s.schedulers = schedulers
	s.mu.Unlock()
	s.evaluate(time.Now())
}

// evaluate checks each scheduler against the current time and fires the
// callback if any state changed.
func (s *Scheduler) evaluate(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	changed := false
	newActive := make(map[string]bool, len(s.schedulers))

	for name, sched := range s.schedulers {
		cur := isWithinWindow(now, sched)
		newActive[name] = cur
		if prev, ok := s.active[name]; !ok || prev != cur {
			slog.Info("scheduler: state changed", "name", name, "active", cur)
			changed = true
		}
	}

	// Detect removed schedulers.
	for name := range s.active {
		if _, ok := newActive[name]; !ok {
			slog.Info("scheduler: removed", "name", name)
			changed = true
		}
	}

	s.active = newActive

	if changed && s.updateFn != nil {
		// Pass a copy so the callback cannot mutate internal state.
		cp := make(map[string]bool, len(newActive))
		for k, v := range newActive {
			cp[k] = v
		}
		s.updateFn(cp)
	}
}

// isWithinWindow determines whether now falls within the time window defined
// by sched. It returns true (active) if no times are configured.
func isWithinWindow(now time.Time, sched *config.SchedulerConfig) bool {
	if sched.StartTime == "" && sched.StopTime == "" {
		return true
	}

	// Check date range if configured.
	if sched.StartDate != "" {
		startDate, err := time.Parse("2006-01-02", sched.StartDate)
		if err != nil {
			slog.Warn("scheduler: invalid start date", "name", sched.Name, "date", sched.StartDate, "err", err)
			return false
		}
		if now.Before(startDate) {
			return false
		}
	}
	if sched.StopDate != "" {
		stopDate, err := time.Parse("2006-01-02", sched.StopDate)
		if err != nil {
			slog.Warn("scheduler: invalid stop date", "name", sched.Name, "date", sched.StopDate, "err", err)
			return false
		}
		// StopDate is inclusive: the scheduler is active through the entire stop date.
		if now.After(stopDate.AddDate(0, 0, 1)) {
			return false
		}
	}

	// If only date range is set (no times), active for the entire date range.
	if sched.StartTime == "" && sched.StopTime == "" {
		return true
	}

	// Parse start and stop times of day.
	startTOD, err := parseTimeOfDay(sched.StartTime)
	if err != nil {
		slog.Warn("scheduler: invalid start time", "name", sched.Name, "time", sched.StartTime, "err", err)
		return false
	}
	stopTOD, err := parseTimeOfDay(sched.StopTime)
	if err != nil {
		slog.Warn("scheduler: invalid stop time", "name", sched.Name, "time", sched.StopTime, "err", err)
		return false
	}

	nowTOD := timeOfDay(now)

	if !startTOD.before(stopTOD) {
		// Wraparound: e.g. 22:00:00 - 06:00:00 means overnight.
		// Active if now >= start OR now < stop.
		return !nowTOD.before(startTOD) || nowTOD.before(stopTOD)
	}

	// Normal range: active if now >= start AND now < stop.
	return !nowTOD.before(startTOD) && nowTOD.before(stopTOD)
}

// tod represents a time of day as hours, minutes, seconds for clean comparison.
type tod struct {
	h, m, s int
}

func (t tod) before(other tod) bool {
	if t.h != other.h {
		return t.h < other.h
	}
	if t.m != other.m {
		return t.m < other.m
	}
	return t.s < other.s
}

func parseTimeOfDay(s string) (tod, error) {
	t, err := time.Parse("15:04:05", s)
	if err != nil {
		return tod{}, err
	}
	return tod{h: t.Hour(), m: t.Minute(), s: t.Second()}, nil
}

func timeOfDay(t time.Time) tod {
	return tod{h: t.Hour(), m: t.Minute(), s: t.Second()}
}
