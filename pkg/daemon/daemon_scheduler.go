package daemon

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
)

type policySchedulerActiveStateSetter interface {
	SetPolicySchedulerActiveState(map[string]bool)
}

type policyScheduleStateUpdater interface {
	UpdatePolicyScheduleState(*config.Config, map[string]bool) error
}

// reconcilePolicySchedulerLocked runs under applySem. It makes the scheduler
// lifecycle follow committed config instead of only daemon startup, and returns
// the active-state map that must be used for the same apply transaction.
func (d *Daemon) reconcilePolicySchedulerLocked(cfg *config.Config) map[string]bool {
	return d.reconcilePolicySchedulerLockedAt(cfg, time.Now())
}

func (d *Daemon) reconcilePolicySchedulerLockedAt(cfg *config.Config, now time.Time) map[string]bool {
	hash, hasSchedulers := policySchedulerConfigHash(cfg)
	if hasSchedulers && d.scheduler != nil && hash == d.policySchedulerConfigHash {
		d.startPolicySchedulerLoopLocked()
		return d.scheduler.ActiveState()
	}

	if d.schedulerCancel != nil {
		d.schedulerCancel()
		d.schedulerCancel = nil
	}
	d.scheduler = nil
	// #3780: the scheduler set is being removed or replaced. Clear any
	// stale republish-failure metric from the outgoing scheduler; a new
	// scheduler's initial state is published by the fallible apply path,
	// and a removed scheduler set has nothing left to converge.
	d.clearSchedulerRepublishFailure()
	epoch := d.policySchedulerEpoch.Add(1)

	if !hasSchedulers {
		d.policySchedulerConfigHash = [32]byte{}
		return nil
	}

	sched, activeState := scheduler.NewPrimed(cfg.Schedulers, func(activeState map[string]bool) error {
		return d.publishPolicyScheduleState(epoch, activeState)
	}, now)
	d.scheduler = sched
	d.policySchedulerConfigHash = hash
	d.startPolicySchedulerLoopLocked()
	return activeState
}

func (d *Daemon) policySchedulerActiveStateForApplyLocked(cfg *config.Config, now time.Time) map[string]bool {
	hash, hasSchedulers := policySchedulerConfigHash(cfg)
	if !hasSchedulers {
		return nil
	}
	if d.scheduler != nil && hash == d.policySchedulerConfigHash {
		return d.scheduler.ActiveState()
	}
	_, activeState := scheduler.NewPrimed(cfg.Schedulers, func(map[string]bool) error { return nil }, now)
	return activeState
}

func policySchedulerConfigHash(cfg *config.Config) ([32]byte, bool) {
	if cfg == nil || len(cfg.Schedulers) == 0 {
		return [32]byte{}, false
	}
	h := sha256.New()
	names := make([]string, 0, len(cfg.Schedulers))
	for name := range cfg.Schedulers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writePolicySchedulerHashString(h, name)
		sched := cfg.Schedulers[name]
		if sched == nil {
			writePolicySchedulerHashString(h, "<nil>")
			continue
		}
		writePolicySchedulerHashString(h, sched.Name)
		writePolicySchedulerHashString(h, sched.StartTime)
		writePolicySchedulerHashString(h, sched.StopTime)
		writePolicySchedulerHashString(h, sched.StartDate)
		writePolicySchedulerHashString(h, sched.StopDate)
		if sched.Daily {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, true
}

func writePolicySchedulerHashString(h interface{ Write([]byte) (int, error) }, s string) {
	var lenBuf [8]byte
	for i := 0; i < len(lenBuf); i++ {
		lenBuf[i] = byte(uint64(len(s)) >> (8 * i))
	}
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}

func (d *Daemon) startPolicySchedulerLoopLocked() {
	if d.daemonCtx == nil || d.scheduler == nil || d.schedulerCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(d.daemonCtx)
	d.schedulerCancel = cancel
	go d.scheduler.Run(ctx)
}

// publishPolicyScheduleState is the scheduler's updateFn. It returns a
// non-nil error only when a live scheduler-driven republish did NOT
// converge, which the scheduler uses to retry autonomously on its next
// tick and which recordSchedulerRepublishResult surfaces as the
// xpf_scheduler_republish_failed metric (#3780). Shutdown / torn-down /
// nothing-to-publish cases return nil (no retry, no alarm).
func (d *Daemon) publishPolicyScheduleState(epoch uint64, activeState map[string]bool) error {
	ctx := d.daemonCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		// Daemon context cancelled — the daemon is shutting down and the
		// scheduler loop is stopping too. Nothing to retry.
		slog.Warn("scheduler: failed to acquire apply semaphore", "err", err)
		return nil
	}
	defer d.applySem.Release(1)

	if epoch != d.policySchedulerEpoch.Load() {
		// A reconcile replaced this scheduler instance; the new instance
		// owns republish. Do not latch a retry on the dead one.
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || d.dp == nil {
		return nil
	}
	d.seedPolicySchedulerActiveStateLocked(activeState)
	err := d.updatePolicyScheduleStateLocked(cfg, activeState)
	d.recordSchedulerRepublishResult(err)
	return err
}

func (d *Daemon) seedPolicySchedulerActiveStateLocked(activeState map[string]bool) {
	if d.dp == nil {
		return
	}
	if setter, ok := d.dp.(policySchedulerActiveStateSetter); ok {
		setter.SetPolicySchedulerActiveState(activeState)
	}
}

func (d *Daemon) updatePolicyScheduleStateLocked(cfg *config.Config, activeState map[string]bool) error {
	if d.dp == nil {
		return nil
	}
	// Both in-tree backends satisfy policyScheduleStateUpdater
	// directly: *dataplane.Manager via UpdatePolicyScheduleState in
	// pkg/dataplane/maps_policy.go
	// and *dataplane/userspace.LegacyDataPlaneAdapter via
	// pkg/dataplane/userspace/legacy_dataplane.go:161. The legacyDP()
	// fallback branch was dead code; removed in #1519.
	if updater, ok := d.dp.(policyScheduleStateUpdater); ok {
		return updater.UpdatePolicyScheduleState(cfg, activeState)
	}
	return nil
}

// recordSchedulerRepublishResult latches or clears the scheduler
// republish-failure metric from a republish result (#3780). This is the
// observability side of the scheduler self-heal: while a
// scheduler-driven republish keeps failing, xpf_scheduler_republish_failed
// reads 1 and xpf_scheduler_republish_stale_seconds climbs, so stale
// enforcement (a permit still live past its window, or a block that never
// engaged) is visible to monitoring instead of silent. The transition
// itself is retried by the scheduler on its next tick.
func (d *Daemon) recordSchedulerRepublishResult(err error) {
	if err != nil {
		if d.schedulerRepublishFailing.CompareAndSwap(false, true) {
			d.schedulerRepublishFirstFailNanos.Store(time.Now().UnixNano())
			slog.Error("scheduler: policy schedule republish FAILED; enforcement is stale (a permit may still be live past its window, or a scheduled block never engaged) — retrying on the next scheduler tick until it converges",
				"err", err)
		}
		return
	}
	if d.schedulerRepublishFailing.CompareAndSwap(true, false) {
		d.schedulerRepublishFirstFailNanos.Store(0)
		slog.Info("scheduler: policy schedule republish recovered; enforcement is back in sync with the schedule window")
	}
}

// clearSchedulerRepublishFailure resets the republish-failure metric.
// Called when the scheduler set is torn down or replaced by a reconcile.
func (d *Daemon) clearSchedulerRepublishFailure() {
	if d.schedulerRepublishFailing.Swap(false) {
		d.schedulerRepublishFirstFailNanos.Store(0)
	}
}

// SchedulerRepublishFailed reports whether the most recent
// scheduler-driven policy republish failed and has not yet converged
// (#3780). Lock-free; safe for the metrics collector goroutine.
func (d *Daemon) SchedulerRepublishFailed() bool {
	return d.schedulerRepublishFailing.Load()
}

// SchedulerRepublishStaleSeconds returns how long the current
// scheduler-republish failure streak has gone unconverged, in seconds
// (0 when healthy) (#3780).
func (d *Daemon) SchedulerRepublishStaleSeconds() float64 {
	if !d.schedulerRepublishFailing.Load() {
		return 0
	}
	first := d.schedulerRepublishFirstFailNanos.Load()
	if first == 0 {
		return 0
	}
	age := time.Now().UnixNano() - first
	if age < 0 {
		return 0
	}
	return time.Duration(age).Seconds()
}
