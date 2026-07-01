# pkg/scheduler

Time-window scheduler for Junos `schedulers` blocks. Evaluates active
state every 60 s and notifies a callback when any scheduler's
active/inactive state changes. Used to gate firewall filters,
forwarding-class rewrites, and other config that should engage only
during specific windows.

## Entry points

- `Scheduler` — `scheduler.go`.
- `New(schedulers map[string]*config.SchedulerConfig, updateFn func(map[string]bool) error) *Scheduler` —
  `scheduler.go`. The `updateFn` callback fires on state change **and**
  while a prior republish is still pending (self-heal, see below), not
  every tick.
- `NewPrimed(..., now)` — constructor for daemon apply paths that need the
  initial active-state map without firing the callback while an external
  apply semaphore is already held.
- `Run(ctx context.Context)` — `scheduler.go`.
- `IsActive(name string) bool` — `scheduler.go`.
- `ActiveState() map[string]bool` — `scheduler.go`. Snapshot of every
  scheduler's active flag.
- `Update(schedulers map[string]*config.SchedulerConfig)` —
  `scheduler.go`.
- `RepublishPending() bool` / `RepublishFailureStatus() (pending bool,
  failures uint64, since time.Time)` — `scheduler.go`. Expose the #3780
  self-heal state for tests and metrics.

## Republish self-heal (#3780)

`updateFn` returns an `error`. A window transition republishes
enforcement (the daemon rebuilds and publishes the userspace policy
snapshot with the new `inactive` bits); if that republish **fails**, the
transition has NOT converged — a scheduled permit whose window just
closed would keep forwarding (fail-open), or a scheduled block would never
engage. A non-nil `updateFn` result latches an internal `republishPending`
flag, and the NEXT evaluation tick re-fires `updateFn` with the current
active state **even when the state did not change**, retrying on the
scheduler's own throttle-paced 60 s sweep until it converges. A successful
republish clears the flag. This replaces the previous fire-and-forget
behavior where a swallowed republish failure left stale enforcement live
until the next unrelated state change (which can be hours away).

The daemon side surfaces the failure as the
`xpf_scheduler_republish_failed` gauge (1 while a republish is pending)
plus `xpf_scheduler_republish_stale_seconds` (age of the current failure
streak), and logs an `ERROR` on the transition into failure. See
`pkg/daemon/daemon_scheduler.go` (`publishPolicyScheduleState`,
`recordSchedulerRepublishResult`).

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## Gotchas

- Evaluation interval is fixed at 60 s. Don't try to drive sub-minute
  precision through this package. This 60 s tick is also the retry cadence
  for a failed republish (#3780).
- `updateFn` receives the **full** active-state map, not just the
  changed entries. Callers compute their own diff if they care. It MUST
  return a non-nil error only when a live republish did not converge (so
  the retry latches); return nil for shutdown / nothing-to-publish so the
  self-heal does not spin.
- Daemon callers must publish scheduler changes while holding the daemon
  apply semaphore. Runtime scheduler callbacks take that semaphore before
  touching dataplane state so commits and time-window flips cannot publish
  hybrid policy snapshots.
- The daemon reconciler keeps an existing scheduler instance when the
  committed scheduler config is byte-identical. This preserves the
  monotonic/wall-clock recovery state and avoids resetting timers on
  no-op commits. Runtime publishes use the daemon context when acquiring
  the apply semaphore, so shutdown cancels a blocked scheduler publish
  instead of leaving a goroutine parked behind a long apply.
- The scheduler uses wall-clock time only in the control plane to evaluate
  Junos time windows. Packet workers must consume published active/inactive
  booleans from the userspace snapshot and must not evaluate scheduler time in
  the hot path.
- Wall-clock discontinuities are fail-closed. Each evaluation compares
  wall elapsed time with Go's monotonic elapsed time from the previous
  evaluation; backward wall steps or drift beyond the tolerance publish
  all schedulers inactive for that evaluation instead of extending an
  allow window with a stale wall-clock assumption.
