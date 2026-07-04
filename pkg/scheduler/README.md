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

## Time-window model (#3849)

A `config.SchedulerConfig` resolves to at most one window per instant:

- **Daily window** — `StartTime`/`StopTime` (the body of a Junos
  `daily { start-time X; stop-time Y; }` block, or the legacy simplified
  shape where `start-time`/`stop-time` are direct children of the
  scheduler). `AllDay` marks the daily window active for the whole day
  (`daily all-day`).
- **Per-day overrides** — `Days["monday".."sunday"]`. A weekday present in
  `Days` overrides the daily window for that weekday; its `Exclude` flag
  forces the day inactive, `AllDay` forces it active. Days without an
  override fall back to the daily window.
- **Date range** — `StartDate`/`StopDate` gate the whole scheduler to a
  calendar range (inclusive of the stop date). A scheduler with only a
  date range (no time-of-day window) is active for the entire range.

`compileSchedulers` (`pkg/config/compiler_system.go`) reads all of these
for both the hierarchical and flat-set AST shapes; the flat-set grammar is
grouped by the `schedulers` entry in `setSchema`
(`pkg/config/schema_schedulers.go`), and the `start-time`/`stop-time` /
`start-date`/`stop-date` value slots are typed so a malformed window is
rejected at commit (`ValidateTimeOfDay` / `ValidateDate`).

**Time zone — system local (#3988).** Scheduler dates and times are Junos
local wall-clock. `withinDateRange` parses `StartDate`/`StopDate` with
`time.ParseInLocation("2006-01-02", …, now.Location())`, so the calendar
boundary lands on **local midnight**; every production caller supplies `now`
from `time.Now()` or the evaluation ticker, both of which carry `time.Local`.
Parsing the date with `time.Parse` (its UTC default) put the boundary on UTC
midnight and shifted the whole range by the local UTC offset — a
`start-date 2026-07-01` range under UTC-7 went active at 17:00 local on
2026-06-30, ~7 h early. The daily `start-time`/`stop-time` window is already
local-safe and unchanged: it never forms an instant, comparing only wall-clock
H/M/S components (`parseTimeOfDay` vs `timeOfDay`, both in `now`'s zone). A
UTC-offset-0 host is unaffected (local == UTC). Deriving the zone from `now`
rather than reading `time.Local` directly keeps the boundary consistent with
the same clock the window is compared against and needs no global test seam.

**Fail-closed invariant (#3849 — security).** `isWithinWindow` treats an
ABSENT window as **inactive**, never always-on. A scheduler that resolves
to no window for a given instant — no daily window, no applicable per-day
override, and no date-only range — returns `false`. Before #3849 the
`daily {}` block was never descended (so `StartTime`/`StopTime` stayed
empty) and an empty window returned `true`, so a policy `scheduler-name`
scoped to business hours actually permitted traffic 24/7 (fail-open). A
window that fails to compile now DENIES, matching the firewall's
fail-closed posture. To express "always active", omit `scheduler-name`
from the policy or use `daily all-day`.

**No-window commit warning (#3860).** The fail-closed flip (#3849/#3858)
is safe but silent: a *degenerate* scheduler that defines no window at all
— an empty `scheduler x {}`, or a bare `daily;` with no start/stop time,
no `all-day`, no per-day arm, and no start/stop date — now resolves to
INACTIVE where the old always-on bug forwarded 24/7. An operator migrating
a config that leaned on that bug would lose enforcement with no signal.
`ValidateConfig` (`pkg/config/compiler_validate_warn.go`,
`schedulerHasEffectiveWindow`) therefore emits a commit-time WARNING naming
each such scheduler: *"scheduler X defines no time window; policies bound
to it will be INACTIVE (use `daily all-day` for always-on)."* A scheduler
carrying any window — a daily/weekday time-of-day arm, `all-day`, or a
start/stop calendar range — does NOT warn. The predicate mirrors the
runtime `schedulerHasTimeWindow || schedulerHasDateRange` split, so the
warning fires exactly when `isWithinWindow` would fail closed for every
instant. It is a warning, not a hard reject, because a degenerate scheduler
is legal Junos and an upgrade must not refuse an existing candidate.

**Overnight windows with per-day overrides.** An overnight window
(e.g. `22:00:00`-`06:00:00`) wraps past midnight, but `effectiveDayWindow`
resolves the applicable window by the *current* weekday. The post-midnight
tail (00:00-06:00 the next calendar day) is therefore evaluated against
that next day's window — a per-day override on the next day (or its absence)
governs the tail, not the prior day's overnight window. This matches (and
does not regress) the single-daily behavior: a uniform `daily 22:00-06:00`
carries across every night because every day resolves to the same window.
Mixing an overnight daily window with divergent per-day arms is the case to
reason about carefully.

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
