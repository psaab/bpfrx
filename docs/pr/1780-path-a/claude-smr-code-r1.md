# Claude SMR hostile code review — PR #1781 r1 (`803638c91`)

**Verdict: MERGE-NEEDS-MINOR**

Domain SMR (HA neighbor maintenance / dataplane) + concurrency + Go API
layering review. One must-fix behavior-preservation delta; the rest of the
change holds up under hostile inspection.

## Finding 1 (MINOR, must-fix) — `maintainClusterNeighborReadiness` lost its config gate

The plan's contract is strict: *"DO NOT change WHAT is warmed/cleaned … only
HOW the loop is supervised."*

Old `runPeriodicNeighborResolution`:
```go
// immediate pass
if cfg := d.store.ActiveConfig(); cfg != nil {
    d.resolveNeighbors(cfg)
    d.maintainClusterNeighborReadiness()   // <-- inside cfg != nil
}
d.cleanFailedNeighbors()
// 15s tick
if cfg := d.store.ActiveConfig(); cfg != nil {
    d.resolveNeighbors(cfg)
    d.forceProbeNeighbors(cfg)
    d.maintainClusterNeighborReadiness()   // <-- inside cfg != nil
}
```

New code calls `d.maintainClusterNeighborReadiness()` **unconditionally** on
both the immediate pass (daemon_neighbor.go:424) and the 15s tick (:444).
`maintainClusterNeighborReadiness` self-gates on `d.cluster == nil`
(:455) but **not** on config, so the new code can run it when
`ActiveConfig() == nil`.

Practical blast radius is near-zero (`d.cluster != nil` implies a config was
applied, so the `cluster!=nil && cfg==nil` window is essentially empty, and
`warmNeighborCache` over an empty session table is a near-no-op). But it is a
WHAT-change the plan forbids, and the fix is one guard. **Restore the cfg gate
on both call sites.**

## Finding 2 (NOTE, no change) — `maintain` is called inline, not guarded

AGY check D will raise this: `maintainClusterNeighborReadiness` is the one
periodic action NOT wrapped in `runGuardedNeighborPhase`, so in principle a
hang inside it would still freeze the loop. Verified it cannot: maintain's
only pre-spawn work is the `d.cluster == nil` check and a `CompareAndSwap` on
`neighborWarmupInFlight`; the actual heavy work (`warmNeighborCache`, the
session-table walk + per-IP UDP probes) already runs in maintain's own
goroutine guarded by `neighborWarmupInFlight` (:462-471). maintain returns in
O(1) non-blocking work, so leaving it inline cannot freeze the for-select
loop. No change needed; documented so the reviewer convergence is explicit.

## Axes verified clean

- **Concurrency (the big one).** Phases were serialized inline before; they now
  run concurrently in guarded goroutines. Verified `resolveNeighbors` /
  `resolveNeighborsInner` / `forceProbeNeighbors` / `cleanFailedNeighbors`
  write **no** shared mutable daemon state (grep for `d.field =` / `.Lock` /
  shared-map mutation: empty). They touch the **kernel** neighbor table via
  netlink (`NeighList`/`NeighDel`) — kernel-serialized — and spawn
  fire-and-forget ICMP/NS probe goroutines. No Go-level data race introduced by
  the concurrency. (Bonus: `resolveNeighborsInner`'s inline
  `time.Sleep(500ms)` no longer blocks the loop — it runs in the goroutine.)
- **Guard correctness.** `runGuardedNeighborPhase` CAS(false→true) gate;
  `defer{ lastSuccess.Store(now); inFlight.Store(false) }`. No path leaves
  `inFlight` stuck true except an infinitely-hung `fn()` — which is the
  intended watchdog signal (age climbs). `defer` stores "success" on panic too,
  but an unrecovered goroutine panic crashes the process, so the stale gauge
  value is moot.
- **Metric wiring.** `xpf_daemon_neighbor_periodic_last_success_age_seconds`
  declared in `Describe()` (metrics.go), emitted in `collectSystemMetrics` only
  when `neighborPhaseAgeFn != nil` (nil-safe), and **registered in the #1726
  whole-collector descriptor-coverage canary** — so a future drop fails the
  test. Label cardinality bounded to 4 phases. Follows the existing
  `xpf_daemon_*` injection pattern (api below daemon → `api.Config` func field).
- **`NeighborPeriodicPhaseAges`.** `age()` returns `now - startTime` when
  `lastNanos == 0`, so a never-run phase flags rather than reading 0.
  `startTime` is set in the Daemon. No nil-deref.
- **Test quality.** `neighbor_periodic_guard_test.go` exercises the actual
  no-block property (spawns the guarded call, asserts `callReturned` before a
  2s timeout while the phase body is still blocked), the skip-while-in-flight +
  self-heal-relaunch, and the gauge advance. Race-clean (`go test -race`),
  waits are deadline-polled not fixed-sleep so non-flaky.

## Required action
Fix Finding 1 (restore cfg gate on both `maintain` call sites), re-run
`go test -race ./pkg/daemon -run guard` + the api coverage canary, fold into
one r1-fixes commit alongside any Codex/AGY findings.
