# #2114 — NAT pool-alarm monitor races `d.dp = nil` in bootstrap-exit

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

The #2079 NAT pool-utilization-alarm monitor (PR #2109) starts a
long-running background goroutine (`Monitor.run()` → `evaluate()` →
`sample()`) on a 10s timer. Its sampler closure (`natPoolAlarmSampler`,
`pkg/daemon/daemon_natpoolalarm.go`) reads the daemon's `d.dp`
(`dataplane.RuntimeDataPlane`) interface field with **no
synchronization**.

In **bootstrap mode** the dataplane backend object is *constructed*
(`d.dp != nil`) but not *armed*. The monitor start block in
`pkg/daemon/daemon_run.go` (~line 880, inside the `if d.dp != nil {`
background-services block) is gated only on `d.dp != nil` — NOT on
`!d.inBootstrap()`. So in bootstrap mode the monitor goroutine is
launched and its sampler runs every 10s.

On the **first confirmed (non-empty) commit**, the apply path
(`daemon_apply.go`) calls `exitBootstrapMode()` then
`runBootstrapExitStartup(cfg)` (`daemon_run.go:1657`), which on a
dataplane arm **failure** writes `d.dp = nil`
(`daemon_run.go:1701`) — under `d.applySem`, on the apply goroutine.

The monitor's sampler goroutine and the apply goroutine both touch
`d.dp` (a non-atomic interface value) without a common lock. A 10s
sampler tick that lands in the bootstrap-exit window = concurrent
read + write of the same non-atomic interface field = a data race per
the Go memory model. `go test -race` / a production race detector
flags it; a torn interface read can panic or mis-resolve a type
assertion.

## Honest scope / value framing

This is a correctness/safety fix for a freshly merged regression, not
a perf change. The win is: **eliminate a Go-memory-model data race on
the unhappy bootstrap path** (fresh foreign-host install whose first
confirmed commit fails to arm the dataplane — the exact #1922/#2079
target scenario). Severity is Medium per the issue: it requires
bootstrap mode + an arm failure, but a torn interface read is UB and
the race detector blocks `-race` builds/CI.

If reviewers conclude the fix is wrong-shaped or the race is not real,
PLAN-KILL is an acceptable verdict. (It is not: the issue's analysis is
confirmed against current origin/master — see "Confirmed against
source" below.)

## Confirmed against source (origin/master @ b30a78e8)

- `pkg/daemon/daemon.go:70` — `dp dataplane.RuntimeDataPlane` is a
  plain field; no mutex, no `atomic.Pointer`.
- `pkg/daemon/daemon_run.go:880-881` — monitor `New(...).Start()`
  inside `if d.dp != nil {`, NOT gated on `!d.inBootstrap()`.
- `pkg/daemon/daemon_run.go:642` — the dataplane `Start()` IS gated:
  `if d.inBootstrap() { ...suppressed... } else { if d.dp != nil { d.dp.Start(ctx) ... } }`. The monitor start should mirror this.
- `pkg/daemon/daemon_run.go:1657` `runBootstrapExitStartup` — arms the
  dataplane on bootstrap exit; on failure `d.dp = nil`
  (`daemon_run.go:1701`), under `applySem` (apply caller holds it).
- `pkg/daemon/daemon_natpoolalarm.go:18-22` — sampler reads
  `d.dp` then type-asserts `d.dp.(interface{ Manager() *Manager })`.
- `pkg/natpoolalarm/natpoolalarm.go` — `Start()` spawns `go m.run()`;
  `run()` calls `m.evaluate()` immediately (so the first racy read
  happens on the new goroutine right after `Start()`), then ticks
  every `tick` (default 10s).
- `pkg/daemon/bootstrap.go:280` — `inBootstrap()` reads
  `d.bootstrapMode atomic.Bool` (race-free gate).
- `pkg/daemon/daemon_run.go:1512` — monitor `Stop()` at shutdown only.

## Chosen design — Option A (gate the start; start on bootstrap exit)

**Why A, not B (synchronize all `d.dp` access):** there is NO existing
mutex/accessor for `d.dp` anywhere in the daemon. Every reader
(`daemon_forwarding_status.go` `IsLoaded`/`IsUserspaceDataplane`,
`daemon_ha_sync.go`, `daemon_ha_fabric.go`, `daemon_neighbor_listener.go`,
`daemon_apply.go`, ~40 sites) reads `d.dp` unsynchronized. Introducing a
mutex/`atomic.Pointer` accessor would touch all of them and is a much
larger, riskier change that the issue itself labels the "durable"
(option 2) fix for the *whole* field — out of scope for a targeted
regression fix. The codebase's actual invariant is: **`d.dp` is written
only on the boot/apply goroutine under `applySem` (or during the
single-threaded boot sequence before background goroutines start);
continuously-running readers must not be launched while a write can
still occur.** The bug is that #2109 violated that invariant by
launching a continuous reader during bootstrap, where the
bootstrap-exit write still happens. Option A restores the invariant
and exactly mirrors the dataplane-`Start()` gate already at line 642.

### Edit 1 — `daemon_run.go` ~880: gate the boot-time start

Wrap the monitor `New/Start` in `if !d.inBootstrap()`:

```go
// #2114: do NOT start the NAT pool-alarm monitor while in bootstrap
// mode. In bootstrap the dataplane object is constructed (d.dp != nil)
// but not armed, and the bootstrap-exit path may write d.dp = nil on
// an arm failure. The monitor's sampler reads d.dp unsynchronized, so
// launching it here would race that write. It is started instead at
// the end of runBootstrapExitStartup once the dataplane is armed
// (mirroring the dataplane Start() gate above). On a normal
// (non-bootstrap) boot this branch runs as before.
if !d.inBootstrap() {
    d.natPoolAlarm = natpoolalarm.New(d.natPoolAlarmSampler(), d.natPoolAlarmEmitter())
    d.natPoolAlarm.Start()
}
```

### Edit 2 — `runBootstrapExitStartup` (~1701): start on successful arm

In the existing arm block, start the monitor in the success branch
(after `d.dp.Start()` succeeds, so `d.dp` is confirmed non-nil; this is
*after* the `d.dp = nil` failure write, so the start is never reached
on the failure path). This runs under `applySem`, so the monitor's
first sampler read cannot overlap a concurrent `d.dp` write:

```go
if d.dp != nil {
    if err := d.dp.Start(d.daemonCtx); err != nil {
        slog.Warn("bootstrap exit: failed to start dataplane, running in config-only mode", "err", err)
        d.dp = nil
    } else {
        if seeder, ok := d.dp.(natSeeder); ok {
            seeder.SeedNATPortCounters()
            seeder.SeedSessionIDCounter(nodeID)
        }
        // #2114: start the NAT pool-alarm monitor now that the
        // dataplane is armed and d.dp is stable. Suppressed at boot in
        // bootstrap mode (see daemon_run.go monitor-start gate). Guard
        // against an unexpected double-start (idempotent: Start() is a
        // no-op once started, but we also only construct once).
        if d.natPoolAlarm == nil {
            d.natPoolAlarm = natpoolalarm.New(d.natPoolAlarmSampler(), d.natPoolAlarmEmitter())
            d.natPoolAlarm.Start()
        }
    }
}
```

Note: `Monitor.Start()` is already idempotent (`started` guard) and
`Stop()` is safe whether or not `Start` ran, so shutdown
(`daemon_run.go:1512` `if d.natPoolAlarm != nil { d.natPoolAlarm.Stop() }`)
remains correct in all three cases (never started, started at boot,
started at bootstrap exit).

## Behavior matrix (must hold after the fix)

| Path | Boot | Bootstrap exit | Monitor running? | Races d.dp write? |
|------|------|----------------|------------------|-------------------|
| Normal boot (not bootstrap, d.dp armed) | start at line 880 | n/a | yes, from boot | no (d.dp not written after boot single-thread) |
| Bootstrap boot → first commit arms OK | suppressed | start in runBootstrapExitStartup success branch | yes, from exit | no (started under applySem after Start succeeds) |
| Bootstrap boot → first commit arm FAILS (d.dp=nil) | suppressed | NOT started (failure branch) | no | no (no monitor goroutine exists) |
| NoDataplane | not reached (`if d.dp != nil` false) | runBootstrapExitStartup returns early | no | n/a |

## Hidden invariants preserved

- **Monitor lifecycle:** still constructed at most once; `Stop()` at
  shutdown still safe (idempotent + safe-on-unstarted). The `d.natPoolAlarm == nil`
  guard in Edit 2 prevents any double-construct if both paths somehow
  ran (they cannot — boot-start is gated on `!inBootstrap()`, exit-start
  only runs from bootstrap exit — but the guard is cheap insurance).
- **Sampler correctness in normal case:** unchanged; the sampler reads
  the same cached `AppliedNATView`. The monitor still surfaces an
  over-threshold pool within the first tick after it starts.
- **Bootstrap-exit ordering:** the monitor start is the LAST step in
  `runBootstrapExitStartup`'s arm block, after NAT seeding, so it never
  changes the takeover sequence (rename → forwarding → arm → seed →
  monitor).
- **applySem discipline:** the bootstrap-exit start runs under the
  caller's `applySem` hold (same as the `d.dp = nil` write site), so
  the construct+launch is serialized w.r.t. any other `d.dp` mutation.
- **HA / cluster (RESOLVED — OQ#1):** the bootstrap-exit transition
  (`exitBootstrapMode` + `runBootstrapExitStartup`) lives at
  `daemon_apply.go:379-380`, inside `applyConfigLocked` — the SINGLE
  reconcile pipeline that BOTH a local confirmed commit AND a cluster
  `SyncApply` route through. The in-source comment is explicit:
  "the FIRST apply of a non-empty config (an interface-claiming
  confirmed commit, or a cluster SyncApply from the primary) leaves
  bootstrap mode and runs ... runBootstrapExitStartup". There is NO
  second bootstrap-exit path. So Edit 2 covers every bootstrap-exit
  case. Option A is complete.
- **Rollback-to-bootstrap (RESOLVED — OQ#3):** `enterBootstrapMode`
  (`bootstrap.go:313`, the `prevCfg==nil` first-commit-timeout
  rollback at `daemon_apply.go:308`) is reached only AFTER
  `runBootstrapExitStartup` already ran (it is the rollback of a failed
  first commit). It does NOT write `d.dp = nil` — it calls
  `d.dp.Teardown()` and KEEPS the object non-nil. So there is no
  `d.dp` nil-write race on this path. If the monitor was started at
  the earlier successful arm, it keeps running and samples the
  torn-down-but-non-nil `d.dp`; the sampler tolerates this
  (AppliedNATView → Available:false → monitor HOLDs). A later
  corrected `runBootstrapExitStartup` re-arm hits the
  `d.natPoolAlarm == nil` guard (non-nil) and does NOT double-start.
  Correct and race-free across rollback→re-arm.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Pure start-gating; normal-boot path byte-identical. Only new behavior: monitor start deferred to bootstrap exit on the bootstrap path. |
| Lifetime / nil-deref | LOW | Monitor Start/Stop already nil-safe + idempotent; guard added. |
| Concurrency correctness | LOW | Removes the race; introduces no new shared state. Start-at-exit runs under applySem. |
| Architectural mismatch | LOW | Mirrors the existing dataplane-Start() bootstrap gate exactly; no new abstraction. |
| Missed start path | **MED** | If a bootstrap-exit code path other than `runBootstrapExitStartup` exists (e.g. cluster SyncApply), the monitor could fail to start there. MUST verify in review. |

## Test plan (this is a DATA RACE — `-race` is the gate)

1. `go build ./...` clean (worktree).
2. **New `-race` regression test** in `pkg/daemon` (preferred — it
   exercises the real daemon fields) OR a focused seam test:
   - Construct a `*Daemon` with a fake `RuntimeDataPlane` set in `d.dp`
     and `bootstrapMode=true`.
   - Start the NAT-alarm monitor via the **real** start path used at
     bootstrap exit (or via a small test seam that calls the same
     sampler against `d.dp`), with a very short tick so the sampler
     fires immediately and repeatedly.
   - Concurrently, from another goroutine, flip `d.dp = nil` (mirroring
     the bootstrap-exit failure write) while the sampler is reading.
   - Run under `go test -race`. **PRE-FIX:** the unsynchronized read
     vs write trips the detector (FAIL). **POST-FIX:** the monitor is
     not started in bootstrap mode (Edit 1) / is started only under the
     serialized exit path, so the test asserts the monitor goroutine is
     NOT racing the bootstrap-mode `d.dp` write → clean under `-race`.
   - NOTE: To get a clean PRE-FIX failure that POST-FIX passes, the test
     must target the *daemon's start gating*, not the raw field (a raw
     unsynchronized read+write will always race regardless of the daemon
     fix). The test will therefore exercise: "with bootstrapMode=true,
     starting the monitor via the boot path does NOT launch a sampler
     goroutine that reads d.dp" — i.e. assert no goroutine is sampling
     d.dp while bootstrap-exit nils it. Final test shape decided in
     Step 5 to guarantee fail-pre / pass-post; if a deterministic
     daemon-level seam is awkward, fall back to a `natpoolalarm`-level
     test that drives `Start()`/sampler vs a concurrent
     dp-transition seam under `-race`.
3. `go test -race ./pkg/daemon/... ./pkg/natpoolalarm/...` clean.
4. `go test ./...` (or at least affected packages) green.
5. **No cluster smoke** — this is control-plane only and changes no
   forwarding path (per task scoping). It DOES touch the bootstrap/HA
   startup sequence, so review must confirm the normal-boot and
   bootstrap-exit monitor-start paths both still fire.

## Out of scope (explicitly)

- Option B (uniform `d.dp` accessor / mutex / `atomic.Pointer`) — the
  durable whole-field fix. Deferred; the pre-existing unsynchronized
  request-driven readers (`IsLoaded`, `IsUserspaceDataplane`) predate
  #2109 and are not this regression. File a follow-up if desired.
- Any change to the alarm evaluation / hysteresis / emit logic.
- Rust / wire / forwarding changes (none).

## Open questions for adversarial review (invite PLAN-KILL)

1. **[RESOLVED] Does every bootstrap-exit path route through
   `runBootstrapExitStartup`?** YES — `exitBootstrapMode` +
   `runBootstrapExitStartup` are called from exactly one site
   (`daemon_apply.go:379-380`, inside `applyConfigLocked`), which is
   the common pipeline for both local confirmed commit and cluster
   SyncApply. No second exit path. Edit 2 is complete.
2. **Is Edit 1's `!d.inBootstrap()` gate sufficient to make the race
   go away pre-fix?** i.e. is the boot-time start the ONLY place the
   monitor goroutine is launched during the bootstrap window? (It is,
   per source — but confirm.)
3. **[RESOLVED] Rollback-to-bootstrap edge case.** `enterBootstrapMode`
   does NOT nil `d.dp` (it Teardown()s and keeps the object), so no
   nil-write race there. The monitor (if started at the prior successful
   arm) keeps running and HOLDs while the dataplane is unavailable; a
   re-arm does not double-start (guard). See "Rollback-to-bootstrap"
   under invariants. Acceptable.
4. **Is the `-race` test genuinely fail-pre / pass-post**, or does it
   merely test an always-racy raw field (which would fail both pre and
   post and prove nothing)? The test must target the daemon's
   start-gating decision, not a hand-rolled unsynchronized read+write.
5. **Should Edit 2 start the monitor even on a cluster (HA) bootstrap
   exit**, or is the monitor cluster-gated elsewhere? (Per #2079 the
   monitor is not cluster-gated; both nodes can raise local alarms.)
6. **Is option A preferable to B given the issue explicitly frames B as
   the "durable" fix?** Argue why the minimal targeted fix is correct
   for a regression and B is a separate, larger refactor.
