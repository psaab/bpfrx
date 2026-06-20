# #2114 — NAT pool-alarm monitor races `d.dp = nil` in bootstrap-exit

**Status:** PLAN-READY (v4) — Codex converged: r1 NEEDS-MAJOR
(rollback→re-arm race) → r2 NEEDS-MAJOR (natPoolAlarm pointer race) →
r3 NEEDS-MINOR (all minor folded in v4: `d.dp==nil` in the helper
guard; test assertions use `.Load()`; part-(c) clears bootstrap before
re-arm). Independent second reviewer (Gemini) is UNAVAILABLE (client
deprecated); parent should dispatch an independent review. v4 makes the
pointer `atomic.Pointer[natpoolalarm.Monitor]` and routes ALL access
through helpers (`maybeStartNATPoolAlarm`, `stopAndDiscardNATPoolAlarm`,
`natPoolAlarms`, shutdown). FIVE edits (0-4).

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

**Second field made shared (v3 — Codex r2):** moving the monitor start
out of the single-threaded boot window means `d.natPoolAlarm` is now
WRITTEN at runtime (started at bootstrap exit, stopped+discarded at
rollback) while gRPC/CLI are already serving. The reader
`natPoolAlarms()` (`daemon_natpoolalarm.go:71`) is wired into the
`show security alarms` render path on both gRPC (`daemon_run.go:1282`,
`NATPoolAlarmsFn`) and CLI (`daemon_run.go:1402`,
`SetNATPoolAlarmsFn`) — request goroutines that race the new
start/discard writes. On origin/master this field is written once at
boot before serving begins, so it is safe today; the fix must NOT
introduce a new pointer race. v3 therefore changes the field to
`atomic.Pointer[natpoolalarm.Monitor]` and routes EVERY access
(start, stop+discard, read, shutdown) through helpers. `sync/atomic`
is already imported in `daemon.go`; the daemon already uses
`atomic.Bool` for `bootstrapMode`, so this matches the local style and
is lock-free.

### Edit 0 — `daemon.go:136`: make the field atomic + add helpers

```go
// natPoolAlarm holds the #2079 monitor. Made atomic in #2114 because the
// monitor is now started/stopped at runtime (bootstrap exit / rollback)
// concurrently with the show-security-alarms render reader.
natPoolAlarm atomic.Pointer[natpoolalarm.Monitor]
```

Helpers (in `daemon_natpoolalarm.go`):

```go
// maybeStartNATPoolAlarm constructs and starts the monitor exactly once,
// gated on a non-bootstrap, dataplane-armed daemon. Idempotent: a
// non-nil stored monitor short-circuits. Called from the normal-boot
// background-services block and from runBootstrapExitStartup's success
// branch.
func (d *Daemon) maybeStartNATPoolAlarm() {
    // Gate: no dataplane backend, in bootstrap (unarmed dp / pending
    // d.dp=nil write), or no constructed dp object → do not start. The
    // d.dp==nil check is added per Codex r3: the plan says
    // "dataplane-armed", and even though every current caller already
    // enforces it, making the helper self-contained prevents a future
    // caller from launching a sampler with no dp.
    if d.opts.NoDataplane || d.inBootstrap() || d.dp == nil {
        return
    }
    if d.natPoolAlarm.Load() != nil {
        return // already started
    }
    m := natpoolalarm.New(d.natPoolAlarmSampler(), d.natPoolAlarmEmitter())
    d.natPoolAlarm.Store(m)
    m.Start()
}

// stopAndDiscardNATPoolAlarm stops the monitor (joins its goroutine) and
// clears the pointer so a later re-arm builds a fresh one (Monitor is not
// restartable after Stop). Safe when no monitor is running. Called from
// rollback (enterBootstrapMode) and shutdown.
func (d *Daemon) stopAndDiscardNATPoolAlarm() {
    if m := d.natPoolAlarm.Swap(nil); m != nil {
        m.Stop()
    }
}
```

and the reader becomes:

```go
func (d *Daemon) natPoolAlarms() []natpoolalarm.ActiveAlarm {
    if d == nil {
        return nil
    }
    m := d.natPoolAlarm.Load()
    if m == nil {
        return nil
    }
    return m.ActiveAlarms()
}
```

Note: `maybeStartNATPoolAlarm` itself is only ever called under
`applySem` (boot path runs before serving; bootstrap-exit runs under the
apply caller's `applySem`), so two concurrent starts cannot interleave;
the `Load()!=nil` short-circuit + atomic `Store` are belt-and-suspenders.
`stopAndDiscardNATPoolAlarm`'s `Swap(nil)` is the single point that
both reads-and-clears, so a concurrent reader either sees the old
monitor (valid; `ActiveAlarms()` is itself mutex-guarded inside the
Monitor) or nil — never a torn pointer.

### Edit 1 — `daemon_run.go` ~880: gate the boot-time start via the helper

Replace the unconditional `New(...).Start()` with the gated helper.
Because `maybeStartNATPoolAlarm` already checks `!inBootstrap()` and
`!NoDataplane`, the call is simply:

```go
// #2114: start the NAT pool-alarm monitor only when NOT in bootstrap
// mode. maybeStartNATPoolAlarm() gates on !inBootstrap() && !NoDataplane
// and is idempotent. In bootstrap the dataplane object is constructed
// (d.dp != nil) but not armed, and the bootstrap-exit path may write
// d.dp = nil on an arm failure; the monitor's sampler reads d.dp, so
// launching it here would race that write. It is started instead at the
// end of runBootstrapExitStartup once the dataplane is armed (mirroring
// the dataplane Start() gate above). On a normal boot the gate passes
// and the monitor starts here exactly as before.
d.maybeStartNATPoolAlarm()
```

### Edit 2 — `runBootstrapExitStartup` (~1701): start on successful arm

In the existing arm block, start the monitor in the success branch
(after `d.dp.Start()` succeeds, so `d.dp` is confirmed non-nil; this is
*after* the `d.dp = nil` failure write, so the start is never reached on
the failure path). This runs under `applySem`, so the monitor's first
sampler read cannot overlap a concurrent `d.dp` write. By this point
`exitBootstrapMode` has already flipped `bootstrapMode=false` (in
`applyConfigLocked` just before calling `runBootstrapExitStartup`), so
the helper's `!inBootstrap()` gate passes:

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
        // #2114: start the NAT pool-alarm monitor now that the dataplane
        // is armed and d.dp is stable. Suppressed at boot in bootstrap
        // mode; bootstrap is already exited here (exitBootstrapMode ran in
        // applyConfigLocked), so the helper's gate passes. Idempotent.
        d.maybeStartNATPoolAlarm()
    }
}
```

### Edit 3 — `enterBootstrapMode` (~bootstrap.go): stop + discard the monitor

**(Codex r1.)** The rollback-to-bootstrap path (`enterBootstrapMode`,
reached from a first-commit-confirmed timeout at
`daemon_apply.go:308`) is reached AFTER a successful bootstrap-exit arm
— so the monitor started by Edit 2 is alive. The rollback `Teardown()`s
the dataplane but keeps `d.dp` NON-nil and (before this fix) did NOT
stop the monitor. A subsequent corrected confirmed commit re-enters
`runBootstrapExitStartup`; if THAT arm fails it writes `d.dp = nil`
while the still-running monitor samples `d.dp` — **the same race
survives**. Also `enterBootstrapMode` re-sets `bootstrapMode=true`, so
without an explicit discard the stale monitor keeps running against a
torn-down dp during the bootstrap window.

Fix: stop AND discard via the helper (the existing `Monitor` is NOT
restartable after `Stop()` — `started` stays true and the `stop`
channel is closed — so the next successful re-arm must build a FRESH
one). `enterBootstrapMode` runs under the caller's `applySem`, and the
helper's `Swap(nil)` atomically clears the pointer so a concurrent
`show security alarms` reader never sees a torn value. Place it AFTER
`d.bootstrapMode.Store(true)` but BEFORE the `applyBodyForTest`
early-return so the existing `bootstrap_rollback_test.go` seam tests
also exercise the discard (it is a no-op when no monitor is running):

```go
func (d *Daemon) enterBootstrapMode() {
    d.bootstrapMode.Store(true)

    // #2114: stop and discard the NAT pool-alarm monitor. It may have
    // been started on a prior successful bootstrap-exit arm; rolling
    // back to bootstrap means a later corrected commit can re-enter
    // runBootstrapExitStartup and, on an arm failure, write d.dp = nil
    // — which would race the monitor's sampler if it kept running.
    // Discard (not just Stop) because Monitor is not restartable after
    // Stop(); the next successful re-arm builds a fresh one.
    d.stopAndDiscardNATPoolAlarm()

    // Test seam: ...
    if d.applyBodyForTest != nil {
        return
    }
    ...
```

### Edit 4 — shutdown stop (`daemon_run.go:1512`): route through the helper

The shutdown stop becomes the helper too (it both stops and clears,
which is harmless at shutdown and keeps a single code path):

```go
// #2079/#2114: stop the NAT pool-utilization-alarm monitor.
d.stopAndDiscardNATPoolAlarm()
```

## Behavior matrix (must hold after the fix)

| Path | Boot | Bootstrap exit | Monitor running? | Races d.dp write? |
|------|------|----------------|------------------|-------------------|
| Normal boot (not bootstrap, d.dp armed) | start at line 880 | n/a | yes, from boot | no (d.dp not written after boot single-thread) |
| Bootstrap boot → first commit arms OK | suppressed | start in runBootstrapExitStartup success branch | yes, from exit | no (started under applySem after Start succeeds) |
| Bootstrap boot → first commit arm FAILS (d.dp=nil) | suppressed | NOT started (failure branch) | no | no (no monitor goroutine exists) |
| Bootstrap exit OK → confirm times out → rollback (enterBootstrapMode) | suppressed | started then **stopped+discarded** (Edit 3) | no (after rollback) | no (Edit 3 stops sampler before any future d.dp=nil) |
| ...then corrected commit re-arms OK | n/a | fresh monitor built (Edit 2 nil-guard fires) | yes | no |
| ...then corrected commit re-arm FAILS (d.dp=nil) | n/a | NOT started (failure branch); no stale sampler (Edit 3) | no | no |
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
- **Rollback-to-bootstrap → re-arm (CORRECTED in v2 — Codex r1):**
  `enterBootstrapMode` (`bootstrap.go:313`, the `prevCfg==nil`
  first-commit-timeout rollback at `daemon_apply.go:308`) is reached
  AFTER a SUCCESSFUL bootstrap-exit arm, so the Edit-2 monitor IS
  alive. `enterBootstrapMode` does NOT nil `d.dp` (Teardown + keep) and
  (before v2) did NOT stop the monitor. A later corrected confirmed
  commit re-enters `runBootstrapExitStartup`; on an arm FAILURE it
  writes `d.dp = nil` while the still-running monitor samples `d.dp`
  → THE SAME RACE survives Option A's Edits 1+2. Edit 2's nil-guard
  does not help (the field is still the old non-nil monitor). **Edit 3
  closes this**: `enterBootstrapMode` now `Stop()`s AND discards
  (`= nil`) the monitor under `applySem`, so no sampler goroutine
  survives the rollback, and the next successful re-arm builds a fresh
  monitor. (Stop+discard is required because `Monitor` is not
  restartable after `Stop()`.)

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Pure start-gating; normal-boot path byte-identical. Only new behavior: monitor start deferred to bootstrap exit on the bootstrap path. |
| Lifetime / nil-deref | LOW | Monitor Start/Stop already nil-safe + idempotent; guard added. |
| Concurrency correctness | LOW | Removes the race; introduces no new shared state. Start-at-exit runs under applySem. |
| Architectural mismatch | LOW | Mirrors the existing dataplane-Start() bootstrap gate exactly; no new abstraction. |
| Missed start path | LOW (was MED) | RESOLVED: single bootstrap-exit site (daemon_apply.go:378-380); cluster SyncApply shares it. |
| Rollback→re-arm race | LOW (was the v1 miss) | Edit 3 stops+discards the monitor in enterBootstrapMode; Monitor rebuilt fresh on next arm. Covered by the new -race rollback test. |
| Monitor-pointer race | LOW (was the v2 miss, Codex r2) | Edit 0 makes d.natPoolAlarm atomic.Pointer + routes all access (start/discard/read/shutdown) through helpers; the show-security-alarms reader can no longer race the runtime start/discard. Covered by the -race pointer-hammer test. |

## Test plan (this is a DATA RACE — `-race` is the gate)

1. `go build ./...` clean (worktree).
2. **New `-race` regression test** in `pkg/daemon` that targets the
   **daemon's monitor-lifecycle decisions** (NOT a raw always-racy
   field — that would fail pre AND post, proving nothing). To make the
   start/stop gating testable, extract the production start logic into a
   tiny method, e.g. `maybeStartNATPoolAlarm()` (called from both
   `daemon_run.go` boot path and `runBootstrapExitStartup`), so the
   test drives the REAL gate. Reuse the existing `runtimeOnlyApplyTestDP`
   fake (`policy_scheduler_apply_test.go`) as a non-nil `d.dp`.
   The test asserts, under `go test -race`:
   - **(a) boot-start gating:** with `bootstrapMode=true`, the boot-path
     start is a no-op — no sampler goroutine is launched — so a
     concurrent `d.dp = nil` (mirroring the bootstrap-exit failure
     write) does NOT race. With `bootstrapMode=false`, the monitor IS
     started.
   - **(b) rollback stop+discard:** start the monitor (simulating a
     successful bootstrap-exit arm), call `enterBootstrapMode` (the
     real method, via the `applyBodyForTest` seam so it skips
     fs/FRR/dataplane teardown but still runs the Stop+discard), assert
     `d.natPoolAlarm.Load() == nil` (atomic field — NOT `== nil`), then
     concurrently write `d.dp = nil` (the re-arm-failure write) — no
     sampler survives, so no race. Note `enterBootstrapMode` also sets
     `bootstrapMode=true`, so the helper is gated off afterward.
   - **(c) re-arm builds fresh:** mimic production re-arm ordering —
     clear bootstrap mode (`d.bootstrapMode.Store(false)`, as
     `exitBootstrapMode` does before `runBootstrapExitStartup`) BEFORE
     calling `maybeStartNATPoolAlarm`, then assert
     `d.natPoolAlarm.Load() != nil` (a FRESH monitor was built). Also
     assert that calling `maybeStartNATPoolAlarm` while still in
     bootstrap (after the part-(b) `enterBootstrapMode`) is a no-op
     (`Load() == nil`).
   - **(d) pointer-publication race (Codex r2):** concurrently hammer
     `natPoolAlarms()` (the `show security alarms` reader) from N
     goroutines while another goroutine repeatedly
     `maybeStartNATPoolAlarm()` → `stopAndDiscardNATPoolAlarm()`. With
     `d.natPoolAlarm` as `atomic.Pointer`, reads/writes of the pointer
     are race-free; pre-fix (plain pointer field mutated at runtime)
     this trips `-race`. This proves Edit 0 (atomic field + helpers).
   - **fail-pre / pass-post guarantee:** part (a) fails under `-race` if
     Edit 1's `!inBootstrap()` gate is reverted (sampler races
     `d.dp = nil`); part (b) fails if Edit 3's Stop+discard is reverted
     (stale sampler races the re-arm write); part (d) fails if Edit 0's
     atomic pointer is reverted to a plain field (reader races
     start/discard). All target real production gating — true regression
     guards, not tautologies.
   - To force the race window deterministically: the monitor's
     `tick` field is unexported and the daemon test is in a different
     package, so add a small exported test-support hook on
     `natpoolalarm.Monitor` — `SetTickForTest(d time.Duration)` (guarded
     to be called only before `Start`) — OR have the daemon test loop
     Start→Stop→discard→rebuild N times so the immediate `m.evaluate()`
     sampler read at the top of `run()` repeatedly overlaps a concurrent
     `d.dp` write. Preferred: the loop approach needs no new API; the
     immediate-evaluate read on each Start gives a deterministic
     overlap with a tight write loop, and `-race` catches a single
     overlapping access. If the loop proves flaky-detecting, add
     `SetTickForTest`. Decided in Step 5; either keeps the test
     sleep-free.
3. `go test -race ./pkg/daemon/... ./pkg/natpoolalarm/...` clean.
4. `go test ./...` (or at least affected packages) green.
5. **No cluster smoke** — control-plane only; no forwarding path change
   (per task scoping). It DOES touch the bootstrap/HA startup sequence,
   so review must confirm normal-boot, bootstrap-exit, rollback, and
   re-arm monitor-lifecycle paths all behave (covered by the test
   above).

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
3. **[CORRECTED v2 — Codex r1] Rollback-to-bootstrap → re-arm race.**
   `enterBootstrapMode` does NOT nil `d.dp` but ALSO did not stop the
   monitor, leaving the sampler alive to race a subsequent re-arm's
   `d.dp = nil`. Plus `Monitor` is not restartable after `Stop()`.
   FIXED by Edit 3 (Stop + discard in `enterBootstrapMode`). Test plan
   now covers this path.
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
