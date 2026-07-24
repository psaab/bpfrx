# #2114 (residual): publish `d.dp` through one synchronized accessor — plan-of-action

- **Status**: DRAFT v1 — pending adversarial plan review
- **Issue**: psaab/xpf#2114 (OPEN; `bug`, `audit`)
- **Branch**: `research/2114-nat-pool-alarm-dp-race` (plan docs only — NO production code in `/research`)
- **Base**: origin/master @ `ed6999000`
- **Mode**: `/research` — stops at PLAN-READY. Implementation requires manual `/engineer 2114`.

---

## 1. Issue framing

#2114 originally reported that the #2079 NAT pool-utilization-alarm monitor
(PR #2109) ran a 10 s sampler goroutine reading the daemon's `d.dp` interface
field with no synchronization, racing the bootstrap-exit `d.dp = nil` write on
a dataplane-arm failure. PR #2116 (merged) closed the *narrow* monitor race:
`d.natPoolAlarm` became an `atomic.Pointer`, the monitor start was gated on
`!inBootstrap()`, the monitor is stopped+discarded on rollback, and `-race`
regression tests landed (`daemon_natpoolalarm_race_test.go`).

The issue remains OPEN on the Paladin-audit **residual** (issue comment, master
`3821cd9d2`): the narrow fix did not close the underlying mutable-dataplane
race. On current master (`ed6999000`):

- `pkg/daemon/daemon_run.go:595-596` starts the forwarding-status CPU sampler
  unconditionally with `d.forwardingStatusDataplane()`; the sampler goroutine
  ticks at 1 Hz for the daemon's lifetime.
- The returned adapter (`forwardingStatusDaemonDataPlane`,
  `pkg/daemon/daemon_forwarding_status.go:12-14`) retains `daemon: d`, not an
  immutable dataplane snapshot, and every method re-reads the non-atomic
  interface field `d.dp` (lines 21, 24, 36, 39, 97, 100, 108, 111) on the
  sampler/request goroutines.
- The bootstrap-exit path still writes `d.dp = nil` at
  `pkg/daemon/daemon_run_naming.go:234` after a failed `Start`, on the apply
  goroutine under `d.applySem` — concurrent with the sampler and with every
  request-goroutine reader.
- The wrapper *type* (base vs userspace) is selected once at construction
  (`daemon_forwarding_status.go:123-132`) and can diverge from the backend a
  later transition leaves behind.

The issue's required closeout (verbatim, numbered):

1. Publish the runtime dataplane through one synchronized/immutable accessor
   used by **every reader and writer**, or bind the sampler to an immutable
   backend and restart/replace it transactionally.
2. Eliminate direct unsynchronized reads in the forwarding-status adapters
   and the bootstrap writer.
3. Add a deterministic `-race` regression covering sampler ticks/status calls
   concurrent with bootstrap-exit `Start` failure, plus backend-type
   transition assertions.
4. Audit all remaining `d.dp` background/request readers so this does not
   become another per-monitor patch.

## 2. Honest scope/value framing

This is a correctness/robustness change, not a performance change. There are
no cycles/MB/retransmits to win back. The win, at absolute scale:

- **Eliminates a real data race on a multiword Go interface value.** A torn
  read of `(type, data)` can panic the daemon process (fatal on a firewall)
  or yield an inconsistent type assertion. The window is narrow — bootstrap
  mode + arm failure on the first confirmed commit (or a rollback→re-exit
  cycle), standalone nodes only — but it is exactly the fresh-install/
  foreign-host unhappy path #1922/#2079 target, and `go test -race` flags the
  pattern today (proven fail-pre by the #2116 test suite before that fix).
- **Converts non-local safety arguments into local ones.** Today every `d.dp`
  reader is safe only by reasoning about some OTHER code path: applySem
  serialization, the cluster↔bootstrap mutual-exclusion invariant, `||`
  short-circuit order, monitor lifecycle gating, boot-phase ordering. The
  audit table in §5.4 classifies all ~50 read sites; roughly a third rely on
  invariants that silently break the day anyone adds a new runtime writer
  (e.g. dataplane re-arm with a fresh backend object, hot-swap, ISSU
  handoff). One publication mechanism makes each site locally correct.
- **Cost**: a mechanical conversion of ~159 production + ~32 test references
  in `pkg/daemon` (the field is package-private; zero references outside
  `pkg/daemon`), one new accessor pair, one collapsed fwdstatus adapter, and
  new `-race` tests. No Rust/helper/FFI changes. No dataplane hot-path
  changes (the packet path is the Rust helper; `d.dp` is control-plane only).

*If reviewers conclude the race window is too narrow to justify the churn,
PLAN-KILL is an acceptable verdict.* The scoped-minimal variant (Option A2,
§4) is the fallback if reviewers want the racy set fixed without the full
conversion.

## 3. What's already shipped / partially batched

- **PR #2116 (merged)** — the narrow monitor fix: `d.natPoolAlarm
  atomic.Pointer[natpoolalarm.Monitor]` (`daemon.go:223`), lifecycle helpers
  `maybeStartNATPoolAlarm` / `stopAndDiscardNATPoolAlarm`
  (`daemon_natpoolalarm.go:100-129`), start gating on `!inBootstrap()`,
  stop+discard in `enterBootstrapMode` (`bootstrap.go:334`), the
  `SetTickForTest`/`natPoolAlarmTestTick` seam, and three `-race` regression
  tests (`daemon_natpoolalarm_race_test.go`). This plan **composes with** that
  pattern (same atomic-publication idiom) and **reuses** its test seams.
- **eBPF/DPDK retirements (#1476/#1527)** — exactly one live backend type
  remains: `*dpuserspace.LegacyDataPlaneAdapter` (plus test fakes). No runtime
  backend-type swap is possible on current master; the only live transition is
  `non-nil → nil` (terminal for the daemon lifetime — nothing re-creates the
  backend after a nil-ing).
- **#1922 bootstrap mode** — the sole runtime writer context. Bootstrap is
  standalone-only: `computeBootClass` (`bootstrap.go:246-248`) resolves
  `nodeIDPresent → bootClassNormal`, so HA nodes never execute the
  bootstrap-exit writer.
- **#5868** — `enterBootstrapMode` best-effort teardown; keeps the dataplane
  object (`d.dp.Teardown()`, `bootstrap.go:472-475`) so a later corrected
  commit re-enters `runBootstrapExitStartup` and can hit the `d.dp = nil`
  writer again (the rollback→re-exit recurrence).
- **`runtime_probes.go` probe-interface idiom** — the daemon already
  duck-type-asserts `d.dp` against narrow local probe interfaces at every
  consumer; the accessor conversion preserves this shape.
- **#3970 `CachedStatus`** — the sampler consumes the manager's cached
  `ProcessStatus`; no control-socket rate change in this plan.

## 4. Multiple path options (explicit)

### Option A1 (RECOMMENDED): atomic publication cell + uniform accessor, compiler-enforced full conversion

Replace the field `dp dataplane.RuntimeDataPlane` (`daemon.go:73`) with an
atomic cell and route **all** ~191 references through one accessor pair.
Because the field's *type* changes, every direct `d.dp` read/write fails to
compile — conversion completeness is compiler-enforced, not reviewer-enforced.

```go
// daemon.go — #2114: single synchronized publication point for the
// runtime dataplane. nil cell == no dataplane (NoDataplane mode, create
// failure, or an arm-failure teardown). The slot is immutable once stored.
type dpSlot struct{ v dataplane.RuntimeDataPlane }

dpCell atomic.Pointer[dpSlot]

// dataplane returns the currently published runtime dataplane, or nil.
// Safe to call from any goroutine; each call is one atomic load. Callers
// that nil-check AND use the value must load ONCE into a local.
func (d *Daemon) dataplane() dataplane.RuntimeDataPlane {
    if s := d.dpCell.Load(); s != nil {
        return s.v
    }
    return nil
}

// setDataplane publishes dp (nil clears). Boot writers run before any
// background goroutine starts; the bootstrap-exit writer runs under
// d.applySem. Stores are ≤5 per daemon lifetime.
func (d *Daemon) setDataplane(dp dataplane.RuntimeDataPlane) {
    if dp == nil {
        d.dpCell.Store(nil)
        return
    }
    d.dpCell.Store(&dpSlot{v: dp})
}
```

Conversion rules (mechanical, applied uniformly):

- **Load-once per site**: `if d.dp != nil { d.dp.HA().X() }` →
  `if dp := d.dataplane(); dp != nil { dp.HA().X() }`. Multi-call sequences
  share one local (no TOCTOU divergence within a site).
- **Capture-once loops stay capture-once**: background goroutines that read
  `d.dp` once at start and hold the value for the loop's lifetime
  (`newConntrackGC` → `conntrack.NewGC(d.dp, …)` at `daemon_gc.go:22`;
  `syncUserspaceSessionDeltas` drainer capture at
  `daemon_ha_userspace_stream.go:67`; `runUserspaceEventStream` provider
  capture at :122) do exactly one `d.dataplane()` load at start. Same
  semantics as today, boot-ordered, no per-tick re-probe behavior change.
- **Per-tick / per-request readers load per call**: the fwdstatus adapter
  methods, the NAT pool sampler, the REST `PolicySchedulerActiveStateFn`, the
  neighbor-listener provider, health check, etc.
- **Writers**: all five `d.dp = …` sites (`daemon_run_bringup.go:448, 464,
  469, 497`; `daemon_run_naming.go:234`) → `d.setDataplane(…)`.

Forwarding-status adapter collapse (closes the wrapper-divergence residual):
replace the two-type split (`forwardingStatusDaemonDataPlane` /
`forwardingStatusDaemonUserspaceDataPlane`) with ONE adapter whose every
method probes the CURRENT dataplane per call:

```go
type forwardingStatusDaemonDataPlane struct{ daemon *Daemon }

func (a forwardingStatusDaemonDataPlane) IsLoaded() bool { /* load once; dataplaneReadyProbe */ }
func (a forwardingStatusDaemonDataPlane) GetMapStats() []fwdstatus.MapStats { /* load once; Telemetry() */ }
func (a forwardingStatusDaemonDataPlane) Status() (dpuserspace.ProcessStatus, error) { /* load once; userspaceStatusProbe */ }
func (a forwardingStatusDaemonDataPlane) CachedStatus() (dpuserspace.ProcessStatus, bool) { /* load once; userspaceCachedStatusProbe */ }
```

`forwardingStatusDataplane()` then returns this single adapter (nil only when
`d.opts.NoDataplane`, preserving today's NoDataplane behavior). The sampler's
per-tick `s.dp.(interface{ CachedStatus() … })` assertion now always succeeds
type-wise; `CachedStatus` returns `ok=false` on nil/non-userspace — the
sampler's documented hold-last-values path, observably identical to today
(sampler.go:111-125). The wrapper type can never diverge from the backend
because there is exactly one wrapper.

Why atomic.Pointer and not `atomic.Value`: `atomic.Value.Store(nil)` panics
and mixed concrete types panic; the cell must hold "interface or absent".
`atomic.Pointer[dpSlot]` gives clean nil semantics, one allocation per Store
(≤5 lifetime), and matches the #2116 `atomic.Pointer` precedent.

### Option A2 (fallback): same accessor, scoped-minimal conversion

Convert only (a) the 5 writers, (b) the genuinely racy readers (fwdstatus
adapter + sampler path, REST `PolicySchedulerActiveStateFn`, neighbor
listener, NAT pool sampler, health), leaving applySem-serialized, boot-only,
and cluster-only readers on a raw field. Smaller diff (~40 sites) but the
field must remain directly readable → two access patterns coexist → the
compiler-enforcement property is lost and a future runtime writer silently
re-races the unconverted readers. Weaker against issue requirement #1
("every reader and writer") and #4. Documented as the reviewers' fork.

### Option B: eliminate the writer (write-once `d.dp` + degraded adapter)

Never nil `d.dp` after boot construction; an arm failure instead marks the
adapter degraded/unarmed, and `d.dp == nil` keeps meaning only "NoDataplane /
create failure". `d.dp` becomes write-once-before-goroutines → plain reads
are safe by goroutine-start happens-before. Rejected as primary: requires
re-auditing every `d.dp == nil` check (159 sites) for nil-vs-degraded
semantics, adds degraded handling across the adapter's
HA()/Sessions()/Telemetry()/ApplyConfig surfaces, changes config-only-mode
behavior on arm failure (blackhole-relevant apply-path semantics), and leaves
the unsynchronized-read pattern latent for any future writer. Larger blast
radius than A1 for the same race closure. Could be a later follow-up; not
required by the issue.

### Option C: `sync.RWMutex`-guarded accessor

Same shape as A1 with a mutex instead of `atomic.Pointer`. Pros: no wrapper
allocation; familiar. Cons: per-read lock traffic; a future caller holding
RLock across a blocking call can self-deadlock against a writer — atomic
makes hold-nothing structural; deviates from the #2116 precedent. Viable if
reviewers prefer it; otherwise A1.

### Option D: per-consumer lifecycle gating (extend #2116 to each reader)

Stop/restart every background consumer around bootstrap transitions.
REJECTED: it is exactly the per-monitor patch pattern issue requirement #4
rules out, and it cannot cover request-goroutine readers at all.

## 5. Concrete design (A1)

### 5.1 New/changed types

- `daemon.go`: add `dpSlot`, replace field `dp` with `dpCell
  atomic.Pointer[dpSlot]`, add `dataplane()`/`setDataplane()`. Document the
  publication contract on the field (mirrors the `natPoolAlarm` comment at
  `daemon.go:211-223`).
- `daemon_forwarding_status.go`: collapse to one adapter (§4 A1);
  `forwardingStatusDataplane()` returns `nil` iff `d.opts.NoDataplane`,
  else the singleton adapter; `userspaceStatusProbe`/
  `userspaceCachedStatusProbe` retained for the per-call assertions.
- No signature changes outside `pkg/daemon`. `fwdstatus.DataPlaneAccessor`,
  `Sampler`, `Build` untouched. `pkg/grpcapi`/`pkg/cli` peer accessors
  untouched (they hold boot-captured probes of their own — see §5.4 class B).

### 5.2 Writer conversion (5 sites)

| Site | Context | After |
|---|---|---|
| `daemon_run_bringup.go:448` `d.dp = nil` (DPDK retired) | boot, pre-servers | `d.setDataplane(nil)` |
| `daemon_run_bringup.go:464` `d.dp = nil` (eBPF retired) | boot, pre-servers | `d.setDataplane(nil)` |
| `daemon_run_bringup.go:469` `d.dp = dp` (construct) | boot, pre-servers | `d.setDataplane(dp)` |
| `daemon_run_bringup.go:497` `d.dp = nil` (Start fail) | boot, pre-servers | `d.setDataplane(nil)` |
| `daemon_run_naming.go:234` `d.dp = nil` (bootstrap-exit arm fail) | apply goroutine, `d.applySem` | `d.setDataplane(nil)` |

### 5.3 Reader conversion rules

Per §4 A1: load-once locals; capture-once loops unchanged semantically;
per-tick/request readers load per call. `%T` logging
(`daemon_ha_sync.go:311`) becomes `%T` of the loaded value (same output).
`dataplane.LastApplyResultOf(d.dp)` (`daemon.go:1012`) →
`dataplane.LastApplyResultOf(d.dataplane())`.

### 5.4 Reader audit table (issue requirement #4)

All `d.dp` read sites, classified by synchronization context. Classes:
**A** = applySem-serialized (safe vs the writer today, non-locally);
**B** = boot-only before servers serve (safe by goroutine ordering);
**C** = background/request goroutine, no synchronization (**racy today** vs
the bootstrap-exit writer);
**D** = cluster-only background (writer unreachable today via the
nodeID→no-bootstrap invariant; formally unsynchronized);
**E** = lifecycle-gated (#2116 monitor; safe, converted for uniformity).

| File:lines | Context | Class |
|---|---|---|
| `daemon_forwarding_status.go` 21,24,36,39,97,100,108,111,124,128 | fwdstatus sampler 1 Hz tick (+ any Build caller) | **C** |
| `daemon_run_servers.go` 409-417 (`PolicySchedulerActiveStateFn`) | REST request goroutine | **C** |
| `daemon_neighbor_listener.go` 304,307,473 | netlink subscription/regen goroutines | **C** |
| `daemon_natpoolalarm.go` 18,21 | monitor sampler (gated) | E |
| `daemon_health.go` 141 | standby-neighbor refresh (standalone short-circuits before reading) | C/D border |
| `daemon_ha_fabric.go` 533,537,554,555,567,570,724,728,750,753 | fabric probe/refresh goroutines | D |
| `daemon_ha_userspace_stream.go` 67,122,235,259 | HA stream/delta goroutines (capture-once at start) | D |
| `daemon_ha_sync.go` 193,299,300,311,733,750,1117,1124 | HA watchdog/sync goroutines | D |
| `daemon_ha.go` 297,299,337,348,362,367,542,549,578,583,813,826 | VRRP event watcher / RG reconcile goroutines | D |
| `daemon_ha_userspace_readiness.go` 202,230,233 | takeover-readiness probe (cluster paths) | D |
| `daemon_apply_dataplane.go` 53,98,122,139,141,293,295,390,393 | apply path | A |
| `daemon_apply_tail.go` 491,494 | apply path | A |
| `daemon_apply_interfaces.go` 42 | apply path | A |
| `daemon_apply_routing.go` 367 | apply path | A |
| `daemon_apply.go` 320 (comment) | — | — |
| `daemon_scheduler.go` 211,221,224,230,239 | scheduler republish under applySem | A |
| `daemon_ipmon.go` 304 | route-overlay actuate under applySem | A |
| `daemon_policy_invalidate.go` 286,290 | session clear (apply + `clear` request paths) | A/C — callers vary; accessor makes both locally safe |
| `daemon_system.go` 41 | applySyslogConfig (apply path) | A |
| `daemon_flow.go` 379 | comment only | — |
| `daemon_run.go` 212,223,238,270,312,324,354,365,375,384,385,611,612 | boot PHASE 3-5 + CLI construction probe | B |
| `daemon_run_servers.go` 117,118,255,256 | gRPC/API server construction probes | B |
| `daemon_run_shutdown.go` 161,167,173,214,219,220,225,229 | shutdown sequence (post-ctx-cancel) | B-ish; load once per site |
| `daemon_gc.go` 22 | GC construction capture | B (capture-once) |
| `daemon.go` 1012 | `applyResult()` (apply path caller only today) | A |
| `bootstrap.go` 472,473 | rollback teardown under applySem | A |
| `daemon_run_bringup.go` 476,477,493,494,506 | boot | B |

The racy-today set (class C, plus the policy-invalidate request variant) is
small — but every class-A/D/E site's safety is a non-local invariant. The
accessor converts all five classes to the same locally-safe load.

### 5.5 Docs contract

`pkg/daemon/README.md` (bootstrap-mode bullet ~:556-568 and first-commit
rollback bullet ~:578-585) currently describes the #2116 monitor-only
lifecycle ("the monitor samples `d.dp`, which is still nil-able …"). Update
both bullets to describe the single publication cell + accessor contract and
the collapsed fwdstatus adapter. No other module docs name `d.dp`
(`pkg/dataplane/README.md` is backend-focused; `docs/engineering-style.md`
unchanged — the atomic-cell idiom may merit one line there, decided at
/engineer time).

## 6. Public API preservation

`Daemon` and its field are package-private; nothing outside `pkg/daemon`
references them (verified: `grep '\.dp\b'` outside pkg/daemon hits unrelated
structs — `fwdstatus.Sampler.dp`, `grpcapi.Server.dp`, `cli.CLI.dp`, which
are their own boot-captured probes and are NOT the daemon's field).

Preserved exactly:

- `fwdstatus.DataPlaneAccessor` interface (`IsLoaded`, `GetMapStats`) and the
  sampler-facing `Status`/`CachedStatus` method set.
- `conntrack.NewGC(d.dp, interval)` receives the same captured value at boot
  (now via one accessor load).
- `cliDataPlane`/`grpcDataPlane`/`apiDataPlane` boot probe results.
- NAT pool-alarm monitor lifecycle (#2116): gating, rollback discard,
  `show security alarms` behavior.
- `show chassis forwarding` rendered output (local + peer paths): same
  not-loaded/unknown render on nil dataplane; same hold-last-values CPU
  sampling on status miss.
- NoDataplane mode: cell nil for the daemon lifetime; every reader observes
  exactly what `d.dp == nil` yields today.
- `applyResult()`, health endpoint, REST simulator gating (`ok=false` fail
  closed on absent dataplane, #3414).

## 7. Hidden invariants the change must preserve

1. **Load-once per site (TOCTOU)**: any site that nil-checks and then uses
   the value, or calls two methods on it, must hold ONE local load. The
   conversion is mechanical but this is the one way to introduce a NEW bug
   (two loads observing a transition mid-site). Reviewer focus point.
2. **Boot publication ordering**: `setDataplane` construction/nil writes at
   bringup happen before any background goroutine or server starts —
   preserved (same program order as today).
3. **Capture-once semantics**: GC and HA stream captures keep the object
   they grabbed at start even across a later nil-ing (today: same, via the
   plain field read at start). Deliberately preserved; a post-transition
   swap of the GC's dataplane is OUT of scope.
4. **applySem orthogonality**: the accessor is lock-free; it neither takes
   applySem nor interacts with the "Locked" conventions. Apply-path readers
   keep their existing serialization; the accessor only adds safe
   publication for the non-applySem readers.
5. **#2116 monitor lifecycle**: the sampler closure switches to the accessor
   but gating/discard are untouched; the three existing race tests must keep
   passing with `writeDPFor` re-pointed at `setDataplane`.
6. **Terminal nil**: after an arm-failure nil-ing, nothing re-publishes a
   backend on current master (no re-construction path exists). The accessor
   does not rely on this (it is correct under any Store sequence), but tests
   assert the observable post-nil state.
7. **No typed-nil publication**: `setDataplane` nil-checks the interface
   exactly as today's assignments do; `buildRuntimeDataPlane` returns either
   a non-nil adapter or a nil interface (`dpuserspace.Boot()` or
   `NewRuntimeDataPlane` error paths). Parity with today; a reflect-based
   typed-nil guard is an open question (OQ7), not planned.
8. **Shutdown ordering** (#5807): the shutdown sequence reads the dataplane
   for `logFinalStats`/HA clear AFTER ctx cancel; load-once per shutdown
   site preserves the exact current behavior (a post-nil shutdown sees nil
   and skips final stats — identical to today).
9. **Allocation rules**: one `dpSlot` allocation per Store (≤5/lifetime);
   zero per read. No hot-path impact (Go control plane only; the Rust helper
   owns packets).

## 8. Risk assessment

| Class | Rating | Assessment |
|---|---|---|
| Behavioral regression | **MED** | Diff is large but mechanical. Compiler-enforced completeness (field retype) makes "missed site" impossible. Real risks: (a) a load-twice divergence introduced at a multi-use site; (b) fwdstatus singleton-adapter observable drift (mitigated — methods return the same values the nil/non-userspace branches return today; `Build` tolerates nil and the sampler already handles `ok=false`); (c) test fakes assigning `d.dp` directly (32 test refs) must move to `setDataplane` — compiler catches all. Full `make test-go` + `-race` + the new regression suite gate this. |
| Lifetime / borrow-checker | **LOW** | Slots are immutable after Store; no object is freed earlier than today (captured references keep the old adapter alive exactly as the plain field did). No FFI/Rust lifetime interaction. |
| Performance regression | **LOW** | One atomic load + one indirection per read on control-plane paths (1 Hz sampler, request rate, HA loops ≤15/s). No per-packet Go code exists. One small allocation per Store, ≤5 per daemon lifetime. |
| Architectural mismatch | **LOW** | Follows the merged #2116 `atomic.Pointer` precedent and the daemon's existing "atomics for cross-goroutine publication, applySem for apply serialization" idiom (`natPoolAlarm`, `bootstrapMode`, `policySchedulerEpoch`). Does NOT attempt the dataplane-lifecycle redesign (Option B) that could dead-end into #961/#946-style churn. |

## 9. Test plan

1. `go build ./... && go vet ./pkg/daemon/...` — the field retype makes the
   compiler enumerate every conversion site.
2. New `pkg/daemon/daemon_dp_race_test.go` (run under `-race`, `-count=5`
   for flake hunt):
   - `TestDataplaneCell_ConcurrentReadersVsWriter` — N goroutines hammer the
     accessor-routed readers (fwdstatus adapter `IsLoaded`/`GetMapStats`/
     `CachedStatus`, `applyResult()`, a `PolicySchedulerActiveStateFn`-shape
     probe, the NAT pool sampler closure) while a writer goroutine alternates
     `setDataplane(nil)` / `setDataplane(fake)` on a tight loop. Fail-pre if
     the cell ever reverts to a plain field; pass-post clean. Mirrors the
     #2116 `writeDPFor` pattern.
   - `TestForwardingStatus_BackendTypeTransitions` — one adapter instance
     across: userspace fake present (CachedStatus live) → `setDataplane(nil)`
     (`IsLoaded` false, `GetMapStats` nil, `CachedStatus` miss) →
     non-userspace ready-probe fake (`IsLoaded` true, `Status` error,
     `CachedStatus` miss). Proves per-call probing; the stale-wrapper class
     cannot regress.
   - `TestBootstrapExit_ArmFailureWithConcurrentSampler` — daemon in
     bootstrap with a `Start`-failing fake; run the real
     `runBootstrapExitStartup` while sampler/status/probe readers churn;
     assert `-race` clean, `d.dataplane() == nil` after, monitor not started.
3. Update `daemon_natpoolalarm_race_test.go`: `writeDPFor` writes through
   `setDataplane`; the three #2116 tests keep their fail-pre gate/discard
   assertions unchanged.
4. Existing suites: `go test ./pkg/daemon/... ./pkg/fwdstatus/... ./pkg/cli/...
   ./pkg/grpcapi/... ./pkg/api/...` and full `make test-go`.
   `make test-rust` untouched (no Rust changes) but runs as part of
   `make test` at /engineer time.
5. HA gate: the conversion mechanically touches `daemon_ha*.go` readers.
   Per CLAUDE.md, `make test-failover` on the loss userspace cluster (with
   the #1875/`with-cluster.sh` lock discipline) before merge at /engineer
   time. Open question OQ6 asks reviewers whether a purely mechanical
   accessor swap waives this.
6. No bootstrap-mode integration env exists (the xpf-fw VM boots with an
   active config → normal boot); bootstrap-window coverage stays at the
   unit/`-race` level, same as #2116.

## 10. Out of scope (explicitly)

- Option B (write-once `d.dp` / degraded-adapter semantics) — deferred; not
  required to close the race.
- Changing capture-once consumers (GC, HA event stream) to per-tick re-probe.
- `pkg/grpcapi` / `pkg/cli` boot-captured forwarding-status probes (stale
  after a daemon-side transition, but never racy — captured before servers
  serve; a consistency follow-up could re-source them from the daemon
  accessor, separate issue).
- The `apply.go:29` TODO (migrate HA session sync from type assertions to
  `RuntimeDataPlane.SessionDeltas`).
- `pkg/fwdstatus` Sampler/Build internals; any Rust/helper change; dataplane
  hot-swap/re-arm support.
- `reflect`-based typed-nil hardening of `setDataplane` (OQ7).

## 11. Open questions for adversarial review

1. **PLAN-KILL fork**: is the racy-today set (bootstrap-exit arm failure ×
   {sampler, REST simulator probe, neighbor listener}, standalone-only,
   unhappy-path-only) worth a ~191-site conversion, or should this plan be
   killed down to A2 (~40 sites, racy set + writers only) — or killed
   outright with the fwdstatus adapter fixed and a comment? Issue requirement
   #1 says "every reader and writer"; reviewers may read that as license for
   A1 or as satisfied by A2+convention.
2. Is `atomic.Pointer[dpSlot]` the right cell, or do reviewers require
   `sync.RWMutex` (Option C) for readability/auditability? Any concrete
   objection to the wrapper-allocation/indirection shape?
3. The fwdstatus singleton adapter makes the sampler's
   `s.dp.(interface{ CachedStatus() … })` assertion always succeed. Confirm
   no consumer distinguishes "accessor lacks Status/CachedStatus" from
   "Status returns error" (audited: only the sampler type-asserts, and its
   `ok=false` path is equivalent; `Build` sees the same values). Did the
   audit miss a consumer?
4. Should capture-once sites (GC at `daemon_gc.go:22`, HA stream at
   `daemon_ha_userspace_stream.go:67/122`) instead re-load per use so a
   future re-arm swaps them onto the new backend? Plan says preserve
   semantics; reviewers may argue the swap is the more correct end-state —
   but it is a behavior change beyond the race fix.
5. `daemon_policy_invalidate.go:286-290` is called from both apply paths
   (applySem) and `clear security session` request paths (no applySem?) —
   confirm the request-path caller set and that the accessor conversion is
   sufficient there (no additional serialization needed for the Sessions()
   store itself, which has its own internal locking).
6. Does a mechanical accessor swap in `daemon_ha*.go` trigger the CLAUDE.md
   `make test-failover` mandate, or is the Go `-race` suite + unit coverage
   sufficient given zero behavioral delta? (Cluster cost: lock + minutes.)
7. Should `setDataplane` reject typed-nil interfaces (`reflect.ValueOf(dp).
   IsNil()`) defensively, or keep parity with today's plain assignment
   (which would also admit a typed nil)? Current callers cannot produce one;
   is the guard worth the import?
8. Any objection to updating `pkg/daemon/README.md`'s bootstrap bullets in
   the same PR (docs-as-contract rule), and should `docs/engineering-style.md`
   gain a one-liner naming `d.dataplane()` as the only legal read pattern?

---

*Review ledger: see `reviewer-ids.md`. Round docs: `claude-smr-plan-r<N>.md`,
`codex-plan-r<N>.md`, `agy-plan-r<N>.md`.*
