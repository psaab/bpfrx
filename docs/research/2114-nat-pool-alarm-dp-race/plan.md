# #2114 (residual): publish `d.dp` through one synchronized accessor — plan-of-action

- **Status**: DRAFT v2 — r1 findings folded (Codex NEEDS-REVISION 7M/6m; AGY
  PLAN-READY-WITH-NITS 1M/3m; Claude SMR NEEDS-REVISION 4B/3M/4m); pending
  convergence review r2
- **Issue**: psaab/xpf#2114 (OPEN; `bug`, `audit`)
- **Branch**: `research/2114-nat-pool-alarm-dp-race` (plan docs only — NO
  production code in `/research`)
- **Base**: origin/master @ `ed6999000`
- **Mode**: `/research` — stops at PLAN-READY. Implementation requires manual
  `/engineer 2114`.
- **Revision history**: v1 @ `1d62be758` (initial). v2: r1 convergence —
  deletes two false safety invariants (B1/B2), deletes incoherent Option A2
  (B3), adds the retirement-canary redesign (B4), regenerates the audit table
  mechanically (M1), scopes the fwdstatus singleton sampler-only (M2),
  enumerates per-site snapshot boundaries (M3), corrects migration size +
  docs scope + test design (m1-m4).

---

## 1. Issue framing

#2114 originally reported that the #2079 NAT pool-utilization-alarm monitor
(PR #2109) ran a 10 s sampler goroutine reading the daemon's `d.dp` interface
field with no synchronization, racing the bootstrap-exit `d.dp = nil` write on
a dataplane-arm failure. PR #2116 (merged) closed the *narrow* monitor race:
`d.natPoolAlarm` became an `atomic.Pointer`, the monitor start was gated on
`!inBootstrap()`, the monitor is stopped+discarded on rollback, and `-race`
regression tests landed (`daemon_natpoolalarm_race_test.go`).

The issue remains OPEN on the Paladin-audit **residual**: the narrow fix did
not close the underlying mutable-dataplane race. The field `d.dp
dataplane.RuntimeDataPlane` (`pkg/daemon/daemon.go:73`) is a plain interface
field with **five writers** and **~159 production read sites** in
`pkg/daemon`, most of them unsynchronized background/request-goroutine
reads.

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

- **Eliminates a real data race on a multiword Go interface value**, on at
  least TWO structurally distinct interleavings (r1 review proved both —
  neither needs exotic timing):
  - **RACE-1 (HA boot publication, no bootstrap needed)**:
    `initManagers` starts the cluster event watcher
    (`daemon_run_bringup.go:203`, election may synchronously enqueue the
    initial transition via `UpdateConfig` at :181) BEFORE
    `setupDataplaneAndInitialConfig` assigns `d.dp` (:448/:469/:497). The
    watcher reads `d.dp` at `daemon_ha.go:297` with no happens-before edge
    to the assignment.
  - **RACE-2 (bootstrap-exit arm failure)**:
    `runBootstrapExitStartup` writes `d.dp = nil`
    (`daemon_run_naming.go:234`) on the apply goroutine under `d.applySem`
    while the 1 Hz forwarding-status sampler
    (`daemon_forwarding_status.go:108,111` via `daemon_run.go:595`), the
    standalone userspace event stream
    (`daemon_ha_userspace_stream.go:122` — launched when
    `d.cluster == nil`, `daemon_run.go:365`), the REST simulator probe
    (`daemon_run_servers.go:409-417`), the neighbor listener
    (`daemon_neighbor_listener.go:303-310,469-476`), and (on HA nodes that
    transit bootstrap after a compile-failed boot + rollback recurrence)
    every `daemon_ha*.go` background reader run unsynchronized.
  A torn `(type, data)` read can panic the daemon process (fatal on a
  firewall) or yield an inconsistent type assertion.
- **Converts non-local safety arguments into local ones.** Today every
  reader's safety depends on reasoning about OTHER code (applySem
  serialization, boot-phase program order, `||` short-circuit order, monitor
  lifecycle gating). r1 review proved two of those non-local arguments
  FALSE as stated (RACE-1; the bootstrap/HA mutual exclusion). One
  publication mechanism makes each site locally correct and keeps it correct
  when the next runtime writer appears.
- **Cost**: a mechanical conversion of ~159 production references plus ~110
  test sites (32 selector-style + ~79 `Daemon{dp: ...}` keyed literals) in
  `pkg/daemon`; the field is package-private, zero references outside the
  package. One new accessor pair, one collapsed sampler-only fwdstatus
  adapter, one redesigned architecture canary, new `-race` tests. No
  Rust/helper/FFI changes; no packet-path changes.

*If reviewers conclude the race windows are too narrow to justify the churn,
PLAN-KILL is an acceptable verdict.*

## 3. What's already shipped / partially batched

- **PR #2116 (merged)** — the narrow monitor fix: `d.natPoolAlarm
  atomic.Pointer[natpoolalarm.Monitor]` (`daemon.go:223`), lifecycle helpers
  (`daemon_natpoolalarm.go:100-129`), `!inBootstrap()` gating, rollback
  stop+discard (`bootstrap.go:334`), `SetTickForTest` seam, three `-race`
  tests. This plan composes with that idiom and reuses its seams.
- **eBPF/DPDK retirements (#1476/#1527)** — one live backend type remains
  (`*dpuserspace.LegacyDataPlaneAdapter`, plus test fakes). The only live
  `d.dp` transition on master is `non-nil → nil` (terminal — nothing
  re-constructs the backend; `buildRuntimeDataPlane` has exactly one caller,
  `daemon_run_bringup.go:421`).
- **#1922 bootstrap mode** — the apply-path writer context. NOTE (r1
  correction): bootstrap is NOT standalone-only — `computeBootClass` checks
  `configCompileFailed` BEFORE `nodeIDPresent` (`bootstrap.go:233-246`), so
  an HA node with an uncompilable committed config enters bootstrap too.
- **#5868** — `enterBootstrapMode` best-effort rollback; keeps the dataplane
  object (`d.dp.Teardown()`, `bootstrap.go:472-475`) and does NOT stop
  cluster comms, so a corrected re-commit re-enters
  `runBootstrapExitStartup` (the rollback recurrence) with HA goroutines
  already live.
- **`runtime_probes.go` probe-interface idiom** — consumers duck-type-assert
  `d.dp` against narrow local interfaces; the accessor preserves this shape.
- **#3970 `CachedStatus`** — sampler consumes the manager's cached
  `ProcessStatus`; no control-socket rate change here.

## 4. Multiple path options (explicit)

### Option A1 (RECOMMENDED): atomic publication cell + uniform accessor, compiler-enforced full conversion

Replace the field `dp dataplane.RuntimeDataPlane` (`daemon.go:73`) with an
atomic cell and route **all** references through one accessor pair. Because
the field's *type* changes, every direct `d.dp` read/write fails to compile —
conversion completeness is compiler-enforced (against old selectors, aliases,
keyed literals, embedding, method values; external packages cannot name the
unexported field at all).

```go
// daemon.go — #2114: single synchronized publication point for the runtime
// dataplane. nil cell == no dataplane (NoDataplane mode, create failure, or
// an arm-failure teardown). The slot is immutable once stored.
type dpSlot struct{ v dataplane.RuntimeDataPlane }

dpCell atomic.Pointer[dpSlot]

// dataplane returns the currently published runtime dataplane, or nil.
// One atomic load; safe from any goroutine. Callers that nil-check AND use
// the value must load ONCE into a local (see §5.3 snapshot boundaries).
func (d *Daemon) dataplane() dataplane.RuntimeDataPlane {
    if s := d.dpCell.Load(); s != nil {
        return s.v
    }
    return nil
}

// setDataplane publishes dp (nil clears). The typed-nil guard keeps a
// non-nil interface wrapping a nil pointer out of the cell (r1 AGY MINOR 2 /
// Codex MINOR 4): current constructors cannot produce one, but the runtime
// registry (pkg/dataplane/dataplane.go:152,215) returns arbitrary
// constructor results unchecked. Reflect cost is once per Store, ≤5 Stores
// per daemon lifetime.
func (d *Daemon) setDataplane(dp dataplane.RuntimeDataPlane) {
    if dp == nil || reflect.ValueOf(dp).IsNil() {
        d.dpCell.Store(nil)
        return
    }
    d.dpCell.Store(&dpSlot{v: dp})
}
```

Why `atomic.Pointer[dpSlot]` and not `atomic.Value`: `Store(nil)` panics and
mixed concrete types panic; the cell must hold "interface or absent". One
allocation per Store, zero per read; matches the #2116 precedent.

**Canary redesign (work item, r1 B4)**: the retype breaks
`TestDaemonRuntimeEntryPointUsesRuntimeDataPlane`
(`pkg/dataplane/retirement_boundary_canary_test.go:1711`, helper
:3314-3348), which requires a Daemon field NAMED `dp` of AST type exactly
`dataplane.RuntimeDataPlane`; its expression renderer also cannot represent
the generic (:3352). The /engineer pass must:
  1. extend the canary matcher to accept the new shape — field
     `dpCell atomic.Pointer[dpSlot]` AND a `dpSlot` struct whose `v` field is
     `dataplane.RuntimeDataPlane` (the retirement boundary the canary guards
     is preserved: the daemon's dataplane IS a RuntimeDataPlane, now
     published atomically);
  2. add a NEW AST canary in `pkg/daemon` forbidding direct `dpCell` /
     `.dpCell.Load()/.Store()` references outside the accessor definitions,
     so a future package-local bypass fails `make test-go`.

**fwdstatus adapter collapse, scoped SAMPLER-ONLY (r1 M2)**: replace the
two-type split (`forwardingStatusDaemonDataPlane` /
`forwardingStatusDaemonUserspaceDataPlane`) with ONE adapter whose methods
probe the CURRENT dataplane per call:

```go
type forwardingStatusDaemonDataPlane struct{ daemon *Daemon }

func (a forwardingStatusDaemonDataPlane) IsLoaded() bool                          // one load; dataplaneReadyProbe
func (a forwardingStatusDaemonDataPlane) GetMapStats() []fwdstatus.MapStats       // one load; Telemetry()
func (a forwardingStatusDaemonDataPlane) Status() (dpuserspace.ProcessStatus, error)   // one load; userspaceStatusProbe
func (a forwardingStatusDaemonDataPlane) CachedStatus() (dpuserspace.ProcessStatus, bool) // one load; userspaceCachedStatusProbe
```

Equivalence claim — DELIBERATELY NARROW (r1 correction): the daemon
adapter's ONLY production consumer is the `fwdstatus.Sampler`
(`daemon_run.go:595`), which calls only `CachedStatus`
(`sampler.go:113-125`); there, "method absent" and "returns ok=false" are
provably equivalent (both hold last counters). `IsLoaded`/`GetMapStats`/
`Status` exist to satisfy `fwdstatus.DataPlaneAccessor` and have **no
production caller** — the gRPC/CLI Build paths construct their OWN adapters
per request from boot-captured probes (`server_show_forwarding.go:21-22`,
`cli_show_chassis.go:59-60`) and are NOT touched by this plan. It is
explicitly NOT claimed that the singleton is `Build`-equivalent: `Build`
detects the backend by the PRESENCE of `Status()` (`builder.go:116-123`),
so a universal always-has-`Status` adapter would flip `isUserspace` and
change rendered state if anyone ever fed it to `Build`. The plan adds a
comment on the adapter ("sampler-only; do not feed to fwdstatus.Build —
capability-presence is backend identity there") and a test pinning the
sampler-path equivalence. `forwardingStatusDataplane()` returns nil iff
`d.opts.NoDataplane` (today: nil iff `d.dp == nil` at construction —
behaviorally identical through the sampler for every boot outcome).

### Option B: eliminate the writer (write-once `d.dp` + degraded adapter)

Never nil `d.dp`; arm failure marks the adapter degraded. REJECTED as
primary: its "write once before goroutines" premise is ALREADY false (RACE-1
shows cluster goroutines start before the boot assignment); it requires
re-auditing every `d.dp == nil` check (~159 sites) for nil-vs-degraded
semantics; it changes config-only-mode behavior on arm failure
(`daemon_apply_dataplane.go:139` skips apply on nil — blackhole-relevant);
and it leaves the unsynchronized-read pattern latent for any future writer.
Larger blast radius than A1 for the same closure.

### Option C: `sync.RWMutex`-guarded accessor

Same shape as A1 with a mutex. NOT wrong on deadlock grounds (an accessor
that copies the interface under RLock and unlocks before returning cannot
hold across a call — r1 correction of v1's overstatement). Not chosen: the
#2116 `atomic.Pointer` precedent, cheaper reads, and hold-nothing-by-
construction. Viable if a reviewer insists; changes nothing else in the plan.

### Option D: immutable owner + atomic presence flag (r1 addition, REJECTED)

Write-once `dpOwner` field + `atomic.Bool dpPresent`; arm failure clears only
the flag; nil-checks become flag-checks. Weaker than A1: identity and
presence live in two words, so a FUTURE republish (new backend object) can
be torn (reader sees flag=true, loads NEW owner, or flag flip mid-
operation); it also cannot express "no dataplane was ever constructed"
without a third state. A1 atomically couples identity + presence in one
pointer and supports republishing for free. Documented for completeness.

### Option E: per-consumer lifecycle gating (extend #2116 per reader)

REJECTED: exactly the per-monitor patch pattern issue requirement #4 rules
out; cannot cover request-goroutine readers at all.

### The honest fork (r1 B3)

v1's Option A2 (accessor + writers converted, raw field retained for
unconverted readers) was **incoherent** — with the retype there is no raw
field; keeping one means dual-writing (two sources of truth, race preserved)
and a stale raw field is FUNCTIONALLY wrong (`d.dp == nil` gates the
dataplane apply at `daemon_apply_dataplane.go:139`). A2 is deleted. The real
fork: **A1 as specified, or PLAN-KILL** (accept the two races as documented
known-issues and fix only the fwdstatus sampler by rebinding it per
transition — which fails issue requirements #1/#4 and leaves RACE-1 open).

## 5. Concrete design (A1)

### 5.1 New/changed types

- `daemon.go`: `dpSlot`, `dpCell atomic.Pointer[dpSlot]` replacing `dp`;
  `dataplane()` / `setDataplane()` with the typed-nil guard; field doc
  comment mirroring the `natPoolAlarm` contract (`daemon.go:211-223`).
- `daemon_forwarding_status.go`: single sampler-only adapter (§4 A1);
  `forwardingStatusDataplane()` returns nil iff `d.opts.NoDataplane`;
  `userspaceStatusProbe` / `userspaceCachedStatusProbe` retained for
  per-call assertions.
- `pkg/dataplane/retirement_boundary_canary_test.go`: matcher extension +
  new `pkg/daemon` AST canary (§4 A1 canary work item).
- No signature changes outside `pkg/daemon`. `pkg/fwdstatus`, `pkg/grpcapi`,
  `pkg/cli` untouched.

### 5.2 Writer conversion (5 sites — complete, verified by both reviewers)

| Site | Context | After |
|---|---|---|
| `daemon_run_bringup.go:448` (DPDK retired) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_bringup.go:464` (eBPF retired) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_bringup.go:469` (construct) | boot, Run goroutine — races the cluster watcher (RACE-1) | `d.setDataplane(dp)` |
| `daemon_run_bringup.go:497` (Start fail) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_naming.go:234` (bootstrap-exit arm fail) | apply goroutine, `d.applySem` (RACE-2) | `d.setDataplane(nil)` |

### 5.3 Per-site snapshot boundaries (r1 M3 — normative conversion rules)

The mechanical rule "load once per site" is REFINED per site shape; each
converted site MUST match one of these patterns:

1. **Per-tick loop readers** (HA watchdog `daemon_ha_sync.go:750`,
   reconcile loops, neighbor listener): ONE load per tick/iteration,
   before any per-element loop that uses it (watchdog: one load shared
   across the RG loop — not per-RG, not a lifetime capture).
2. **Spawn-gated loops** (`daemon_ha_sync.go:733` gates the watchdog
   goroutine on `d.dp != nil` THEN the loop reads per tick): gate check is
   one load; the loop body loads per tick per rule 1 (the goroutine must
   observe a later nil-ing — today it would too, reading the plain field).
3. **Multi-use straight-line sites** (`daemon_run_naming.go:230-248`
   bootstrap-exit: nil-check + `Start` + seeding): ONE local for the whole
   block; `setDataplane(nil)` only on the failure branch.
4. **Two-assertion sites** (`daemon_neighbor_listener.go:469-476`: provider
   then `indexEnumerator`): both assertions derive from ONE load.
5. **Snapshot-per-operation** (fence `daemon_ha_sync.go:1286+`,
   `warmNeighborCache` `daemon_ha.go:1521+`, shutdown blocks
   `daemon_run_shutdown.go:161-173` and :214-229 — one snapshot for the
   HA-clear block, a SECOND for final-stats+Close/Teardown, matching
   today's two separate field reads).
6. **Capture-once at goroutine start** (`daemon_gc.go:22` GC,
   `daemon_ha_userspace_stream.go:67,122` drainer/provider): exactly one
   load at start — preserves today's capture-once semantics deliberately
   (no per-tick re-probe behavior change).
7. **Per-request readers** (REST `PolicySchedulerActiveStateFn`, NAT pool
   sampler closure, health): one load per invocation.
8. **Apply-path readers under `d.applySem`**: same load-once rules; the
   accessor is lock-free and orthogonal to applySem (no lock-ordering
   interaction).
9. **`%T` logging** (`daemon_ha_sync.go:311`): `%T` of the loaded value —
   same output.

### 5.4 Reader audit table (issue requirement #4 — regenerated, exhaustive)

Classes: **W** = writer; **APPLY** = applySem-serialized reader (safe vs the
writer today by mutex — non-locally); **BOOT-SYNC** = Run-goroutine read
before any server can deliver a commit (safe today by program order);
**CONCURRENT** = background/request-goroutine reader — formally
unsynchronized vs a writer (racy today on at least one reachable
interleaving). There is NO "cluster-only safe" class: r1 proved HA readers
can coexist with the writer via compile-failed-bootstrap + rollback
recurrence (§2 RACE-2), and RACE-1 is a plain HA-boot interleaving.

| File:lines (production, `grep -n 'd\.dp\b'` verified) | Context | Class |
|---|---|---|
| `daemon_run_bringup.go` 448,464,469,497 | boot assign/nil | W |
| `daemon_run_naming.go` 234 | bootstrap-exit nil | W |
| `daemon_run_naming.go` 230,236 | exit arm block (nil-check, seeder) | APPLY |
| `daemon_forwarding_status.go` 21,24,36,39,97,100,108,111,124,128 | sampler tick (1 Hz) + adapter construction | CONCURRENT |
| `daemon_run_servers.go` 409,412 | REST `PolicySchedulerActiveStateFn` request | CONCURRENT |
| `daemon_neighbor_listener.go` 304,307,473 | netlink listener/regen goroutines (started at boot when `ActiveConfig() != nil`, `daemon_run.go:518-533` — including the never-committed-restart bootstrap case where the empty tree compiles non-nil) | CONCURRENT |
| `daemon_ha_userspace_stream.go` 67,122,235,259 | event stream/delta goroutines; :122 launched when `d.cluster == nil` (`daemon_run.go:365`) — STANDALONE | CONCURRENT |
| `daemon_natpoolalarm.go` 18,21,101 | monitor sampler + start gate (lifecycle-gated #2116) | CONCURRENT (gated) |
| `daemon_run.go` 312,324 | `er.AddCallback` per-SESSION_OPEN event reads on the event-reader goroutine (registered :288 when `getSessionSync() != nil`) | CONCURRENT |
| `daemon_run.go` 611,612 | CLI probe — AFTER gRPC start (:598); a remote commit can already be in flight | CONCURRENT |
| `daemon_run_servers.go` 117,118,255,256 | gRPC/API construction probes — HTTP started :588, gRPC :598 | CONCURRENT (micro-window) |
| `daemon_run_shutdown.go` 161,167,173,214,219,220,225,229 | shutdown (releases applySem immediately, :50; tolerates surviving apply) | CONCURRENT |
| `daemon_ha_fabric.go` 533,537,554,555,567,570,724,728,750,753 | fabric probe/refresh goroutines | CONCURRENT |
| `daemon_ha_sync.go` 193,299,300,311,733,750,1117,1124,1164,1286 | watchdog/sync/fence/SetRuntime goroutines | CONCURRENT |
| `daemon_ha.go` 297,299,337,348,362,367,542,549,578,583,813,826,1521 | VRRP/RG event watcher, warm cache | CONCURRENT |
| `daemon_ha_userspace_readiness.go` 202,230,233 | takeover-readiness probes | CONCURRENT |
| `daemon_health.go` 141 | standby-neighbor refresh (session-sync trigger, `daemon_ha_sync.go:970`) | CONCURRENT |
| `daemon_apply_dataplane.go` 53,98,122,139,141,293,295,390,393,455,458 | apply path | APPLY |
| `daemon_apply_tail.go` 491,494 | apply path | APPLY |
| `daemon_apply_interfaces.go` 42 | apply path | APPLY |
| `daemon_apply_routing.go` 367 | apply path | APPLY |
| `daemon_scheduler.go` 211,221,224,230,239 | scheduler republish under applySem | APPLY |
| `daemon_ipmon.go` 304 | route-overlay actuate under applySem | APPLY |
| `daemon_policy_invalidate.go` 286,290 | contract: callers hold applySem (:114-116; `daemon_apply_commit.go:270` et al.) | APPLY |
| `daemon_system.go` 41 | applySyslogConfig (apply path) | APPLY |
| `daemon.go` 1012 | `applyResult()` (apply-path caller) | APPLY |
| `bootstrap.go` 472,473 | rollback teardown under applySem | APPLY |
| `daemon_run_bringup.go` 476,477,493,494,506 | boot post-construct reads (same goroutine as W) | BOOT-SYNC |
| `daemon_run.go` 212,223,238,270,354,365,375,384,385 | boot PHASE 3-5 setup, pre-server | BOOT-SYNC |
| `daemon_gc.go` 22 | GC construction capture (boot) | BOOT-SYNC (capture-once) |

Count check: 5 W + ~159 reads above; anything missing from the table is a
plan bug — the /engineer pass regenerates this mechanically at commit time
and the compiler (field retype) proves the conversion total.

### 5.5 Docs contract

- `pkg/daemon/README.md`: add the publication-cell contract to the
  ARCHITECTURE section (:13) — not only the bootstrap bullets; update the
  bootstrap-mode bullet (:556-568) and first-commit rollback bullet
  (:578-585) which currently describe the monitor-only #2116 lifecycle.
- `docs/` sweep: `docs/ha-failover-status.md:279`,
  `docs/ha-no-hitless-restart.md:22`, `docs/rib-group-route-leaking.md:94`
  (at minimum — the /engineer pass greps `docs/` for `d\.dp` and updates or
  explicitly justifies each hit).
- `_Log.md` entries for every implementation edit (CLAUDE.md logging rules).

## 6. Public API preservation

`Daemon` and its field are package-private; nothing outside `pkg/daemon`
references them (`fwdstatus.Sampler.dp`, `grpcapi.Server.dp`, `cli.CLI.dp`
are their OWN boot-captured probes — not the daemon's field; untouched).

Preserved exactly:

- `fwdstatus.DataPlaneAccessor` interface and the sampler-facing
  `Status`/`CachedStatus` method set; sampler rendering and hold-last-values
  behavior on status miss.
- gRPC/CLI `show chassis forwarding` output (their per-request adapters are
  untouched; per-request re-selection against an immutable captured object
  has no type divergence).
- `conntrack.NewGC` receives the same captured value at boot (one accessor
  load at construction).
- `cliDataPlane`/`grpcDataPlane`/`apiDataPlane` boot probe results.
- NAT pool-alarm monitor lifecycle (#2116): gating, rollback discard,
  `show security alarms` behavior.
- NoDataplane mode: cell nil for the daemon lifetime; readers observe
  exactly what `d.dp == nil` yields today.
- `applyResult()`, health endpoint, REST simulator fail-closed `ok=false`
  on absent dataplane (#3414).

## 7. Hidden invariants the change must preserve

1. **Snapshot boundaries per §5.3** — the only way to introduce a NEW bug in
   a mechanical conversion (two loads observing a transition mid-site).
   Reviewer focus point at /engineer code review.
2. **Publication ordering**: boot writers publish via the cell in the same
   program order as today; the cell makes RACE-1's publication atomic
   (reader sees nil or the full slot — never a torn interface).
3. **Capture-once semantics**: GC and event-stream captures keep the object
   grabbed at start across a later nil-ing (same as today). Deliberately
   preserved; swapping them onto a future re-arm is OUT of scope.
4. **applySem orthogonality**: the accessor is lock-free; apply-path
   readers keep existing serialization; no lock-ordering interaction.
5. **#2116 monitor lifecycle**: the sampler closure switches to the
   accessor; gating/discard untouched; the three existing race tests keep
   passing with `writeDPFor` re-pointed at `setDataplane`.
6. **Terminal nil**: after an arm-failure nil-ing, nothing re-publishes a
   backend on current master. The accessor is correct under ANY Store
   sequence; tests assert the observable post-nil state but must not rely
   on terminality for safety.
7. **Typed-nil exclusion**: `setDataplane` rejects typed-nil via the
   reflect guard (§4 A1); the cell never stores a non-nil interface
   wrapping a nil pointer.
8. **Shutdown ordering** (#5807): two snapshot sites per §5.3 rule 5;
   post-nil shutdown skips final stats exactly as today.
9. **Allocation rules**: one `dpSlot` per Store (≤5/lifetime); zero per
   read. Go control plane only; the Rust helper owns packets.
10. **Retirement boundary**: the canary's guarded invariant (daemon holds a
    `dataplane.RuntimeDataPlane`, constructed via `NewRuntimeDataPlane`) is
    preserved semantically through the redesigned matcher (§4 A1).

## 8. Risk assessment

| Class | Rating | Assessment |
|---|---|---|
| Behavioral regression | **MED** | Diff is large but mechanical; compiler-enforced completeness (field retype) plus the regenerated §5.4 table make "missed site" a compile error. Real risks: (a) a snapshot-boundary mistake at a §5.3 site; (b) canary redesign errors turning the gate off unnoticed (mitigation: the redesigned canary must FAIL on a raw `dp dataplane.RuntimeDataPlane` field AND on an unguarded `dpCell` access — assert both directions in the canary's own tests); (c) test-literal migration churn (~110 sites) — mechanical. Gates: full `make test-go`, scoped `-race` target, smoke gates in §9. |
| Lifetime / borrow | **LOW** | Slots immutable after Store; captured references keep backends alive exactly as the plain field did. No FFI/Rust interaction. |
| Performance regression | **LOW** | One atomic load + indirection per read on control-plane paths (1 Hz sampler, request rate, watchdog 2/s, HA loops ≤15/s). One small allocation per Store, ≤5 per lifetime. No per-packet Go code exists. |
| Architectural mismatch | **LOW** | Follows the merged #2116 precedent and the daemon's atomics-for-publication idiom (`natPoolAlarm`, `bootstrapMode`, `policySchedulerEpoch`). Does NOT attempt the lifecycle redesign (Option B) that could dead-end. The canary redesign EXTENDS the existing boundary-guard pattern rather than fighting it. |

## 9. Test plan

1. `go build ./... && go vet ./pkg/daemon/...` — the field retype makes the
   compiler enumerate every conversion site.
2. New `pkg/daemon/daemon_dp_race_test.go` (run under `-race`, `-count=5`
   flake hunt):
   - `TestDataplaneCell_ConcurrentReadersVsWriter` — N goroutines hammer the
     accessor-routed readers (fwdstatus adapter methods, `applyResult()`,
     a `PolicySchedulerActiveStateFn`-shape probe, the NAT pool sampler
     closure, a watchdog-shape per-tick load) while a writer goroutine
     alternates `setDataplane(nil)` / `setDataplane(fake)`. Revert-guard:
     fails under `-race` if the cell reverts to a plain field.
   - `TestForwardingStatus_BackendTypeTransitions` — REVERSED direction per
     r1 (today's wrapper already re-probes, so userspace→nil passes
     pre-fix): start nil (`IsLoaded` false, `GetMapStats` nil,
     `CachedStatus` miss, `Status` error) → `setDataplane(userspaceFake)`
     (all live) → `setDataplane(readyProbeOnlyFake)` (`IsLoaded` true,
     `Status` error, `CachedStatus` miss). Old code fails the
     nil→userspace leg (base wrapper permanently lacks `Status`); new code
     adapts per call.
   - `TestBootstrapExit_ArmFailureWithConcurrentReaders` — drive the REAL
     writer: extract the arm block (`daemon_run_naming.go:228-249`) into
     `armBootstrapExitDataplane(nodeID int)` (Start + seeder +
     `maybeStartNATPoolAlarm` + nil-on-failure) so the test avoids the
     netlink/sysctl takeover steps; inject a `Start`-failing fake; churn
     readers concurrently; assert `-race` clean, `d.dataplane() == nil`,
     monitor not started.
   - `TestDataplaneCell_RollbackRearmRecurrence` — full recurrence with the
     real helpers: successful arm → monitor starts → `enterBootstrapMode`
     (monitor discarded) → corrected re-exit with a failing Start →
     `d.dataplane() == nil`, no monitor, `-race` clean with HA-watchdog-
     shape readers churning throughout.
   - `TestDataplaneCell_ClusterStartPublication` — RACE-1 shape: a watcher-
     shape reader loop racing the boot `setDataplane(dp)` publication;
     asserts readers observe nil-or-full-slot and `-race` stays clean.
3. Update `daemon_natpoolalarm_race_test.go` (`writeDPFor` → `setDataplane`)
   and `daemon_forwarding_status_test.go` (construct via helper;
   `UsesCurrentDataplaneAfterSwap` maps naturally onto per-call probing;
   add the sampler-only comment assertion).
4. Scoped race gate: add a `test-race-dp` make target —
   `go test -race ./pkg/daemon/ -run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit' -count=2`
   — invoked from `test-go` (keeps the pre-commit gate honest; full-repo
   `-race` stays out of scope). Final target name/wiring at /engineer time.
5. Canary tests: the redesigned matcher gets its own unit coverage (accepts
   the new shape, rejects a raw field, rejects unguarded `dpCell` access).
6. Existing suites: `go test ./pkg/daemon/... ./pkg/fwdstatus/...
   ./pkg/cli/... ./pkg/grpcapi/... ./pkg/api/... ./pkg/dataplane/...`; full
   `make test-go`; `make test-rust` untouched but runs via `make test`.
7. Smoke gates (engineering-style.md:93, NOT waivable — r1 Codex MAJOR 7):
   `make test-deploy` + ping on the standalone VM; `make cluster-deploy` +
   iperf3 on the loss userspace cluster; `make test-failover` AND
   `make test-ha-crash` (mechanical `daemon_ha*.go` touches mandate the HA
   gates per CLAUDE.md), all under the #1875/`with-cluster.sh` lock
   discipline.
8. Bootstrap-window coverage stays unit/`-race`-level (no bootstrap
   integration env exists; same as #2116).

## 10. Out of scope (explicitly)

- Option B (write-once `d.dp` / degraded-adapter semantics).
- Swapping capture-once consumers (GC, event stream) to per-tick re-probe.
- `pkg/grpcapi` / `pkg/cli` boot-captured forwarding-status probes (stale
  after a daemon-side transition, never racy — separate consistency
  follow-up if wanted).
- The `apply.go:29` TODO (HA session sync → `SessionDeltas()` migration).
- `pkg/fwdstatus` Sampler/Build internals; any Rust/helper change;
  dataplane hot-swap/re-arm support (the accessor ENABLES it safely later).
- Full-repo `go test -race` wiring.

## 11. Open questions for adversarial review (r2)

Resolved in v2 (for the record): OQ1 (A2 deleted — fork is A1 vs PLAN-KILL),
OQ2 (atomic.Pointer, both external reviewers concur), OQ3 (adapter scoped
sampler-only; Build-equivalence claim withdrawn), OQ5 (policy-invalidate is
APPLY-class, verified), OQ6 (HA smoke gates mandatory, not waived), OQ7
(reflect typed-nil guard adopted), OQ8 (README architecture section + docs/
sweep + `_Log.md` committed).

Still open:

1. **PLAN-KILL fork**: with RACE-1 (HA boot) and RACE-2 (bootstrap-exit)
   both proven structural, does any reviewer still judge the ~270-site
   conversion unjustified? A PLAN-KILL here means accepting both races as
   documented known-issues with only the sampler rebound — state the
   reasoning explicitly if so.
2. The `armBootstrapExitDataplane` extraction (§9.2) splits
   `runBootstrapExitStartup` for testability. Any objection to the helper
   boundary (naming/sysctl stay in the caller; arm+seed+monitor+nil in the
   helper)?
3. The new `dpCell`-access AST canary (§4 A1) — is an in-package AST test
   the accepted enforcement mechanism here (precedent:
   `pkg/dataplane/retirement_boundary_canary_test.go`), or do reviewers
   want a lighter `grep`-based `make` check instead?
4. `test-race-dp` wiring into `test-go` (§9.4): acceptable to grow the
   pre-commit gate by the scoped race run (~tens of seconds), or should it
   be a documented manual gate only?
5. §5.3 rule 6 deliberately preserves capture-once for the GC and event
   stream. Confirm no reviewer requires the re-probe behavior change as
   part of THIS issue.

---

*Review ledger: see `reviewer-ids.md`. Round docs: `claude-smr-plan-r<N>.md`,
`codex-plan-r<N>.md`, `agy-plan-r<N>.md`.*
