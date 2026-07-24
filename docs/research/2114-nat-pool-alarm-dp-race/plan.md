# #2114 (residual): publish `d.dp` through one synchronized accessor — plan-of-action

- **Status**: DRAFT v4 — r3 findings folded (Codex NEEDS-REVISION 3M/3m; AGY
  PLAN-READY-WITH-NITS 0M/1m, all r2 findings FOLDED; Claude SMR
  NEEDS-REVISION 1B/2M/2m); pending convergence review r4
- **Issue**: psaab/xpf#2114 (OPEN; `bug`, `audit`)
- **Branch**: `research/2114-nat-pool-alarm-dp-race` (plan docs only — NO
  production code in `/research`)
- **Base**: origin/master @ `ed6999000`
- **Mode**: `/research` — stops at PLAN-READY. Implementation requires manual
  `/engineer 2114`.
- **Revision history**: v1 @ `1d62be758` (initial). v2 @ `61568128f` (r1:
  deleted false invariants, deleted A2, canary redesign, sampler-only scope,
  snapshot boundaries, table regeneration). v3 @ `f0c1605cd` (r2: kind-gated
  typed-nil, four-link exclusion, STRUCTURAL sampler-only via
  `CachedStatusProvider`, real-sampler barrier, untruncated table). v4: r3
  convergence — corrected the real-sampler barrier so it no longer
  happens-before-orders the conflicting accesses (two-sided gate;
  cancel+quiesce teardown); exact reference count 134 = 5 writers + 129
  readers with per-row classification fixes; RACE-1 scoped to the
  pre-publication watcher chain only; typed-nil kind-gate broadened to all
  nillable kinds; Option D rejection restated honestly; comment sweep
  extended.

---

## 1. Issue framing

#2114 originally reported that the #2079 NAT pool-utilization-alarm monitor
(PR #2109) ran a 10 s sampler goroutine reading the daemon's `d.dp` interface
field with no synchronization, racing the bootstrap-exit `d.dp = nil` write on
a dataplane-arm failure. PR #2116 (merged) closed the *narrow* monitor race
(`atomic.Pointer` monitor, `!inBootstrap()` gating, rollback discard, `-race`
tests).

The issue remains OPEN on the Paladin-audit **residual**: the field `d.dp
dataplane.RuntimeDataPlane` (`pkg/daemon/daemon.go:73`) is a plain interface
field with **5 writers** and **129 read sites** in `pkg/daemon` (134
non-comment greppable references total — exact enumeration in §5.4), most
of them unsynchronized or synchronized only by non-local reasoning. Required closeout (verbatim):

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

- **Eliminates a real data race on a multiword Go interface value** on two
  structurally distinct, reviewer-verified interleavings:
  - **RACE-1 (HA boot publication — no bootstrap needed, WATCHER-CHAIN
    ONLY)**: `initManagers` starts the cluster event watcher
    (`daemon_run_bringup.go:203`; the election inside `UpdateConfig` at :181
    can synchronously enqueue the initial transition) BEFORE
    `setupDataplaneAndInitialConfig` assigns `d.dp` (:448/:469/:497). The
    watcher's event-handler chain reads `d.dp` at
    `daemon_ha.go:297,299,337,348,362,367` with no happens-before edge to
    the assignment. **Scope note (r3)**: this is the ONLY pre-publication
    reader chain — every other HA goroutine (`startClusterComms`
    `daemon_run.go:396`, VRRP watcher :578, reconcile :582, session sync
    `daemon_ha_sync.go:790`) starts AFTER publication and is
    goroutine-start HB-safe against the boot writer.
  - **RACE-2 (bootstrap-exit arm failure — standalone/bootstrap nodes)**:
    `runBootstrapExitStartup` writes `d.dp = nil`
    (`daemon_run_naming.go:234`) on the apply goroutine under `d.applySem`
    while the 1 Hz forwarding-status sampler, the standalone userspace
    event stream (`daemon_ha_userspace_stream.go:122`, launched when
    `d.cluster == nil` at `daemon_run.go:365`), the REST simulator probe
    (`daemon_run_servers.go:409-417`), the neighbor listener
    (`daemon_neighbor_listener.go:303-310,469-476`), and shutdown
    (`daemon_run_shutdown.go:161,214`, which releases applySem immediately
    at :50) read `d.dp` unsynchronized.
  A torn `(type, data)` read can panic the daemon process (fatal on a
  firewall) or yield an inconsistent type assertion.
- **Bootstrap/cluster mutual exclusion — the PRECISE invariant (r2 B2)**:
  HA background readers cannot coexist with the RACE-2 writer, but NOT for
  the naive reason (v1 claimed `nodeIDPresent ⇒ no bootstrap`, false —
  `computeBootClass` checks `configCompileFailed` first, `bootstrap.go:233`,
  so compile-failed HA nodes DO bootstrap). The real exclusion is four-link:
  (i) compile-failed boot ⇒ `ActiveConfig() == nil`
  (`daemon_run_bringup.go:287`); (ii) `d.cluster` is constructed EXACTLY
  ONCE, at boot, only from a non-nil active cluster config
  (`daemon_run_bringup.go:164`, documented `cluster_topology_preflight.go:117`);
  (iii) standalone↔cluster topology transitions are rejected at commit
  (`daemon_apply_commit.go:551-557` `clusterTopologyCommitPreflight`) and a
  peer SyncApply that would transition returns BEFORE `applyConfigLocked`
  (`daemon_apply_commit.go:364-379`); (iv) `enterBootstrapMode` fires only
  for a nil rollback target (`daemon_apply_commit.go:650-652`), which cannot
  follow a config that had a live cluster runtime. HA readers are therefore
  RACE-2-unreachable, and only the watcher chain is RACE-1-reachable; the
  remaining HA readers are converted for UNIFORMITY (issue requirement #1:
  one mechanism for every reader and writer), not because a live race
  reaches them today.
- **Converts non-local safety arguments into local ones.** r1/r2 review
  proved two of the plan's own non-local arguments false as stated. One
  publication mechanism makes each of the 128 read sites locally correct
  and keeps it correct when the next runtime writer appears.
- **Cost**: ~134 production references + ~110 test sites (32 selector-style
  + ~79 `Daemon{dp: ...}` keyed literals) in `pkg/daemon`; 3 files in
  `pkg/fwdstatus`; the field is package-private, zero references outside
  `pkg/daemon`. No Rust/helper/FFI changes; no packet-path changes.

*If reviewers conclude the race windows are too narrow to justify the churn,
PLAN-KILL is an acceptable verdict.*

## 3. What's already shipped / partially batched

- **PR #2116 (merged)** — the narrow monitor fix: `d.natPoolAlarm
  atomic.Pointer[natpoolalarm.Monitor]`, lifecycle helpers
  (`daemon_natpoolalarm.go:100-129`), `!inBootstrap()` gating, rollback
  stop+discard (`bootstrap.go:334`), `SetTickForTest` seam, three `-race`
  tests. Composed with, not replaced by, this plan.
- **eBPF/DPDK retirements (#1476/#1527)** — one live backend type
  (`*dpuserspace.LegacyDataPlaneAdapter`, plus test fakes). The only live
  `d.dp` transition on master is `non-nil → nil` (terminal — nothing
  re-constructs the backend; `buildRuntimeDataPlane` has exactly one caller,
  `daemon_run_bringup.go:421`).
- **#1922 bootstrap mode + #5840 topology preflight** — the RACE-2 writer
  context and the four-link exclusion above.
- **#5868** — `enterBootstrapMode` best-effort rollback; keeps the dataplane
  object (`bootstrap.go:472-475`).
- **`runtime_probes.go` probe-interface idiom** — preserved by the accessor
  shape.
- **#3970 `CachedStatus`** — the sampler's only dataplane call; no
  control-socket rate change.

## 4. Multiple path options (explicit)

### Option A1 (RECOMMENDED): atomic publication cell + uniform accessor, compiler-enforced full conversion

Replace `dp dataplane.RuntimeDataPlane` (`daemon.go:73`) with an atomic cell
and route **all** references through one accessor pair. The field's *type*
changes, so every direct `d.dp` read/write fails to compile — conversion
completeness is compiler-enforced (old selectors, aliases, keyed literals,
embedding, method values; external packages cannot name the unexported
field). r2 verification (Codex): no `package daemon_test` bypasses, no
reflective/unsafe field lookup, no alternate receiver alias, no production
method-value capture exists.

```go
// daemon.go — #2114: single synchronized publication point for the runtime
// dataplane. nil cell == no dataplane (NoDataplane mode, create failure, or
// an arm-failure teardown). The slot is immutable once stored.
type dpSlot struct{ v dataplane.RuntimeDataPlane }

dpCell atomic.Pointer[dpSlot]

// dataplane returns the currently published runtime dataplane, or nil.
// One atomic load; safe from any goroutine. Callers that nil-check AND use
// the value must load ONCE into a local (§5.3 snapshot boundaries).
func (d *Daemon) dataplane() dataplane.RuntimeDataPlane {
    if s := d.dpCell.Load(); s != nil {
        return s.v
    }
    return nil
}

// setDataplane publishes dp (nil clears). The kind-gated typed-nil check
// keeps a non-nil interface wrapping a nil value out of the cell WITHOUT
// panicking on non-nillable kinds (r2: reflect.IsNil panics on struct
// values) and WITHOUT missing non-pointer nillable kinds (r3: named
// Chan/Func/Map/Slice types can have methods — in-repo precedent
// pkg/dataplane/userspace/wire_uint8list.go:32). RuntimeDataPlane has no
// pointer-only constraint and the registry (pkg/dataplane/dataplane.go:152,
// 215) returns arbitrary constructor results unchecked.
func (d *Daemon) setDataplane(dp dataplane.RuntimeDataPlane) {
    if dp == nil {
        d.dpCell.Store(nil)
        return
    }
    v := reflect.ValueOf(dp)
    switch v.Kind() {
    case reflect.Chan, reflect.Func, reflect.Map,
        reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
        if v.IsNil() {
            d.dpCell.Store(nil)
            return
        }
    }
    d.dpCell.Store(&dpSlot{v: dp})
}
```

Why `atomic.Pointer[dpSlot]`, not `atomic.Value`: `Store(nil)` panics and
mixed concrete types panic; the cell must hold "interface or absent". One
allocation per Store (≤5 per daemon lifetime), zero per read; matches the
#2116 precedent.

**Canary redesign (explicit work item)**: the retype breaks
`TestDaemonRuntimeEntryPointUsesRuntimeDataPlane`
(`pkg/dataplane/retirement_boundary_canary_test.go:1711`, helper
:3314-3348), which requires a Daemon field NAMED `dp` of AST type exactly
`dataplane.RuntimeDataPlane`. The /engineer pass must:
  1. extend the matcher to accept the new shape — field
     `dpCell atomic.Pointer[dpSlot]` AND a `dpSlot` struct whose `v` field is
     `dataplane.RuntimeDataPlane`. `atomic.Pointer[dpSlot]` parses as
     `*ast.IndexExpr` (generic instantiation), which the canary's
     `canaryExprString` renderer (:3352-3360) does not yet handle — add
     `*ast.IndexExpr`/`*ast.IndexListExpr` support (r2 AGY MINOR 1). The
     guarded boundary is preserved semantically: the daemon's dataplane IS a
     `RuntimeDataPlane`, now published atomically.
  2. add a NEW AST canary in `pkg/daemon/daemon_dp_canary_test.go` (named
     per r2 AGY MINOR 2) forbidding direct `dpCell` /
     `.dpCell.Load()/.Store()` references outside the accessor definitions
     and the field declaration — a future package-local bypass then fails
     `make test-go`.
  3. give the redesigned canary its own unit coverage: it must FAIL on a
     raw `dp dataplane.RuntimeDataPlane` field AND on an unguarded `dpCell`
     access (both directions asserted).

**fwdstatus adapter: STRUCTURALLY sampler-only (r2 M1 — Codex's structural
argument adopted over AGY's comment-level one, per this repo's
compile-time-invariant discipline).** The sampler only ever calls
`CachedStatus` (`sampler.go:113-125`); `fwdstatus.DataPlaneAccessor`
requires only `IsLoaded`+`GetMapStats` (`builder.go:35-41`); `Build` keys
backend identity on `Status()` PRESENCE (`builder.go:116-123`) and maps a
Status error to `StateUnknown` (:219). Therefore:

- `pkg/fwdstatus` gains
  `type CachedStatusProvider interface { CachedStatus() (userspace.ProcessStatus, bool) }`;
  `NewSampler` takes it (was `DataPlaneAccessor`); `Sampler.dp` retypes;
  `sample()` calls `s.dp.CachedStatus()` directly (the per-tick type
  assertion at :113 is deleted). 3 files touched: `sampler.go`,
  `sampler_test.go` (the `countingAccessor` fake already has
  `CachedStatus`), and the daemon adapter file. `Build` untouched.
- The daemon adapter collapses to a SINGLE method, probing the CURRENT
  dataplane per call:

```go
// forwardingStatusDaemonDataPlane is the daemon's sampler-only dataplane
// adapter (#2114). It deliberately does NOT satisfy
// fwdstatus.DataPlaneAccessor and has no Status method: Build keys backend
// identity on Status() presence (builder.go:116-123), so this type can
// never be misrouted into a Build path.
type forwardingStatusDaemonDataPlane struct{ daemon *Daemon }

func (a forwardingStatusDaemonDataPlane) CachedStatus() (dpuserspace.ProcessStatus, bool) {
    if a.daemon == nil {
        return dpuserspace.ProcessStatus{}, false
    }
    return a.daemon.userspaceDataplaneCachedStatus() // one d.dataplane() load; userspaceCachedStatusProbe
}
```

- `forwardingStatusDataplane()` now returns `fwdstatus.CachedStatusProvider`
  (nil iff `d.opts.NoDataplane`); `IsLoaded`/`GetMapStats`/`Status` leave
  the daemon adapter (verified: no production callers — the gRPC/CLI Build
  paths construct their OWN adapters per request from boot-captured probes,
  `server_show_forwarding.go:21-22`, `cli_show_chassis.go:59-60`, and are
  untouched); the now-dead `userspaceDataplaneStatus()` helper is removed;
  `userspaceDataplaneCachedStatus()` is retained.

### Option B: eliminate the writer (write-once `d.dp` + degraded adapter)

REJECTED: its "write once before goroutines" premise is already false
(RACE-1); it re-audits every `d.dp == nil` check for nil-vs-degraded
semantics; it changes config-only-mode apply behavior
(`daemon_apply_dataplane.go:139` — blackhole-relevant); it leaves the
unsynchronized-read pattern latent for any future writer.

### Option C: `sync.RWMutex`-guarded accessor

Viable (an accessor that copies under RLock and unlocks before returning
cannot deadlock — r1 correction stands). Not chosen: #2116 `atomic.Pointer`
precedent, cheaper reads, hold-nothing-by-construction.

### Option D: immutable owner + atomic presence flag (r1 addition, REJECTED)

Write-once `dpOwner` + `atomic.Bool dpPresent`; arm failure clears only the
flag. It cleanly represents never-constructed (`owner == nil && !present`)
vs cleared (`owner != nil && !present`), and the immutable owner RETAINS
identity for post-clear introspection (`%T` logging, shutdown final stats)
— a genuine advantage over A1's nil-slot (which discards identity on clear).
Rejected on its real weaknesses: (a) two-word state requires every reader
to follow a flag-then-load ordering discipline with zero compiler help (A1
makes the correct read the only read; D would need its own canary to be
enforced); (b) the write-once premise forbids backend REPLACEMENT by
construction — a future hot-swap/re-arm with a fresh object cannot be
expressed, whereas A1 republishes trivially; (c) it deviates from the
merged #2116 `atomic.Pointer` precedent. A1 carries identity+presence in
ONE atomic word and is the simpler invariant to hold.

### Option E: per-consumer lifecycle gating

REJECTED: the per-monitor patch pattern issue requirement #4 rules out;
cannot cover request-goroutine readers.

### The honest fork

**A1 as specified, or PLAN-KILL** (accept both races as documented
known-issues and rebind only the sampler per transition — fails issue
requirements #1/#4 and leaves RACE-1 open). v1's A2 (raw field + cell
coexistence) is deleted as incoherent (r1 B3).

## 5. Concrete design (A1)

### 5.1 New/changed types

- `pkg/daemon/daemon.go`: `dpSlot`, `dpCell atomic.Pointer[dpSlot]`
  replacing `dp`; `dataplane()` / `setDataplane()` (kind-gated); field doc
  comment mirroring the `natPoolAlarm` contract (`daemon.go:211-223`).
- `pkg/daemon/daemon_forwarding_status.go`: single-method sampler-only
  adapter (§4 A1); `userspaceDataplaneStatus()` removed;
  `userspaceCachedStatusProbe` retained; `forwardingStatusDataplane()`
  returns `fwdstatus.CachedStatusProvider`, nil iff `d.opts.NoDataplane`.
- `pkg/fwdstatus/sampler.go`: `CachedStatusProvider` interface; `NewSampler`
  + `Sampler.dp` retyped; `sample()` direct call.
- `pkg/dataplane/retirement_boundary_canary_test.go`: matcher extension
  (incl. `*ast.IndexExpr` renderer support).
- `pkg/daemon/daemon_dp_canary_test.go` (new): dpCell-access AST canary.
- No other package touched. `pkg/grpcapi`, `pkg/cli`, `pkg/api` untouched.

### 5.2 Writer conversion (5 sites — complete, both reviewers verified)

| Site | Context | After |
|---|---|---|
| `daemon_run_bringup.go:448` (DPDK retired) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_bringup.go:464` (eBPF retired) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_bringup.go:469` (construct) | boot, Run goroutine — RACE-1 window | `d.setDataplane(dp)` |
| `daemon_run_bringup.go:497` (Start fail) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_naming.go:234` (bootstrap-exit arm fail) | apply goroutine, `d.applySem` — RACE-2 | `d.setDataplane(nil)` |

### 5.3 Per-site snapshot boundaries (normative conversion rules)

1. **Per-tick loop readers** (HA watchdog `daemon_ha_sync.go:750`,
   reconcile loops, neighbor listener): ONE load per tick/iteration before
   any per-element loop (watchdog: one load shared across the RG loop — not
   per-RG, not a lifetime capture).
2. **Spawn-gated loops** (`daemon_ha_sync.go:733`): gate check is one load;
   the loop body loads per tick per rule 1.
3. **Multi-use straight-line sites** (`daemon_run_naming.go:230-248`): ONE
   local for nil-check + `Start` + seeding; `setDataplane(nil)` only on the
   failure branch.
4. **Two-assertion sites** (`daemon_neighbor_listener.go:469-476`):
   provider and `indexEnumerator` derive from ONE load.
5. **Snapshot-per-operation** (fence `daemon_ha_sync.go:1286,1297`,
   `warmNeighborCache` `daemon_ha.go:1521-1545`, shutdown
   `daemon_run_shutdown.go:161-173` and :214-229 — one snapshot for the
   HA-clear block, a SECOND for final-stats+Close/Teardown, matching
   today's two separate reads).
6. **Capture-once at goroutine start** (`daemon_gc.go:22`,
   `daemon_ha_userspace_stream.go:67,122,235,259`): exactly one load at
   start — preserves today's semantics deliberately.
7. **Per-request readers** (REST `PolicySchedulerActiveStateFn`, NAT pool
   sampler closure, health): one load per invocation.
8. **Apply-path readers under `d.applySem`**: same load-once rules; the
   accessor is lock-free, orthogonal to applySem.
9. **`%T` logging** (`daemon_ha_sync.go:311`): `%T` of the loaded value —
   same output.

### 5.4 Reader audit table (issue requirement #4 — untruncated, exact)

**134 executable production references** (163 greppable lines over
`pkg/daemon/*.go` minus `_test.go` matching `'d\.dp\b|a\.daemon\.dp\b'`,
minus 29 full-line comments): **5 writers + 129 readers**. Classes:
**W** = writer; **APPLY** = applySem-serialized reader; **BOOT-SYNC** =
Run-goroutine read before any server can deliver a commit; **CONCURRENT** =
background/request-goroutine reader. Reachability: RACE-2 reaches only
standalone/bootstrap consumers (§2 four-link exclusion); RACE-1 reaches
ONLY the pre-publication watcher chain (§2 scope note). Everything else is
converted for uniformity, not reachability. The compiler (field retype)
proves the conversion total; this table is the classification snapshot.

| File:lines | Context | Class | RACE exposure |
|---|---|---|---|
| `daemon_run_bringup.go` 448,464,469,497 | boot writes | W | — |
| `daemon_run_naming.go` 234 | bootstrap-exit write | W | — |
| `daemon_forwarding_status.go` 108,111,124,128 | sampler tick (`CachedStatus`) + adapter construction | CONCURRENT | RACE-2 (sampler) |
| `daemon_forwarding_status.go` 21,24,36,39,97,100 | `IsLoaded`/`GetMapStats`/`Status` methods — DELETED by the narrowing, not converted | — | — |
| `daemon_run_servers.go` 409,412 | REST simulator probe | CONCURRENT | RACE-2 |
| `daemon_neighbor_listener.go` 304,307,473 | netlink listener/regen (started when `ActiveConfig() != nil` at boot, `daemon_run.go:518-533` — incl. never-committed-restart bootstrap) | CONCURRENT | RACE-2 |
| `daemon_ha_userspace_stream.go` 67,122,235,259 | event stream/delta; launched when `d.cluster == nil` (`daemon_run.go:365`) — STANDALONE; :67,122 capture-once at start, :235,259 per-call | CONCURRENT | RACE-2 |
| `daemon_natpoolalarm.go` 18,21 | monitor sampler goroutine (#2116 lifecycle-gated) | CONCURRENT (gated) | gated off by lifecycle |
| `daemon_natpoolalarm.go` 101 | start gate (boot block + `runBootstrapExitStartup` under applySem) | APPLY/BOOT-SYNC | serialized |
| `daemon_run.go` 312,324 | `er.AddCallback` per-SESSION_OPEN reads (registered :288 iff `getSessionSync() != nil`, post-publication) | CONCURRENT | unreachable-by-writer (uniformity) |
| `daemon_run.go` 611,612 | CLI probe after gRPC start (:598) | CONCURRENT | RACE-2 (micro-window) |
| `daemon_run_servers.go` 117,118 | gRPC construction probes (HTTP already serving) | CONCURRENT | RACE-2 (micro-window) |
| `daemon_run_servers.go` 255,256 | API construction probes (before HTTP serving starts) | BOOT-SYNC | program order |
| `daemon_run_shutdown.go` 161,167,173 | HA-only rg_active clear (requires cluster config) | CONCURRENT | unreachable via exclusion (uniformity) |
| `daemon_run_shutdown.go` 214,219,220,225,229 | final stats / Close / Teardown (applySem released at :50) | CONCURRENT | RACE-2 |
| `daemon_ha_fabric.go` 533,537,554,555,567,570,724,728,750,753 | fabric probe/refresh goroutines (post-publication start) | CONCURRENT | uniformity |
| `daemon_ha_sync.go` 193,299,300,311,733,750,1117,1124,1164,1165,1286,1297 | watchdog/sync/fence/SetRuntime goroutines (post-publication start) | CONCURRENT | uniformity |
| `daemon_ha.go` 297,299,337,348,362,367 | `watchClusterEvents` handler chain (started `daemon_run_bringup.go:203`, PRE-publication) | CONCURRENT | **RACE-1** |
| `daemon_ha.go` 542,549,578,583 | `watchVRRPEvents` (:511-604, post-publication) | CONCURRENT | uniformity |
| `daemon_ha.go` 813,826,842 | `reconcileRGState` (:707+, post-publication) | CONCURRENT | uniformity |
| `daemon_ha.go` 1521,1531,1545 | `warmNeighborCache` (:1520, failover paths, post-publication) | CONCURRENT | uniformity |
| `daemon_ha_userspace_readiness.go` 202,230,233 | takeover-readiness probes (post-publication) | CONCURRENT | uniformity |
| `daemon_health.go` 141 | standby-neighbor refresh (session-sync trigger, `daemon_ha_sync.go:970`, post-publication) | CONCURRENT | uniformity |
| `daemon_apply_dataplane.go` 53,98,122,139,141,293,295,390,393,397,455,459,463,482,485,497,501,505 | apply path (incl. `reapplyAfterDeferredMAC`, `recordDataplaneWorkerArmDebt`) | APPLY | serialized |
| `daemon_apply_tail.go` 491,494 | apply path | APPLY | serialized |
| `daemon_apply_interfaces.go` 42 | apply path | APPLY | serialized |
| `daemon_apply_routing.go` 367 | apply path | APPLY | serialized |
| `daemon_scheduler.go` 211,221,224,230,239 | scheduler republish under applySem | APPLY | serialized |
| `daemon_ipmon.go` 304 | route-overlay actuate under applySem | APPLY | serialized |
| `daemon_policy_invalidate.go` 286,290 | callers hold applySem (:114-116; `daemon_apply_commit.go:270`) | APPLY | serialized |
| `daemon_system.go` 41 | applySyslogConfig (boot-time and apply-path callers) | APPLY/BOOT-SYNC | serialized |
| `daemon.go` 1012 | `applyResult()` (boot-time and apply-path callers) | APPLY/BOOT-SYNC | serialized |
| `bootstrap.go` 472,473 | rollback teardown under applySem | APPLY | serialized |
| `daemon_run_naming.go` 230,231,236 | exit arm block (nil-check, Start, seeder) | APPLY | serialized (writer site) |
| `daemon_run_bringup.go` 476,477,493,494,506 | boot post-construct reads (same goroutine as W) | BOOT-SYNC | program order |
| `daemon_run.go` 212,223,238,270,354,365 | boot PHASE 3-5 setup, pre-server | BOOT-SYNC | program order |
| `daemon_gc.go` 22 | GC construction capture (boot) | BOOT-SYNC (capture-once) | program order |

### 5.5 Docs contract

- `pkg/daemon/README.md`: publication-cell contract in the ARCHITECTURE
  section (:13); update the bootstrap-mode bullet (:556-568), the
  first-commit rollback bullet (:578-585), AND the live
  `d.dp.ApplyConfig` reference (:936) (r2 Codex MINOR 3).
- Source comments contradicting the rollback recurrence get reworded in
  the same PR: `daemon_run_naming.go:200-206` ("one-way ... at most once"),
  `bootstrap.go:284-289` ("one-way for the daemon's lifetime"),
  `daemon_apply.go:213-220` ("Exit is one-way"), plus the r3 additions
  `daemon.go:901`, `bootstrap.go:276` ("written once at startup and at most
  once more"), `bootstrap.go:303` ("re-suppress takeover for the daemon's
  lifetime"), and `cluster_topology_preflight.go:117`'s stale
  `daemon_run.go:1868` cite (now `daemon_run_bringup.go:164`) — the
  recurrence (exit → `enterBootstrapMode` → re-exit) is real and now
  tested; the comments must say "one-way per bootstrap episode; rollback
  can re-enter" (r2 Codex MINOR 3, r3 Codex MINOR 3).
- `docs/` sweep: `docs/ha-failover-status.md:279`,
  `docs/ha-no-hitless-restart.md:22`, `docs/rib-group-route-leaking.md:94`
  (the /engineer pass greps `docs/` for `d\.dp` and updates or justifies
  each hit).
- `_Log.md` entries for every implementation edit (CLAUDE.md).

## 6. Public API preservation

`Daemon` and its field are package-private; nothing outside `pkg/daemon`
references them.

**Intentional signature change (the only one)**: `fwdstatus.NewSampler`
takes `CachedStatusProvider` instead of `DataPlaneAccessor` (r2 M1).
Callers: exactly one production (`daemon_run.go:595`) + two test sites
(`sampler_test.go:69,106`); the test fake already satisfies the narrow
interface. `DataPlaneAccessor`/`Build`/`Format` are unchanged for their
real consumers (grpcapi/cli adapters).

Preserved exactly:

- gRPC/CLI `show chassis forwarding` output (their per-request adapters
  untouched; no type divergence against an immutable captured object).
- Sampler behavior: worker counters hold-last on `ok=false` (unchanged code
  path, now a direct call instead of an assertion).
- `conntrack.NewGC` capture at boot; boot probe results
  (`cliDataPlane`/`grpcDataPlane`/`apiDataPlane`).
- NAT pool-alarm monitor lifecycle (#2116) and `show security alarms`.
- NoDataplane mode: cell nil for the daemon lifetime.
- `applyResult()`, health endpoint, REST simulator fail-closed `ok=false`
  (#3414).

## 7. Hidden invariants the change must preserve

1. **Snapshot boundaries per §5.3** — the one way to introduce a NEW bug in
   a mechanical conversion.
2. **Publication atomicity (RACE-1)**: boot writers publish via the cell in
   the same program order; readers see nil or the full slot — never a torn
   interface.
3. **Capture-once semantics**: GC/event-stream captures keep the object
   grabbed at start (same as today). Deliberately preserved.
4. **applySem orthogonality**: lock-free accessor; no lock-ordering
   interaction with the "Locked" conventions.
5. **#2116 monitor lifecycle**: sampler closure switches to the accessor;
   gating/discard untouched; existing race tests re-point `writeDPFor` at
   `setDataplane`.
6. **Terminal nil**: nothing re-publishes a backend on current master; the
   accessor is correct under ANY Store sequence; tests assert observable
   post-nil state without relying on terminality for safety.
7. **Typed-nil exclusion without panic**: kind-gated guard over ALL
   nillable kinds (§4 A1); a value-type implementation Stores normally; a
   typed-nil of any nillable kind (pointer, named slice/map/chan/func)
   Stores as nil. All shapes covered by unit tests (r2 B1, r3 m1).
8. **Shutdown ordering** (#5807): two snapshots per §5.3 rule 5; post-nil
   shutdown skips final stats exactly as today.
9. **Allocation rules**: one `dpSlot` per Store (≤5/lifetime); zero per
   read. Go control plane only.
10. **Retirement boundary**: the canary's invariant (daemon holds a
    `dataplane.RuntimeDataPlane` built by `NewRuntimeDataPlane`) preserved
    through the redesigned matcher; both-direction canary self-tests (§4).

## 8. Risk assessment

| Class | Rating | Assessment |
|---|---|---|
| Behavioral regression | **MED** | Large but mechanical diff; compiler-enforced completeness + regenerated §5.4 table + the new dpCell canary. Real risks: (a) a §5.3 snapshot-boundary mistake; (b) canary redesign errors (mitigated by both-direction self-tests); (c) the fwdstatus narrowing touching `NewSampler` (contained: 1 prod caller + 2 test sites; full-suite gate). |
| Lifetime / borrow | **LOW** | Immutable slots; captured references keep backends alive exactly as today. No FFI/Rust interaction. |
| Performance regression | **LOW** | One atomic load + indirection per control-plane read (1 Hz sampler, request rate, watchdog 2/s, HA ≤15/s). One small allocation per Store, ≤5/lifetime. No per-packet Go code. |
| Architectural mismatch | **LOW** | #2116 `atomic.Pointer` precedent; daemon atomics-for-publication idiom; no lifecycle redesign (Option B rejected); canary redesign extends the existing boundary-guard pattern. |

## 9. Test plan

1. `go build ./... && go vet ./pkg/daemon/... ./pkg/fwdstatus/...` — the
   field retype makes the compiler enumerate every conversion site.
2. New `pkg/daemon/daemon_dp_race_test.go` (under `-race`, `-count=5`):
   - `TestDataplaneCell_ConcurrentReadersVsWriter` — N goroutines hammer
     accessor-routed readers (narrowed adapter `CachedStatus`,
     `applyResult()`, a `PolicySchedulerActiveStateFn`-shape probe, the NAT
     pool sampler closure, a watchdog-shape per-tick load) while a writer
     alternates `setDataplane(nil)` / `setDataplane(fake)`. Revert-guard.
   - `TestDataplaneCell_TypedNilAndValueShapes` (r2 B1, r3 broadened) — a
     typed-nil pointer fake Stores as nil (`d.dataplane() == nil`); a
     value-receiver fake Stores normally (no panic, non-nil read); a
     typed-nil named-slice fake (methods on a named slice type, per the
     `wire_uint8list.go:32` precedent) Stores as nil.
   - `TestForwardingStatusAdapter_BackendTypeTransitions` — start
     `readyProbeOnlyFake` (adapter `CachedStatus` ok=false) →
     `setDataplane(userspaceFake)` (ok=true, injected status) →
     `setDataplane(nil)` (ok=false). Proves per-call capability adaptation;
     the OLD construction-time wrapper selection (base wrapper permanently
     lacking `CachedStatus`, or nil accessor when nil-at-construction,
     `daemon_forwarding_status.go:123-125`) cannot express the middle leg.
   - `TestBootstrapExit_ArmFailureWithConcurrentReaders` — REAL writer via
     the extracted `armBootstrapExitDataplane(nodeID int)` helper
     (Start + seeder + `maybeStartNATPoolAlarm` + nil-on-failure, split
     from `runBootstrapExitStartup` so the test avoids the netlink/sysctl
     takeover steps); failing-Start fake; churn readers; assert `-race`
     clean, `d.dataplane() == nil`, monitor not started.
   - `TestBootstrapExit_RealSamplerOverlap` (r2 M2, r3 B1 — the barrier
     must NOT happens-before-order the conflicting accesses): the adapter's
     `CachedStatus` loads `d.dataplane()` BEFORE invoking the provider, so
     a gate inside the provider's `CachedStatus` would serialize
     `read(d.dp) → entered → writer`, keeping even the pre-fix plain field
     race-clean (silent green). The gate must therefore sit BEFORE the
     `d.dp` access on BOTH sides with NO channel between the two
     conflicting accesses:
     - Reader side: the fake `ProcReader.ReadSelfStat` (which
       `Sampler.sample()` calls before touching the adapter,
       `sampler.go:93`) signals `readerEntered` and blocks on a shared
       `release` channel. `go fwdSampler.Start(ctx)` — `Start` MUST run on
       its own goroutine because its prime sample is synchronous
       (`sampler.go:64-67`).
     - Writer side: the failing fake dataplane's `Start()` signals
       `writerEntered` and blocks on the SAME `release` before returning
       its error (the `setDataplane(nil)` store happens after `Start`
       returns in `armBootstrapExitDataplane`).
     - Test: wait for BOTH `readerEntered` and `writerEntered`, then
       `close(release)`. The adapter's `d.dp` load and the writer's store
       now proceed with no happens-before edge between them: on the plain
       field the race detector fires (only the ABSENCE of an HB edge is
       required — deterministic as a memory-model proposition, not a
       timing one); on the atomic cell it is clean.
     - Teardown: the sampler loop exposes no join handle (`Start` returns
       nothing) — `cancel(ctx)` and quiesce-poll the fake `ReadSelfStat`
       call counter until it stops increasing, instead of joining.
   - `TestDataplaneCell_RollbackRearmRecurrence` — real helpers: successful
     arm → monitor starts → `enterBootstrapMode` (discarded) → re-exit with
     failing Start → `d.dataplane() == nil`, no monitor, `-race` clean with
     watchdog-shape readers churning.
   - `TestDataplaneCell_ClusterStartPublication` — RACE-1 shape:
     watcher-shape reader loop racing the boot `setDataplane(dp)`
     publication; nil-or-full-slot assertion; `-race` clean.
3. Update `daemon_natpoolalarm_race_test.go` (`writeDPFor` →
   `setDataplane`) and `daemon_forwarding_status_test.go` (rewrite against
   the narrowed adapter: `ProjectsMapStats`/`UsesUserspaceStatusAdapter`
   move to asserting `CachedStatus` per-call probing;
   `UsesCurrentDataplaneAfterSwap` maps onto the narrowed shape with
   `setDataplane` swaps).
4. Scoped race gate: new `test-race-dp` make target —
   `go test -race ./pkg/daemon/ -run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit' -count=2`
   — invoked from `test-go` (r1/r2: plain `go test ./...` has no race
   teeth; full-repo `-race` stays out of scope).
5. Canary tests: redesigned matcher self-tests both directions; new
   `daemon_dp_canary_test.go` asserts no direct `dpCell` access outside the
   accessors.
6. `make test` explicitly (Go + Rust legs), plus the full Go suite.
7. Smoke gates (engineering-style.md:93-103 — NOT waivable; r2 Codex M6
   specifics folded):
   - `make test-deploy` on the standalone VM + ping with **0% loss**.
   - `make cluster-deploy` on the loss userspace cluster, then RE-APPLY CoS
     (`./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` — deploy
     wipes CoS, engineering-style.md:422), then `iperf3 -P 16 -t 30 -p 5203`
     to `172.16.80.200` with **≥23 Gbit/s, no regression** vs the pre-change
     baseline.
   - `make test-failover` AND `make test-ha-crash` (mechanical
     `daemon_ha*.go` touches mandate both per CLAUDE.md), with explicit
     HA loss/convergence criteria recorded in the PR (failover <1s traffic
     loss, cluster reconverges, no stale dataplane state) — all under the
     #1875/`with-cluster.sh` lock discipline.
8. Bootstrap-window coverage stays unit/`-race`-level (no bootstrap
   integration env; same as #2116).

## 10. Out of scope (explicitly)

- Option B (write-once `d.dp` / degraded-adapter semantics).
- Swapping capture-once consumers (GC, event stream) to per-tick re-probe.
- `pkg/grpcapi` / `pkg/cli` boot-captured forwarding-status probes (stale
  after a daemon-side transition, never racy — separate consistency
  follow-up if wanted).
- The `apply.go:29` TODO (HA session sync → `SessionDeltas()` migration).
- `pkg/fwdstatus` `Build`/`Format` internals (the ONLY fwdstatus change is
  the `CachedStatusProvider` narrowing in `sampler.go` + its test).
- Any Rust/helper change; dataplane hot-swap/re-arm support (the accessor
  ENABLES it safely later).
- Full-repo `go test -race` wiring.

## 11. Open questions for adversarial review (r4)

Resolved in v2/v3/v4 (for the record): A2 deletion; atomic cell choice;
sampler-only adapter — now STRUCTURAL via `CachedStatusProvider`;
policy-invalidate APPLY-class; HA smoke gates mandatory + specific;
typed-nil kind-gated guard over all nillable kinds; docs scope (README
architecture + :936 + docs/ sweep + stale comments + `_Log.md`); audit
table completeness AND exact count (134 = 5 + 129); deterministic
real-sampler barrier redesigned as a two-sided gate that cannot
happens-before-order the conflicting accesses; four-link bootstrap/cluster
exclusion; RACE-1 scoped to the pre-publication watcher chain.

Still open:

1. **PLAN-KILL fork**: with RACE-1 and RACE-2 both proven structural, does
   any reviewer still judge the ~244-site conversion (134 prod + ~110 test)
   unjustified? A PLAN-KILL here means accepting both races as documented
   known-issues — state the reasoning explicitly if so.
2. The `CachedStatusProvider` narrowing (§4 A1) is the one intentional
   public-signature change (`fwdstatus.NewSampler`). Any objection, or an
   alternative that keeps the adapter structurally excluded from `Build`
   without touching `pkg/fwdstatus`?
3. The `armBootstrapExitDataplane` extraction splits
   `runBootstrapExitStartup` for testability. Any objection to the helper
   boundary (naming/sysctl stay in the caller; arm+seed+monitor+nil in the
   helper)?
4. The new `dpCell`-access AST canary in `pkg/daemon` — accepted
   enforcement mechanism (precedent: the retirement canary), or do
   reviewers want a lighter `grep`-based `make` check instead?
5. `test-race-dp` wiring into `test-go`: acceptable growth of the
   pre-commit gate, or documented-manual-gate only?

---

*Review ledger: see `reviewer-ids.md`. Round docs: `claude-smr-plan-r<N>.md`,
`codex-plan-r<N>.md`, `agy-plan-r<N>.md`.*
