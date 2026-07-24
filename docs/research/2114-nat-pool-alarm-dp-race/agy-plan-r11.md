# Adversarial Architecture Review (Round 11 - Convergence Round)

**Target**: [`docs/research/2114-nat-pool-alarm-dp-race/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (v11)  
**Base**: `origin/master` @ `ed6999000`  
**Verdict**: **PLAN-READY**

---

## (A) Verification of v11 Folds

| Delta | Status | Code Evidence & Plan Mapping |
| :--- | :--- | :--- |
| **1. First-statement `stopping.Store(true)`** | **FOLDED** | Master [`daemon_run_shutdown.go:25-36`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_shutdown.go#L25-L36) shows `runShutdownSequence` entering directly into `if d.applyCancel != nil { d.applyCancel() ...`. The plan's placement of `d.stopping.Store(true)` as line 26 (before `applyCancel`) closes the interactive CLI exit window by construction. Plan: lines 89–91, 468–475, 1219–1221, 1358–1360. |
| **2. Pre-migration GuardedHash binding capture** | **FOLDED** | Master [`dataplane_retire.go:215-224`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/dataplane_retire.go#L215-L224) (`isRetiredDataplaneLeaf`) drops retired leaves without an `Inactive` check, and [`store_persist.go:65,74-77`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L65) mutates `tree` before `recoverPendingConfirmLocked` hashes `s.active` at [`store_persist.go:159`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L159). Commit hashes the raw promoted tree at [`store_commit.go:543-549`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L543-L549). Capturing `preMigrationHash = journalConfigHash(tree)` right after [`db.go:400`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L400) / before [`store_persist.go:65`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L65) binds `GuardedHash` to the on-disk tree bytes. Plan: lines 108–118, 653–672, 1010–1011, 1246–1250. |
| **3. Cancellable `applySem.Acquire` in executor** | **FOLDED** | Master [`daemon_apply_commit.go:630`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go#L630) uses uncancellable `_ = d.applySem.Acquire(context.Background(), 1)`. The plan specifies `Acquire(d.runCtxOrBackground(), 1)` with error check to abandon on shutdown signal. Plan: lines 94–98, 438–449, 1213–1215. |
| **4. Nil-safe double guard + wiring & fixture updates** | **FOLDED** | Master [`daemon_run.go:86`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L86) derives signal context. Plan specifies `(d.runCtx != nil && d.runCtx.Err() != nil)`, helper `runCtxOrBackground()`, fixture initialization, and signal-child wiring assertions. Plan: lines 99–102, 461–467, 561–568, 1221–1223. |
| **5. Invariant 11 narrowed claim** | **FOLDED** | Master [`daemon_run_shutdown.go:15,50-58`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_shutdown.go#L15) has `applyCloseoutDrainTimeout = 5s`. The plan explicitly narrows its claim: no admitted body enlargement and no larger worst case, but openly acknowledges the potential shift in overlap likelihood due to gate delay. Plan: lines 103–105, 1073–1087. |
| **6. `bootstrapFromFile` interaction adjudication** | **FOLDED** | Master [`bootstrap.go:77-79,243-245`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go#L77-L79) and [`daemon_run_bringup.go:313-334`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L313-L334) verified. Documented consistency folded with regression test (ix). Plan: lines 119–128, 680–705, 1251–1253. |

---

## (B) Ruling on the `bootstrapFromFile` Adjudication

**ACCEPT**.

**Analysis**:
1. **Parity**: On master today, if a `FirstCommit` record (standalone or cluster) expires while the daemon is offline, `recoverPendingConfirmLocked` ([`store_persist.go:171-227`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L171-L227)) resets `s.active` to an empty tree, sets `s.compiled = nil`, and sets `everCommitted = false`. Bringup then reaches [`daemon_run_bringup.go:313`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L313) where `shouldBootstrapFromFile(false, false)` evaluates to `true`, importing `xpf.conf` if present. Work item H’s revert-at-Load yields the exact same store state (`compiled = nil`, `everCommitted = false`).
2. **Data Source Isolation**: `xpf.conf` is a day-0 seed file. The daemon never writes database state back into `xpf.conf`. Therefore, importing `xpf.conf` imports the day-0 initial configuration, never resurrecting the unconfirmed database delta.
3. **HA Protection**: On an HA node, `/etc/xpf/node-id` is present. In [`bootstrap.go:246-248`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go#L246-L248) (`computeBootClass`), `if nodeIDPresent { return bootClassNormal }`. Thus, an HA node resolves to `bootClassNormal` (never `bootClassBootstrap`), bringing up cluster managers from the imported `xpf.conf`. No bootstrap-with-live-cluster hybrid can arise.

---

## (C) Fresh Attacks Analysis

### 1. Pre-Migration Hash Capture
- **Load-time Mutations**: In [`store_persist.go:22-64`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L22-L64), `s.db.ReadActiveMeta()` parses `active.json` directly into `tree *config.ConfigTree` via [`db.go:377`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L377) (`json.Unmarshal`). No migrations or in-place sanitizations run prior to line 65. Capturing `preMigrationHash = journalConfigHash(tree)` right after line 48 captures the raw on-disk AST hash before any mutation.
- **`SyncApply` Basis**: [`SyncApply`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L634) on a standby node cancels any pending confirm timer ([`store.go:717`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L717)) and resolves/deletes `confirm.json` once `writeActive` succeeds ([`store.go:754`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L754)). If `writeActive` fails, `confirmResolvePendingPersist = true` retains `confirm.json`, which points to the old active config that remains on disk.
- **Round-Trip Equivalence**: Go's standard library `encoding/json` sorts map keys deterministically during `json.MarshalIndent` ([`db.go:436`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L436)). AST formatting via `tree.Format()` sorts child keys deterministically. Thus, `Format(jsonRoundTrip(tree)) == Format(tree)` holds identically.

### 2. First-Statement `Store` on Abort Path
- When a signal interrupts startup, `runStartupOrAbort` ([`daemon_run.go:822-833`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L822-L833)) calls `finishStartup(false)` (or the Run-scoped `defer` fires).
- `finishStartup(false)` sets `startupOK = false` and closes `d.startupDone`.
- Any blocked executor sitting on `<-d.startupDone` unblocks, sees `!startupOK`, logs a warning, and abandons immediately—never attempting `applySem` acquisition or rollback.
- `runStartupOrAbort` then invokes `teardown(err)` (`runShutdownSequence`), which executes its first statement `d.stopping.Store(true)` before `d.applyCancel()`. The ordering `finishStartup(false)` -> `close(startupDone)` -> `runShutdownSequence` -> `stopping.Store(true)` is strictly sequential and race-free.

### 3. Uncancellable Gate Wait (`<-d.startupDone`)
- `d.startupDone` is allocated in the `Daemon` constructor (`daemon.go:1086-1108`).
- `Run()` installs `defer d.finishStartup(false)` on entry. Every exit path out of `Run()`—successful completion at END-of-PHASE-5 (`finishStartup(true)`), plain phase error, signal abort in `runStartupOrAbort`, or unhandled panic—guarantees `d.startupDoneOnce.Do(...)` executes and closes `d.startupDone`.
- All test fixtures constructing `Daemon` directly are specified to initialize `d.startupDone` as already closed. No path leaves `d.startupDone` open after daemon bringup ends.

### 4. Regression Audit Across v11 Edits
- All v11 deltas are mutually consistent: `stopping.Store(true)` as first statement, cancellable `applySem.Acquire(runCtxOrBackground())`, `(d.runCtx != nil && d.runCtx.Err() != nil)` double guard, pre-migration `GuardedHash` capture, and `bootstrapFromFile` documented consistency are aligned across pseudocode, invariants, and test plans.

---

## Verdict

**PLAN-READY**
