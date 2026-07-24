### Executive Summary

This is the **Round 6 Adversarial Architecture Review** of the **v6 revised plan** for xpf issue #2114 (`docs/research/2114-nat-pool-alarm-dp-race/plan.md` at commit `ee270c729`).

The v6 revision introduces **Work Item G** (a startup-readiness gate `d.startupReady` for `executeConfirmedRollback`) to close the pre-existing dispatch-ordering defect uncovered by the RACE-3 audit (where a recovered commit-confirmed timer firing before `initManagers` completes causes a nil-dereference panic on `d.vrrpMgr` or arms the dataplane inside bootstrap mode).

---

### Detailed Review of the v6 Delta

#### 1. Work Item G Design Analysis
* **(a) Aborted/Failed Startup Goroutine Leak (MAJOR FINDING)**:
  The v6 plan (section 4 A1, lines 280-291) specifies that `executeConfirmedRollback` will wait on the gate before taking `d.applySem`:
  ```go
  select {
  case <-d.startupReady:
  case <-d.daemonCtx.Done():
      return
  }
  ```
  **Failure Analysis**: As documented in `pkg/daemon/daemon_run.go:64-83` and `:186-193` (the #5807 architecture), `d.daemonCtx` is the **RAW, signal-uncancelled parent** (production: `context.Background()`) and is **NEVER cancelled** during daemon runtime or shutdown.
  - If daemon startup aborts on a signal (`pkg/daemon/daemon_run.go:822`, `runStartupOrAbort`), `ctx` (the child signal context) is cancelled, but `d.daemonCtx` remains uncancelled.
  - If daemon startup fails with a plain phase error (`pkg/daemon/daemon_run.go:177`), `Run()` returns immediately; `d.daemonCtx` is uncancelled and `runShutdownSequence` is not even called.
  - In both failure/abort cases, `close(d.startupReady)` is **NEVER called**, and `d.daemonCtx.Done()` is **NEVER closed**.
  - If a pending commit-confirmed timer was re-armed in Phase 1 (`store.Load`), when that timer expires, the timer goroutine calling `executeConfirmedRollback` will block on `select` **forever**, permanently leaking the timer goroutine.
  - **Required Fix**: Work Item G must not rely on `d.daemonCtx.Done()`. `Run()` must ensure `d.startupReady` is handled on all exit paths (e.g. closing an explicit `shutdownCtx` / `startupAborted` channel or checking a startup-success state flag), ensuring that an aborted or failed startup allows `executeConfirmedRollback` to abandon without leaking.

* **(b) Pre-startup paths into `applyConfigLocked` / `executeConfirmedRollback`**:
  - The boot apply (`loadAndBootstrapConfig` / `setupDataplaneAndInitialConfig`) runs synchronously on the main `Run()` goroutine holding `d.applySem` during PHASES 1–4. It does not go through `executeConfirmedRollback`.
  - No other background goroutines or HTTP/gRPC handlers issue applies or rollbacks prior to PHASE 5.

* **(c) gRPC Server start vs. Gate Mid-Close**:
  - The gRPC server starts at `daemon_run.go:599` in PHASE 5. Immediately following line 599, PHASE 5 finishes and `close(d.startupReady)` runs before entering PHASE 6.
  - A remote gRPC client issuing `commit confirmed` produces a timer set for seconds or minutes; it cannot fire during the microsecond window between gRPC server start and `startupReady` close.
  - If a recovered timer was already waiting at the gate from PHASE 1, `close(d.startupReady)` unblocks `executeConfirmedRollback` at the end of PHASE 5. At this point, `initManagers` has completed, `d.vrrpMgr` is constructed, and `d.dp` is assigned. Unblocking at this exact boundary is completely safe.

* **(d) Pivoted Test Verification**:
  - Gate test (a), cell revert-guard test (b), and real-path ordering test (c) (§9 item 2) properly pin the gate and prevent regression of both the memory race on `d.dp` and the dispatch panic on `d.vrrpMgr`.

---

#### 2. Four-Link Exclusion & Legacy Records
The argument in section 2 (lines 138-147) regarding legacy confirm records is **sound**:
- A legacy confirm record lacking `GuardedHash` with `prevCfg == nil` represents a first-commit rollback.
- A live `d.cluster` runtime is only created if the active config at boot had `Chassis.Cluster != nil` (`daemon_run_bringup.go:164`).
- An uncommitted node (first commit, `prevCfg == nil`) never has an active cluster config prior to that first commit. Thus, a live `d.cluster` runtime and `prevCfg == nil` can never coexist, preventing reachability to `enterBootstrapMode`.

---

#### 3. Table Preamble, Stream Row, and Citation Spot-Check
- **Table Preamble**: Correctly articulates pre-gate vs. post-gate reachability semantics.
- **Stream `:67` Row**: Correctly categorized as mixed standalone/HA RACE-2 exposure (`daemon_ha_userspace_stream.go:67,259`).
- **Citations Spot-Check**:
  - `:136` -> `daemon_run.go:136` (`d.store.SetRollbackExecutor(d.executeConfirmedRollback)`) — **EXACT**.
  - `:251` -> `store_persist.go:251` (`time.AfterFunc` re-arm) — **EXACT**.
  - `:819` -> `store_commit.go:819` (`exec(gen)`) — **EXACT**.
  - `:311` -> `daemon_ha.go:311` (`removeBlackholeRoutes`) — **EXACT**.

---

#### 4. Open Question 6 Position & Reasoning
**Position: KEEP Work Item G IN THIS PR.**
- **Reasoning**: The RACE-3 scenario is one of the primary race vectors identified in the audit. Fixing the `d.dp` publication cell without fixing the startup gate leaves a known, pre-existing boot panic (`d.vrrpMgr` nil-deref and bootstrap-mode interleave) open on the exact same trigger path. Work Item G is small (~30 LoC + tests), directly resolves this vulnerability, and satisfies issue requirement #4 ("Audit all remaining d.dp background/request readers so this does not become another per-monitor patch").

---

### Findings

#### MAJOR FINDINGS

1. **[pkg/daemon/daemon_run.go:64-83](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L64-L83) | [docs/research/2114-nat-pool-alarm-dp-race/plan.md:280-291](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L280-L291)**
   * **Description**: Work Item G's selection on `d.daemonCtx.Done()` inside `executeConfirmedRollback` is broken because `d.daemonCtx` is the raw, uncancelled parent context (`context.Background()` in production) and is never cancelled. On an aborted startup (`runStartupOrAbort`, `daemon_run.go:822`) or a startup phase error (`daemon_run.go:177`), `d.startupReady` is never closed and `d.daemonCtx` is never cancelled. If a recovered commit-confirmed timer fires on an aborted or failed startup, `executeConfirmedRollback` will block indefinitely on `select`, causing a permanent goroutine leak.
   * **Remedy**: Update the design of Work Item G in `plan.md` section 4 A1 so that `executeConfirmedRollback` selects on a context/channel that is cancelled upon shutdown or startup abort (e.g. `d.applyCancelContext`, a dedicated `shutdownCtx`, or an explicit abort signal), and checks startup success before attempting rollback execution.

#### MINOR FINDINGS

1. **[pkg/dataplane/retirement_boundary_canary_test.go:3352-3360](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/retirement_boundary_canary_test.go#L3352-L3360) | [docs/research/2114-nat-pool-alarm-dp-race/plan.md:248-252](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L248-L252)**
   * **Description**: The AST canary string renderer update in `retirement_boundary_canary_test.go` must explicitly support generic instantiation expressions (`*ast.IndexExpr`) for `atomic.Pointer[dpSlot]`. Ensure both-direction canary self-tests cover this case cleanly so `make test` outputs clear error diagnostics if field syntax deviates.

---

VERDICT: NEEDS-REVISION
