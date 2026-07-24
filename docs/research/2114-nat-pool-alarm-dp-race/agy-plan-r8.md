### Adversarial Architecture Review (Round 8)

**Target Plan**: [docs/research/2114-nat-pool-alarm-dp-race/plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (REVISED v8 @ commit `9c2bc5bbd`)

---

### (A) Verification of `finishStartup(ok)` (Double-Close Fold)

**Status**: **VERIFIED & SUFFICIENT**

- **Mechanism**: Work item G (§4 A1, lines 290–307) routes all startup outcome publications through `d.finishStartup(ok bool)`, which guards both `d.startupOK.Store(true)` and `close(d.startupDone)` behind a single `d.startupDoneOnce.Do(...)`.
- **Paths**:
  - **Success**: `finishStartup(true)` called exactly once at the linearization point (END of PHASE 5, after `startGRPCServer` completes).
  - **Failure**: `finishStartup(false)` called from `runStartupOrAbort`'s error/signal handling paths.
- **Analysis**: The `sync.Once` guarantees that even if a failure path and a deferred wrapper or shutdown sequence both trigger `finishStartup`, `close(d.startupDone)` executes at most once. Waiters unblock and read `d.startupOK == true` on success or `false` on failure (triggering clean abandonment without executing a rollback).

---

### (B) Attack on v8 Delta & Verification Jobs

#### 1. Work Item H — Narrow Legacy Recovery Guard
- **Guard Placement & Timing**:
  - `recoverPendingConfirmLocked()` ([pkg/configstore/store_persist.go:136-165](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L136-L165)) is called from `s.Load()` ([store_persist.go:113](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L113)).
  - In bringup ([pkg/daemon/daemon_run_bringup.go:277](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L277)), `s.Load()` runs in **PHASE 1/2**.
  - `initManagers()` ([daemon_run_bringup.go:47-210](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L47-L210)), where `d.cluster` is constructed at line 164 (`d.cluster = cluster.NewManager(...)`), runs in **PHASE 3**.
  - **Verdict**: The guard point is **100% correct**. No cluster-runtime construction can precede it.
- **Semantics (`resolve-as-expired`)**:
  - Rolling back a `FirstCommit` record would revert `s.active` to an empty tree (`&config.ConfigTree{}`) and clear `everCommitted`.
  - For a legacy cross-upgrade record with an active cluster config, rolling back to empty bootstrap would strand a live cluster node in bootstrap mode.
  - Resolving as expired keeps `s.active` (the active cluster config), removes `confirm.json`, logs a loud warning, and skips timer re-arm.
  - **Verdict**: `resolve-as-expired` is the **correct and safe semantics**.
- **`GuardedHash` Bypass Analysis**:
  - In `store_persist.go:159-165`, if `rec.GuardedHash != ""` and mismatches `journalConfigHash(s.active)`, it logs a warning, calls `s.resolveConfirmRemovalLocked("stale_confirm_recovery")`, and returns immediately (removing the record without rollback/re-arm).
  - If `GuardedHash` matches or is empty `""` (legacy record), execution reaches the Work Item H guard (`rec.FirstCommit && recoveredActiveHasCluster(s.active)`).
  - The guard fires, calls `s.resolveConfirmRemovalLocked(...)`, and returns before reaching deadline expiry (line 171) or timer re-arm (line 231).
  - **Verdict**: **No bypass exists**.

#### 2. Gate Tests v8
- **Deterministic Pinning**:
  1. **Entry Hook**: Signalled immediately before `<-d.startupDone`, guaranteeing the executor is suspended at the gate before test contention.
  2. **Dual Failure-Path Coverage**: Tests drive `finishStartup(false)` manually and via both real failure returns in `runStartupOrAbort` (plain phase error + signal abort).
  3. **No-Side-Effects Assertion**: Verifies that while gated, `d.applySem` remains acquirable by other routines and no rollback side effects occur.
  4. **Backend-Factory Seam**: A test-only variable seam for `buildRuntimeDataPlane` prevents unwanted userspace binary instantiation or hardcoded phase-4 overwrites.
  5. **Phase-Level Orchestration**: Drives bringup phases sequentially with a hook between `Load` and `initManagers`.
  6. **Late-Manager Milestone**: Asserts rollback executes post-linearization with late-manager state (`snmpBootReady` / LLDP manager) initialized.
- **Verdict**: The test plan deterministically covers all gate invariants.

#### 3. Linearization at END of PHASE 5 after `startGRPCServer`
- **Remote-Commit Equivalence**:
  - Moving the linearization point to the END of PHASE 5 ensures `startGRPCServer` has returned and all daemon subsystems are fully initialized.
  - Any rollback released past this point executes against a fully operational control plane under `d.applySem`, making its execution state-transition equivalent to a remote commit received over gRPC on first server contact.
- **Verdict**: Claim holds rigorously.

#### 4. v8 Integrity Check
- No new regressions, gaps, or invalid assumptions were introduced in v8.
- Auditor table count (134 executable references: 5 writers + 129 readers) and §5.3 snapshot rules remain consistent and complete.

---

### Findings

#### MAJOR
*None.*

#### MINOR
*None.*

---

VERDICT: PLAN-READY
