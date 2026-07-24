### Job (A): Verification of Fold of Round 6 Findings

#### 1. MAJOR Fold Verification (Gate Redesign for Rollback Executor)
- **Code Inspection**: Checked [pkg/daemon/daemon_run.go:60-200](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L60-L200) and [pkg/daemon/daemon_run.go:780-840](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L780-L840).
- **Can any startup-exit path leave the waiter blocked forever?**
  - **No.** `startupDone` is constructor-initialized before executor registration at `daemon_run.go:136`. A deferred close registered at the start of `Run()` guarantees `startupDone` is closed regardless of whether startup succeeds, returns an error from `runStartupOrAbort` (`daemon_run.go:176-178`), or aborts via signal.
- **Can any path authorize a rollback against partial initialization?**
  - **No.** `startupOK` (atomic.Bool) defaults to `false`. It is stored `true` strictly at the linearization point after the last manager initialization (`daemon_run.go:435-511`) and before server exposure (`:587`/`:599`). On any startup-exit path prior to that point, `startupOK` remains `false`. When `executeConfirmedRollback` unblocks from `<-d.startupDone`, `!d.startupOK.Load()` triggers an immediate log warning and abandon without attempting rollback.
- **Can the gate deadlock the boot apply (which holds `applySem`)?**
  - **No.** `executeConfirmedRollback` evaluates `<-d.startupDone` **before** attempting `d.applySem.Lock()`. While startup is in progress, the boot apply holds `applySem`, and the rollback executor goroutine blocks on `<-d.startupDone` without taking `applySem`. No lock inversion or deadlock can occur.

#### 2. MINOR Fold Verification (Canary Renderer `IndexExpr` + Self-Tests)
- **Status**: **Verified.** Section 4 A1 (lines 251–272) and Section 9.5 explicitly require:
  1. Extending AST renderer `canaryExprString` to support `*ast.IndexExpr`/`*ast.IndexListExpr` for `atomic.Pointer[dpSlot]`.
  2. Adding new AST canary `pkg/daemon/daemon_dp_canary_test.go` forbidding raw `.dpCell` access.
  3. Writing unit coverage for the canary that asserts failures in **both directions** (raw `dp` field and unguarded `.dpCell` access).

---

### Job (B): Fresh Attack on v7 Delta & Open Questions

#### 1. Cross-Upgrade Coexistence Fold
- **Assessment**: **Safe to defer.** 
- **Evidence**: The atomic cell `dpCell` (`atomic.Pointer[dpSlot]`) converts all 129 read sites across `pkg/daemon` to load atomically via `d.dataplane()`. Even if legacy store state (`FirstCommit=true` + cluster config; [store_commit.go:458-461](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L458-L461), [store_persist.go:149-159](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L149-L159)) results in `d.cluster != nil` during `enterBootstrapMode`, any concurrent read from cluster background loops yields either a valid `RuntimeDataPlane` reference or `nil` without interface tearing or data races.
- The coexistence behavior is a pre-existing configstore recovery policy issue. Deferring behavior-level hardening to a follow-up issue is safe for PR #2114.

#### 2. Gate Tests & New Implementation Nit

##### Test Coverage:
- Test (a) pins gate blocking before `applySem`, abandonment on `startupOK == false`, and execution on `startupOK == true`.
- Test (c) uses a deterministic phase-hook seam (post-`Load`/pre-`initManagers`) to prove zero dispatch during paused startup and orderly dispatch after the linearization point.

##### MINOR Implementation Nit (Channel Double-Close Risk):
- **Location**: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:310-322`
- **Issue**: The plan specifies calling `close(d.startupDone)` explicitly at the success linearization point AND calling `close(d.startupDone)` in a `defer` registered at `Run()` entry.
- **Risk**: In Go, calling `close()` on an already closed channel panics. If `Run()` completes successfully (closing `startupDone` at line ~585) and the daemon subsequently shuts down, `Run()` returning will trigger the deferred close, causing a `panic: close of closed channel`.
- **Fix**: The plan should explicitly mandate using `sync.Once` (`d.startupDoneOnce.Do(func() { close(d.startupDone) })`) or an idempotent helper method (e.g. `d.finishStartup(ok bool)`) to wrap the channel close.

#### 3. Open Question Positions
- **OQ6 (Commit Structure)**: **Separate prerequisite commit in the same PR stack.** (Recommended). Separating Work Item G (dispatch-ordering gate for rollback executor) into a prerequisite commit before the `dpCell` atomic retype keeps git history clean, simplifies code review, and isolates bisectability.
- **OQ7 (Legacy Hardening Split)**: **Approve follow-up split.** Legacy recovery policy for pre-guard records should be tracked in a dedicated follow-up issue.

---

VERDICT: PLAN-READY-WITH-NITS
