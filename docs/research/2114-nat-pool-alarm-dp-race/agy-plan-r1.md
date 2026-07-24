# Adversarial Architecture Review: Go Concurrency Fix (#2114 Residual)

**Target Plan**: [docs/research/2114-nat-pool-alarm-dp-race/plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md)  
**Base Commit**: `ed6999000`

---

## Executive Summary

The proposed architecture (**Option A1**: `atomic.Pointer[dpSlot]` with accessor pair `d.dataplane()` / `d.setDataplane()` and compiler-enforced full field retype) is **architecturally sound, robust, and correctly scoped**. Retyping the package-private field `dp` guarantees compiler-enforced conversion completeness across all 191 reference sites in `pkg/daemon`. 

The review identified one major domain-reasoning flaw in the plan's safety proof (HA node bootstrap reachability) and minor implementation edge cases (typed-nil guards and ticker-loop scoping), but because Option A1 converts *all* reference sites universally, the underlying code implementation remains fully correct.

---

## Major Findings

### 1. Flawed HA Safety Invariant in Plan Analysis
- **File & Line**: [pkg/daemon/bootstrap.go:233-247](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go#L233-L247)
- **Details**: The plan claims (§3, lines 101–103) that `"nodeIDPresent → bootClassNormal, so HA nodes never execute the bootstrap-exit writer."` This is **incorrect**. `computeBootClass` checks `if configCompileFailed { return bootClassBootstrap }` at line 233 *before* evaluating `if nodeIDPresent` at line 246. 
- **Impact**: If an active configuration DB fails to compile after an upgrade or corruption, an HA node (`nodeIDPresent == true`) **will** enter `bootClassBootstrap`. In Phase 5 ([daemon_run.go:578-584](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L578-L584)), background HA goroutines (`watchVRRPEvents`, `reconcileRGStateLoop`) start up. If a valid configuration is subsequently pushed, bootstrap exit executes `runBootstrapExitStartup`. If the dataplane `Start` fails, `enterBootstrapMode` writes `d.dp = nil` at [daemon_run_naming.go:234](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_naming.go#L234) concurrently with the active HA background readers.
- **Architectural Validation**: This finding invalidates Option A2 (racy-set-only) and reinforces why **Option A1 (full ~191-site conversion including `daemon_ha*.go`) is mandatory** for production safety.

---

## Minor Findings

### 1. Scoping Rules for Ticker Loops vs Load-Once Conversions
- **File & Line**: [pkg/daemon/daemon_ha_sync.go:733-756](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go#L733-L756)
- **Details**: In `daemon_ha_sync.go:733`, `if d.dp != nil` guards spawning the HA watchdog ticker goroutine, while line 750 calls `d.dp.HA().SetHAWatchdog(...)` inside the 500ms ticker loop. If the conversion rule mechanically loads `dp := d.dataplane()` *once before* spawning the goroutine, the background loop will permanently hold a reference to the old pre-transition dataplane object.
- **Recommendation**: Conversion rules (§4) must explicitly state that inside long-lived `select/ticker` loops (e.g., watchdog loops, neighbor listeners), `d.dataplane()` must be loaded **per tick inside the loop body** (`if dp := d.dataplane(); dp != nil { ... }`) to properly observe `d.setDataplane(nil)` transitions.

### 2. Typed-Nil Risk in `d.setDataplane()`
- **File & Line**: [pkg/daemon/daemon_run.go:53-60](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L53-L60), [plan.md:144-150](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L144-L150)
- **Details**: `setDataplane(dp)` checks `if dp == nil`. In Go interface semantics, passing a non-nil interface header containing a `nil` concrete pointer evaluates `dp == nil` as `false`. `setDataplane` would execute `d.dpCell.Store(&dpSlot{v: dp})`, storing a typed-nil in the cell. Calls to `d.dataplane()` would return `dp != nil` (true), causing downstream dereference panics when calling interface methods.
- **Recommendation**: While current factory constructors (`dpuserspace.Boot()`, `NewRuntimeDataPlane()`) return interface values directly, `setDataplane` should incorporate an explicit typed-nil check (`if dp == nil || reflect.ValueOf(dp).IsNil()`) or require constructors to return untyped `nil`.

### 3. Inaccurate Table Classification for Session Invalidation Callers
- **File & Line**: [pkg/daemon/daemon_policy_invalidate.go:285-290](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_policy_invalidate.go#L285-L290), [plan.md:300](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L300)
- **Details**: Section 5.4 table classifies `clearSessionsForPolicyIDs` as `A/C — callers vary; (apply + clear request paths)`. Audit of the codebase confirms that **all** production callers (`clearSessionsForDeletedPolicies`, `clearSessionsForModifiedPolicies`, `clearSessionsForDefaultPolicyChange`) are invoked exclusively via `clearSessionsForPolicyChanges` under `d.applySem` in [daemon_apply_commit.go:270, 450, 706](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go#L270). REST/gRPC session clear endpoints call `d.dp.Sessions().Delete...` directly and do not invoke `clearSessionsForPolicyIDs`.

---

## Detailed Check Verification Summary

1. **HA Node Bootstrap Reachability (Q1)**: **Hole identified** (see Major Finding 1). HA nodes can enter bootstrap mode via `configCompileFailed`. Option A1 correctly converts HA readers anyway.
2. **`clearSessionsForPolicyIDs` Callers (Q2)**: **Verified**. All production callers run under `d.applySem` during commit apply.
3. **`atomic.Pointer[dpSlot]` & Compiler Retype (Q3)**: **Verified**. Field retyping guarantees 100% compiler enforcement against missed direct reads. Minor typed-nil note logged.
4. **Forwarding-Status Adapter Collapse Equivalence (Q4)**: **Verified**. Audited [fwdstatus/sampler.go:113-125](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go#L113-L125) and [fwdstatus/builder.go:118-124](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/builder.go#L118-L124). No consumer distinguishes "lacks method" from "returns ok=false/error".
5. **Load-Once Conversions (Q5)**: **Verified**. Straightforward across apply/shutdown paths; explicit per-tick load rule added for long-lived ticker loops.
6. **Test Honesty & Deterministic `-race` Regression (Q6)**: **Verified**. Running `fwdSampler` concurrent with `runBootstrapExitStartup` arm failure fails deterministically on master under `go test -race` and passes cleanly under Option A1.
7. **Option Evaluation (Q7)**: **Verified**. Option A1 (~191 sites) is superior to Option A2 (~40 sites) due to compiler enforcement and HA edge cases. Option B (degraded adapter) is rightly deferred.
8. **Documentation & Test Gates (Q8)**: **Verified**. Commitments for `pkg/daemon/README.md` updates and `make test-failover` (under `#1875` cluster lock discipline) comply with `CLAUDE.md`.

---

VERDICT: PLAN-READY-WITH-NITS
