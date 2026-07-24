# Adversarial Architecture Review: Go Concurrency Fix (#2114 Residual) — ROUND 3

**Target Plan**: [docs/research/2114-nat-pool-alarm-dp-race/plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (REVISED v3 @ commit `f0c1605cd`)  
**Base Commit**: `ed6999000`

---

## (A) Verification of Round-2 AGY Findings

| # | Finding | Status | Verification & Evidence |
|---|---|---|---|
| 1 | **MAJOR**: `reflect.IsNil` panic on non-nillable struct value receivers | **FOLDED** | [plan.md:160-175](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L160-L175) gates `IsNil()` behind `v.Kind() == reflect.Pointer` in `setDataplane()`. Section 9.2 (lines 478–481) specifies `TestDataplaneCell_TypedNilAndValueShapes` covering both typed-nil pointer fakes and value-receiver fakes. (See MINOR 1 for residual non-pointer nillable kind note). |
| 2 | **MINOR 1**: AST canary renderer needs `*ast.IndexExpr` / `*ast.IndexListExpr` for `atomic.Pointer[dpSlot]` | **FOLDED** | [plan.md:192-194](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L192-L194) explicitly mandates extending `canaryExprString` in [pkg/dataplane/retirement_boundary_canary_test.go:3352-3360](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/retirement_boundary_canary_test.go#L3352-L3360) to handle generic index expressions. |
| 3 | **MINOR 2**: Explicit test file name for in-package `dpCell` AST canary | **FOLDED** | [plan.md:196, 300](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L196) explicitly names [pkg/daemon/daemon_dp_canary_test.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_dp_canary_test.go) as the target test file. |

---

## (B) Hostile Re-Attack on v3 Plan Deltas

### 1. Verification of the Structural `fwdstatus` Sampler-Only Delta (Codex M1 Fold)

- **Interface Narrowing & Scope**:
  `fwdstatus.NewSampler` is narrowed to accept `fwdstatus.CachedStatusProvider` ([plan.md:213-220](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L213-L220)). `Sampler.sample()` calls `s.dp.CachedStatus()` directly without per-tick type assertion.
- **Observable Surface Check**:
  Verified via codebase inspection:
  - `pkg/grpcapi/server_show_forwarding.go:22,33-74` constructs its own `forwardingStatusServerDataPlane` adapter for `fwdstatus.Build()`.
  - `pkg/cli/cli_show_chassis.go:60,71-132` constructs its own `forwardingStatusCLIDataPlane` adapter for `fwdstatus.Build()`.
  - The daemon adapter `forwardingStatusDaemonDataPlane` ([pkg/daemon/daemon_forwarding_status.go:12](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go#L12)) has only **one** caller: `d.forwardingStatusDataplane()` at `daemon_run.go:595` for `fwdstatus.NewSampler`.
  Removing `IsLoaded()`, `GetMapStats()`, and `Status()` from the daemon adapter and removing `userspaceDataplaneStatus()` loses zero observable surface while structurally excluding the daemon adapter from `fwdstatus.Build()`.
- **Sampler Behavior (Nil vs Absent Dataplane)**:
  `userspaceDataplaneCachedStatus()` performs per-call type assertion against `d.dataplane()`. When `d.dataplane()` returns `nil` (or a non-userspace backend), `CachedStatus()` returns `(ProcessStatus{}, false)`. The sampler's worker CPU counters hold at previous values monotonically in both cases.

### 2. Verification of the Four-Link Bootstrap / Cluster Mutual Exclusion Proof

- **Link (i)**: Compile-failed boot leaves `d.store.ActiveConfig() == nil` ([pkg/daemon/daemon_run_bringup.go:287](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L287)).
- **Link (ii)**: `d.cluster` is constructed **only** at boot if `d.store.ActiveConfig() != nil` ([pkg/daemon/daemon_run_bringup.go:162-164](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L162-L164)).
- **Link (iii)**: Topology transitions are blocked at commit pre-flight ([pkg/daemon/daemon_apply_commit.go:558](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go#L558)) and peer `SyncApply` returns before `applyConfigLocked` ([pkg/daemon/daemon_apply_commit.go:364-379](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go#L364-L379)).
- **Link (iv)**: `enterBootstrapMode` is reached only on a `nil` rollback target (`prevCfg == nil`) during `PromoteRollback` ([pkg/daemon/daemon_apply_commit.go:651](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go#L651)), which occurs only on fresh un-configured stores where `d.cluster` was `nil` from boot.
- **Proof Integrity**: Verified. HA background readers (`daemon_ha*.go`) require `d.cluster != nil` and are therefore exposed to RACE-1 (boot publication window) but are structurally unreachable during RACE-2 (bootstrap-exit teardown).

### 3. Reader Audit Table Verification (§5.4)

- Untruncated grep over `pkg/daemon/*.go` (pattern `'d\.dp\b|a\.daemon\.dp\b'` excluding `_test.go` and comments) yields **133 total lines**:
  - 5 Writers: `daemon_run_bringup.go:448,464,469,497` and `daemon_run_naming.go:234`.
  - 128 Readers: Exclusively enumerated across 28 files in table §5.4 ([plan.md:354-386](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L354-L386)).
- Total counts match the pre-collected evidence exactly.

---

## Findings

### MAJOR Findings

*None.*

---

### MINOR Findings

#### 1. `setDataplane` typed-nil guard `v.Kind() == reflect.Pointer` omits non-pointer nillable kinds
- **File & Line**: [docs/research/2114-nat-pool-alarm-dp-race/plan.md:170-174](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L170-L174)
- **Details**: The proposed `setDataplane` implementation checks:
  ```go
  if v := reflect.ValueOf(dp); v.Kind() == reflect.Pointer && v.IsNil() {
      d.dpCell.Store(nil)
      return
  }
  ```
  In Go, non-pointer nillable kinds include `Chan`, `Func`, `Map`, `Slice`, and `UnsafePointer`. If a test fake implements `dataplane.RuntimeDataPlane` using a custom map or slice type (e.g. `type mockMapDP map[string]int`), passing a typed-nil `mockMapDP(nil)` will evaluate `v.Kind() == reflect.Pointer` as `false`. `setDataplane` will wrap the typed-nil map inside `dpSlot`, causing `d.dataplane()` to return a non-nil interface containing a nil map.
- **Remediation**: While all current production backends are pointers or struct values, standardizing the check against all reflect nillable kinds ensures completeness:
  ```go
  if dp == nil {
      d.dpCell.Store(nil)
      return
  }
  if v := reflect.ValueOf(dp); isNillableKind(v.Kind()) && v.IsNil() {
      d.dpCell.Store(nil)
      return
  }
  ```
  where `isNillableKind(k)` checks `Chan`, `Func`, `Map`, `Pointer`, `Slice`, `UnsafePointer`.

---

VERDICT: PLAN-READY-WITH-NITS
