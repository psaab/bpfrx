# Adversarial Architecture Review: Go Concurrency Fix (#2114 Residual) — ROUND 2

**Target Plan**: [docs/research/2114-nat-pool-alarm-dp-race/plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (REVISED v2 @ commit `61568128f`)  
**Base Commit**: `ed6999000`

---

## (A) Verification of Round-1 AGY Findings

| # | Finding | Status | Verification & Evidence |
|---|---|---|---|
| 1 | **MAJOR**: HA node bootstrap reachability (`configCompileFailed` checked before `nodeIDPresent`, [bootstrap.go:233](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go#L233)) | **FOLDED** | Section 3 (lines 110–112) explicitly acknowledges the HA bootstrap reachability correction. Section 5.4 completely eliminates "Class D" (cluster-only safe) and reclassifies all `daemon_ha*.go` background readers as `CONCURRENT`, subjecting them to full conversion under the `d.dataplane()` accessor. |
| 2 | **MINOR 1**: Per-tick load rule for long-lived ticker loops ([daemon_ha_sync.go:733,750](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go#L733-L750)) | **FOLDED** | Section 5.3 Rules 1 & 2 explicitly differentiate spawn-gating loads from per-tick loads inside long-lived ticker loop bodies (`if dp := d.dataplane(); dp != nil`). |
| 3 | **MINOR 2**: Typed-nil risk in `setDataplane` | **FOLDED** | Section 4 A1 (lines 157–165) adds the `reflect.ValueOf(dp).IsNil()` guard to `setDataplane` to prevent storing non-nil interface headers containing nil concrete pointers. |
| 4 | **MINOR 3**: `clearSessionsForPolicyIDs` classification ([daemon_policy_invalidate.go:286](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_policy_invalidate.go#L286)) | **FOLDED** | Section 5.4 table (line 361) reclassifies `clearSessionsForPolicyIDs` as `APPLY`-class, citing the `d.applySem` caller contract. |

---

## (B) Hostile Re-Attack on v2 Plan

### MAJOR Findings

#### 1. Unguarded `reflect.ValueOf(dp).IsNil()` in `setDataplane` panics on concrete struct-value implementations
- **File & Line**: [docs/research/2114-nat-pool-alarm-dp-race/plan.md:158-164](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L158-L164)
- **Details**: The proposed `setDataplane` implementation executes:
  ```go
  if dp == nil || reflect.ValueOf(dp).IsNil() {
      d.dpCell.Store(nil)
      return
  }
  ```
  In Go standard library `reflect` (`reflect/value.go`), calling `IsNil()` on a `reflect.Value` whose `Kind()` is not a `Chan`, `Func`, `Map`, `Pointer`, `UnsafePointer`, or `Interface` causes an immediate runtime panic: `panic: reflect: call of reflect.Value.IsNil on struct Value`.
  If any unit test or test fake implements `dataplane.RuntimeDataPlane` using a value receiver or non-pointer struct (e.g. `type mockDP struct{}`; `d.setDataplane(mockDP{})`), calling `setDataplane` will crash the daemon or test runner.
- **Remediation**: The typed-nil guard must inspect `val.Kind()` before invoking `IsNil()`:
  ```go
  if dp == nil {
      d.dpCell.Store(nil)
      return
  }
  if val := reflect.ValueOf(dp); val.Kind() == reflect.Pointer && val.IsNil() {
      d.dpCell.Store(nil)
      return
  }
  ```

---

### MINOR Findings

#### 1. Canary helper `canaryExprString` requires generic `*ast.IndexExpr` support
- **File & Line**: [pkg/dataplane/retirement_boundary_canary_test.go:3352-3360](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/retirement_boundary_canary_test.go#L3352-L3360), [docs/research/2114-nat-pool-alarm-dp-race/plan.md:173-185](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L173-L185)
- **Details**: Section 4 A1 specifies extending the canary matcher in `retirement_boundary_canary_test.go` to match field `dpCell atomic.Pointer[dpSlot]`. However, the helper `canaryExprString(expr ast.Expr)` currently only handles `*ast.Ident`, `*ast.SelectorExpr`, `*ast.StarExpr`, and `*ast.BasicLit`. Generic type instantiations like `atomic.Pointer[dpSlot]` produce `*ast.IndexExpr` (or `*ast.IndexListExpr`) nodes in the Go AST. Without adding `*ast.IndexExpr` handling to `canaryExprString`, the canary helper will return `""` when evaluating `dpCell`'s field type.
- **Remediation**: Add `*ast.IndexExpr` handling to `canaryExprString` in `pkg/dataplane/retirement_boundary_canary_test.go` during the canary redesign work item.

#### 2. In-package AST canary for `dpCell` needs explicit test file location in `pkg/daemon`
- **File & Line**: [docs/research/2114-nat-pool-alarm-dp-race/plan.md:182-185, 489-495](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L182-L185)
- **Details**: Section 4 A1 proposes a new AST canary in `pkg/daemon` forbidding direct `dpCell.Load()/.Store()` references outside accessor definitions. Section 9 mentions canary unit tests, but does not explicitly name the new test file (e.g., `pkg/daemon/daemon_dp_canary_test.go`).
- **Remediation**: Name `pkg/daemon/daemon_dp_canary_test.go` as the target file for the new AST canary test.

---

## Targeted Adversarial Assessment Questions

1. **Is Option A1 implementable without behavior drift?**  
   **Yes.** Retyping `dp` to `dpCell atomic.Pointer[dpSlot]` forces 100% compiler enforcement across `pkg/daemon`. No `package daemon_test` external test packages exist, and field retyping guarantees all selector expressions (`d.dp.Method()`), assignments (`d.dp = ...`), and struct literals fail compilation until converted to `d.dataplane()` / `d.setDataplane()`.

2. **Is the retirement-canary redesign implementable without gutting protective value?**  
   **Yes.** Extending `assertDaemonDPFieldIsRuntimeDataPlane` to verify `Daemon.dpCell` holds `atomic.Pointer[dpSlot]` and `dpSlot` contains `v dataplane.RuntimeDataPlane` preserves the exact architectural boundary (that `Daemon`'s runtime dataplane interface is `dataplane.RuntimeDataPlane`). The new `pkg/daemon` AST canary prevents package-local accessor bypass.

3. **Is sampler-only scoping of the `fwdstatus` adapter sufficient?**  
   **Yes.** `forwardingStatusDaemonDataPlane` is an unexported type in `pkg/daemon` whose only caller is `fwdstatus.NewSampler(d.forwardingStatusDataplane(), ...)`. `pkg/grpcapi` and `pkg/cli` construct their own adapters for `fwdstatus.Build`. The doc comment and sampler test pinning are sufficient.

4. **Are the smoke gates policy-complete?**  
   **Yes.** Section 9.7 explicitly mandates all four required gates (`make test-deploy` + ping, `make cluster-deploy` + iperf3, `make test-failover`, and `make test-ha-crash`), adhering strictly to `CLAUDE.md` and `docs/engineering-style.md`.

5. **Is there any sixth option better than A1?**  
   **No.** Option A1 remains the superior path for total correctness and compiler-enforced safety.

---

VERDICT: PLAN-READY-WITH-NITS
