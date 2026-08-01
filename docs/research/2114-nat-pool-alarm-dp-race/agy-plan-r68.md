# AGY adversarial plan-review — round 68 (plan v69 @ ee70003a3)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes; attempt 1 from the launch cwd hit the headless command-permission auto-deny, attempt 2 from the trusted workspace succeeded). Verdict: PLAN-READY (extraction fidelity confirmed; 6 verification areas walked; no findings; explicit 'NO' to the PR-1-blocking question). Raw output follows verbatim.

---

# Adversarial Plan Review: #2114 — Round 68 (CONVERGENCE)

**Plan Document**: [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (v69 @ `ee70003a3`)  
**Follow-up Seed**: [`followup-seed.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md)  
**Branch**: `research/2114-nat-pool-alarm-dp-race`  

---

## Verdict: **PLAN-READY**

**Does anything in PR-1 block PLAN-READY for #2114?**  
**NO.** The PR-1 scope defined in [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) is complete, self-contained, mathematically sound at the memory-ordering level, and free of smuggled follow-up dependencies. It closes the memory-ordering data races (RACE-1, RACE-2, RACE-3) across all 134 production sites in `pkg/daemon` and introduces zero regressions or worsening of pre-existing hazards.

---

## Hostile Verification & Evidence

### 0. Extraction Fidelity Verification
- **(a) PR-1 Load-Bearing Content Integrity**: Checked [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md). All load-bearing PR-1 content remains intact in the plan after the v69 extraction:
  - **Types & Accessors**: `dpSlot`, `dpCell atomic.Pointer[dpSlot]`, `dataplane()`, `setDataplane()` (§5.1).
  - **Writer Sites**: 5 explicit writer sites (§5.2).
  - **Snapshot Rules**: 9 normative per-site snapshot boundary rules (§5.3).
  - **Reader Audit**: Untruncated 134-row audit table (5 writers + 129 readers, §5.4).
  - **Canary Requirements**: Dual AST canary design (retire boundary extension + `pkg/daemon` access pin, §5.1).
  - **Core Test Suite**: 8 core test specifications, `-race` harness `test-race-dp`, and non-waivable deployment/failover smoke gates (§9).
- **(b) Follow-up Dependency Smuggling Check**:
  - **RACE-1 (Watcher chain)**: Memory ordering closed by `dpCell` acquire-release loads. Safe without G/H/H2.
  - **RACE-2 (Bootstrap-exit arm failure)**: `d.setDataplane(nil)` under `d.applySem` eliminates torn interface reads for concurrent readers. Safe without G/H/H2.
  - **RACE-3 (Recovered confirm timer)**: `dpCell` atomic access eliminates multiword interface torn reads when apply pipeline reads `d.dp` concurrently with boot writes.
  - **Pre-existing Hazard Comparison**: Every hazard addressed by G/H/H2 (dispatch ordering, `vrrpMgr` nil-deref on early timer, cross-upgrade topology hybrid recurrence, confirm-record durability) is pre-existing on `origin/master`. PR-1 does not worsen any of these hazards or introduce new window exposures.

---

### 1. The Atomic Publication Cell & Memory Ordering
- **Cell Structure**: `dpCell atomic.Pointer[dpSlot]` holding immutable `dpSlot{v dataplane.RuntimeDataPlane}`. Zero allocation per read, $\le 5$ allocations per daemon lifetime.
- **Kind-Gated Typed-Nil Guard**:
  ```go
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
  ```
  - **Soundness**: Prevents `reflect.ValueOf(dp).IsNil()` from panicking on struct/value types (which panic if `IsNil()` is called without gating `Kind()`), while preventing non-nil interface wrappers around typed nil pointers/slices/maps/chans/funcs from entering the cell.
- **Memory Ordering Sufficiency**: Go's `atomic.Pointer.Store` (release store) and `atomic.Pointer.Load` (acquire load) establish a synchronized-before edge. Concurrent readers executing `d.dataplane()` receive either `nil` or a fully initialized `dpSlot.v`. Multiword interface tearing is impossible.

---

### 2. Writer Conversion Completeness & Snapshot Boundaries (§5.2 / §5.3)
- **5 Writer Sites (Verified against codebase)**:
  1. [`daemon_run_bringup.go:448`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L448) (DPDK retired): `d.setDataplane(nil)`
  2. [`daemon_run_bringup.go:464`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L464) (eBPF retired): `d.setDataplane(nil)`
  3. [`daemon_run_bringup.go:469`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L469) (construct): `d.setDataplane(dp)`
  4. [`daemon_run_bringup.go:497`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L497) (Start fail): `d.setDataplane(nil)`
  5. [`daemon_run_naming.go:234`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_naming.go#L234) (bootstrap-exit arm fail): `d.setDataplane(nil)`
- **Snapshot Boundaries (§5.3)**: Rules 1–9 dictate assigning `dp := d.dataplane()` to a local variable once per operation/tick/invocation prior to nil-checking or calling methods. This prevents double-load TOCTOU nil-dereference bugs across all reader patterns.

---

### 3. Reader Audit & Compiler Enforcement (§5.4)
- **Reference Count**: Exactly 134 production references (5 writers + 129 readers) in `pkg/daemon/*.go` (excluding `_test.go`).
- **Compiler Totality Claim**: Retyping [`Daemon.dp`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon.go#L73) to `dpCell` breaks any direct `d.dp` reference across the workspace at compile time. Verified: zero use of `unsafe` or `reflect` for field offset access to `d.dp` exists in `pkg/daemon`.

---

### 4. `CachedStatusProvider` Narrowing & `pkg/fwdstatus` Adapter
- **Interface & Adapter**:
  - `pkg/fwdstatus` introduces `CachedStatusProvider` (`CachedStatus() (userspace.ProcessStatus, bool)`).
  - `forwardingStatusDaemonDataPlane` in [`daemon_forwarding_status.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go#L108) collapses to a single method implementing `CachedStatusProvider`.
- **Structural Exclusion from `Build()`**: [`fwdstatus.Build`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/builder.go#L118-L123) checks `dp.(interface { Status() (userspace.ProcessStatus, error) })`. Because the collapsed daemon adapter does not have `Status()`, `IsLoaded()`, or `GetMapStats()`, it does not satisfy `fwdstatus.DataPlaneAccessor` and cannot be misrouted into `Build()`.
- **Deletion & Test Inventory**: Retains `userspaceCachedStatusProbe`; removes `var _ DataPlaneAccessor` assertion, `forwardingStatusDaemonUserspaceDataPlane` wrapper, and `userspaceStatusProbe` interface; includes a negative type assertion unit test.

---

### 5. Canary Pair Verification
1. **Retirement Boundary Canary Matcher**: [`pkg/dataplane/retirement_boundary_canary_test.go:1711`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/retirement_boundary_canary_test.go#L1711) (`canaryExprString`) extended to parse `*ast.IndexExpr` / `*ast.IndexListExpr` for `atomic.Pointer[dpSlot]`.
2. **Access AST Canary**: New `pkg/daemon/daemon_dp_canary_test.go` checks that no file in `pkg/daemon` reads or writes `.dpCell` directly outside `dataplane()`, `setDataplane()`, and the field declaration.
3. **Bi-directional Self-Test**: Tests assert failure if raw `d.dp` is restored OR if direct `dpCell` access is attempted.

---

### 6. Public API & Hidden Invariants (§6 / §7)
- **API Surface**: `Daemon.dp` is package-private. The only public signature change is [`fwdstatus.NewSampler`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go#L57) taking `CachedStatusProvider`, which has only 1 production caller ([`daemon_run.go:595`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L595)) and 2 test callers in `sampler_test.go`.
- **Hidden Invariants**: All 11 PR-1 hidden invariants (§7) are strictly preserved (snapshot boundaries, publication atomicity, capture-once semantics, `applySem` orthogonality, `#2116` monitor lifecycle, typed-nil guard, allocation bounds, and boundary canary).

---

## Conclusion

PR-1 is fully specified, self-contained, and ready for implementation via `/engineer 2114`. No blocking findings remain against the PR-1 verdict surface.
