# AGY adversarial plan-review — round 90 (plan v92 @ 7eb2e20df0d4)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY ("Blocks PR-1 PLAN-READY: NONE."). Raw output follows verbatim.

---

### Adversarial PLAN Review Verdict: **PLAN-READY**

**Target**: #2114 — Plan v92 @ `7eb2e20df0d4`, branch `research/2114-nat-pool-alarm-dp-race`.  
**Scope**: **PR-1 ONLY** (`followup-seed.md` / G+H+H2 out of scope).  
**Blocks PR-1 PLAN-READY**: **NONE.**

---

### 1. Verification of the Five v92 Folds

| Fold Item | Plan File & Line(s) | Verification & Findings |
|---|---|---|
| **(a) `maps_nat.go:400` in Class 3 & "other required" deletion** | [plan.md:3922](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3922), [5153-5188](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5153-L5188) | `ClearNATRuleCounters` (`maps_nat.go:395`) is explicitly assigned to **Class 3** (pre-error Go-side offset reset side effect). The false claim that mixed methods carry "OTHER required accesses" has been deleted; text now correctly states that `ClearNATRuleCounters`, `ClearZoneCounters`, `SeedNATPortCounters`, `UpdatePolicyScheduleState`, and `SeedSessionIDCounter` each contain **only one** registry access. |
| **(b) Per-site outcome precision** | [plan.md:5091-5099](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5091-L5099) | Correctly specifies master’s **exact per-site behavior**: silent skip, nil-guard return, or skip-and-continue. Explicitly notes that `Compile` (`compiler.go:353`) skips `redirect_capable` population and **continues** execution, while `loader.go:700` (`iface_zone_map`) is a comma-ok early return rather than a generic nil-guard. |
| **(c) §6 & §8 IsLoaded surface pluralization** | [plan.md:4253-4256](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4253-L4256), [4660-4664](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4660-L4664), [4761](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4761) | Both §6 and §8 (plus §7's risk table) explicitly name the externally observable `IsLoaded()` surface ([`loader.go:456`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L456) → REST/gRPC status) alongside the loaded-check set admission narrowing. |
| **(d) Detach oracle seeding `iface_zone_map`** | [plan.md:5270-5285](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5270-L5285) | `TestManager_ArmedGate_DetachRetainedClaims` explicitly requires seeding a usable `iface_zone_map`. Without it, `loader.go:700` returns early (`nil`) under master's no-op behavior before reaching claim discovery at `:711`. |
| **(e) §9 five legs & START-path seam transition** | [plan.md:4885-4916](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4885-L4916), [4984](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4984) | §9 bookkeeping updated to **FIVE legs**. Line 4913 explicitly marks the transition so the in-hold `Store(true)` hook placement applies strictly to the START path, distinct from Leg 5's Close-window post-`Store(false)` hook. |

---

### 2. The Registry Census & Stale Text Sweep

* **Full Census Re-derivation**:
  $$\text{Total Registry Accesses} = 91 \text{ (required)} + 41 \text{ (optional/neutral)} + 3 \text{ (writes)} = 135$$
  - **91 required lookups**: Map/program lookups that return an error signature when absent.
  - **41 optional lookups**: 17 mixed/multi-access sites + 24 single-map neutral sites (e.g., `maps_stale.go` cleanups, `maps_stats.go:72`, `maps_counters.go:181/233`, `maps_nat.go:400`).
  - **3 writes**: Whole-batch population insert loops + `xdpEntryProg` swap section.
* **Stale Text Audit**:
  - `79 required`: **None.** (Line 3539's `~79` refers strictly to `Daemon{dp: ...}` test literals in `pkg/daemon`).
  - `16 sites`: **None active.** Appears only as explicit historical revision context ([plan.md:65, 87, 3376](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L65)) explaining the correction to 17 mixed sites.
  - `four legs`: **None active.** Appears only as explicit historical revision context ([plan.md:20-22, 4887, 4984](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4887)) explaining the update to 5 legs.

---

### 3. Verification of the Five-Leg Oracle Set

The 5-leg test suite in §9 ([plan.md:4885-4916, 5000-5015](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4885-L4916)) forms a mutually consistent and implementable set:

1. **Leg (1) `TestManager_ArmedGate_FreshOutcomes`**: Quiescent fresh state; no overlap. Asserts typed errors / neutral / pinned hybrids / nil per class.
2. **Leg (2) `TestManager_ArmedGate_RetainedOutcomes`**: Quiescent retained state (`loaded=false`, maps present); no overlap. Asserts master-identical execution per class.
3. **Leg (3) `TestManager_ArmedGate_BlockedStart`**: Blocked fresh `Start` hold. Readers block at `m.mu` registry selection during hold, observe `ARMED` after release.
4. **Leg (4) `TestManager_ArmedGate_RetainedReStartOverlap`**: Blocked retained re-`Start` hold on seeded fixture. Same whole-batch blocking & post-release assertion.
5. **Leg (5) `TestManager_ArmedGate_CloseWindowIsLoaded`**: Close-window observability. Hook held after entry `loaded.Store(false)` ([`loader.go:1206`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1206)) and before link-handle teardown. Concurrent `IsLoaded()` reads observe `false` immediately.

**Hook Semantics & Consistency**:
- **START-path hooks (Legs 3 & 4)**: Placed inside `Start`'s whole-batch critical section (`m.mu` held, before `loaded.Store(true)`). Loaded-check entry points (`AttachXDP`, `Compile`) fail fast pre-Store (`loaded==false`) and block at `m.mu` post-Store.
- **CLOSE-path hook (Leg 5)**: Placed inside `Close()` immediately after atomic `loaded.Store(false)`. `IsLoaded()` does not take `m.mu`, avoiding deadlocks while asserting atomic visibility.

---

### 4. Fresh Hostile Attack on PR-1 Claims

* **Class-3 Nesting Safety**: Verified. Composed helper methods like `ClearAllCounters` call raw internal helpers (`clearInterfaceCountersRaw`), preventing public gate re-entry and preserving legacy error text.
* **XDP Entry Prog Atomicity**: Verified. `swapXDPEntryProg` uses a scoped `m.mu` lock section rather than whole-method locking, preventing mutex re-entrancy while guaranteeing atomic program selection.
* **Two-State Gate Carve-Outs**: Verified. Methods with pre-existing loaded checks (`AttachXDP`, `AttachTC`, `CompileConfig`) preserve their master error strings across both fresh and retained states without generating spurious `ErrDataplaneNotArmed` errors.
* **Canary Enforcements**: Structural AST canaries in `pkg/daemon` (`daemon_dp_canary_test.go`) and `pkg/dataplane` ensure no un-isolated `d.dp` or direct `m.maps` lookups bypass the accessors in future commits.

---

### Summary Conclusion

Plan v92 resolves all residual bookkeeping inconsistencies, accurately counts and categorizes the 135 registry accesses, and presents a complete 5-leg test oracle. 

PR-1 is **ready for implementation**. Recommend advancing to `/engineer 2114`.
