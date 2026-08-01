# AGY adversarial plan-review — round 74 (plan v75 @ e42b3429c)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (locked-helper scheme verified; Swap assignment verified; the VlanSubInterfaces adjudication explicitly ACCEPTED as 'fully valid and sufficient'; DetachXDP mixed classification verified; the XDP test seam robust). Raw output follows verbatim.

---

### PR-1 Plan Review for #2114 — Round 74 (CONVERGENCE)

**Target Plan**: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` (DRAFT v75 @ `e42b3429c`)  
**Scope**: PR-1 ONLY (`d.dp` accessor core + A3 admission gate + site conversions + canaries + sampler narrowing).  

---

### Hostile Verification of PR-1 Plan Points

#### 1. Locked-Helper Scheme (`xdpEntryProgramLocked()`)
* **Verification & Audit**:
  * On master, `m.xdpEntryProg` is defined at [`loader.go:47`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L47), initialized at [`loader.go:97`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L97), read at [`loader.go:106,109`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L106-L109), written at [`loader.go:115`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L115), written at [`loader.go:154`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L154), written at [`loader.go:632`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L632), and read in status logging at [`maps_sync.go:481`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go#L481).
  * In v74, having `UsingUserspaceXDPShimEntryProgram()` lock `m.mu` caused a **deadlock** because it called public `XDPEntryProgram()`, which also locked `m.mu` (`sync.Mutex` is non-reentrant).
  * In v75, the raw helper `xdpEntryProgramLocked()` reads the field without locking. Public `XDPEntryProgram()` locks `m.mu` once and calls the helper. `UsingUserspaceXDPShimEntryProgram()` locks `m.mu` once and directly calls `xdpEntryProgramLocked() == userspaceShimEntryProg` (never calling `XDPEntryProgram()`).
  * In `swapXDPEntryProg`, line [`:632`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L632) `m.xdpEntryProg = name` is placed inside a tightly scoped `m.mu.Lock()`/`m.mu.Unlock()` block, leaving the netlink link update loop unlocked.
  * **Finding**: Complete coverage of all 7 access points. **No deadlock, no recursion, and zero uncovered accesses.**

#### 2. `SwapToUserspaceXDPShimEntryProgram` Assignment
* **Verification & Audit**:
  * [`loader.go:604`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L604) delegates to `m.swapXDPEntryProg(userspaceShimEntryProg)`.
  * [`loader.go:609`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L609) performs `prog, ok := m.programs[name]`.
  * Before `Start()` completes, `m.programs` is uninitialized/nil.
  * Assigning `SwapToUserspaceXDPShimEntryProgram` to **Class 1** causes it to check `m.loaded.Load()`. When `false`, it returns `ErrDataplaneNotArmed` instead of failing with the pre-arm `"XDP program %q not found"` error.
  * **Finding**: Perfectly conforms to the Class 1 contract.

#### 3. Explicit Adjudication on `VlanSubInterfaces` Disposition
* **RULING**: **ACCEPTED** (Residual with named #1 cheap-follow-up candidate is **fully valid and sufficient**).
* **Rationale & Proof**:
  * **Scope Alignment**: Work item A3 (L2 claim) is strictly defined as method-level admission safety during the **pre-arm / `Start()` window** (between `d.dp = mgr` and `mgr.Start()` completing).
  * **Empirical Scoping**: `VlanSubInterfaces` is initialized at `New()` and is **never written during `Start()`** (which only delegates to `Load()` at [`manager.go:370`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/manager.go#L370)). It is written only during `Compile()` at [`compiler.go:441`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L441) / [`loader.go:201`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L201).
  * The 1 Hz status loop reading `VlanSubInterfaces` at [`maps_sync.go:950`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go#L950) is started at [`manager_compile.go:399`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/manager_compile.go#L399) **only after a successful `Compile()`**.
  * Therefore, `VlanSubInterfaces` has **zero overlap with the `Start()` window**. It is a post-arm `Compile()` vs status-loop race, outside A3's scope.
  * By contrast, the `xdpEntryProg` trio is written inside `Start()` at [`loader.go:154`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L154), which is why it belongs in A3.
  * **Sufficiency**: Full inventory completed (`loader.go:201`, `compiler.go:441` vs `loader.go:622`, `maps_sync.go:950`), documented in §10, and explicitly named as candidate #1 (one-field `m.mu` guard) in the follow-up issue filed at `/engineer` time.

#### 4. `DetachXDP` Mixed Classification
* **Verification & Audit**:
  * [`loader.go:640-642`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L640-L642): `l, exists := m.xdpLinks[ifindex]; if !exists { return nil }`. On an unarmed manager, `m.xdpLinks` is empty; absent-link returning `nil` is **Category G**.
  * [`loader.go:650`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L650): Non-empty path delegates to `m.setXDPAttachedFlag(ifindex, false)`, which reads `m.maps["iface_zone_map"]` ([`:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700)) and `m.maps["vlan_iface_map"]` ([`:730`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730)).
  * The delegation target is classified as a **Class 2 internal**: on `loaded == false` (e.g., during re-arm), it takes the no-map `nil` return path, matching master's "No iface_zone_map yet" behavior.
  * **Finding**: Correctly handles both fresh-unarmed and re-arm states with dedicated test coverage.

#### 5. Dedicated XDP Test Seam (`:154` Barrier)
* **Verification & Audit**:
  * During real `Start()`, `m.xdpEntryProg = userspaceShimEntryProg` is written at [`loader.go:154`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L154).
  * A post-population barrier alone would fire after line `:154` was already executed, masking potential unsynchronized access bugs.
  * The synthetic loader's two-sided entered/resume barrier placed around line `:154` forces concurrent getters (`XDPEntryProgram`, `UsingUserspaceXDPShimEntryProgram`) and `swapXDPEntryProg` ([`:632`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L632)) to execute across line `:154` under `go test -race`.
  * **Finding**: Robust test seam design that effectively validates data-race freedom.

#### 6. Hostile Attack on Remaining PR-1 Claims
* **Totality & Categorization**: The §9 157-method manifest is complete, exclusive, and accurate.
* **Canary Integrity**: `pkg/daemon/daemon_dp_canary_test.go` AST canary prevents any un-accessed reads/writes of `d.dp`.
* **Interface Guard**: `pkg/fwdstatus/sampler.go` `CachedStatusProvider` cleanly isolates the sampler without collateral impact.

---

### Final Verdict

**VERDICT**: **`PLAN-READY`**

**Explicit Statement**: Nothing in PR-1 blocks `PLAN-READY` for issue #2114. The PR-1 design is complete, verified, and ready for `/engineer 2114`.
