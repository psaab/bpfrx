# AGY adversarial plan-review — round 69 (plan v70 @ dd14047a6)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-NEEDS-MINOR (0 MAJOR, 1 MINOR — the loaded Store(false) must move to Close() ENTRY at loader.go:1206, before link-handle teardown, not exit :1217). A3 happens-before, escaping references, no-successful-path, and the rejected-alternative rationale all verified sound. Raw output follows verbatim.

---

# Adversarial PLAN Review for #2114 — Round 69 (Convergence)

**Plan Document**: [`docs/research/2114-nat-pool-alarm-dp-race/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md)  
**Revision**: Plan v70 @ `dd14047a6`  
**Branch**: `research/2114-nat-pool-alarm-dp-race`  
**Verdict Surface**: **PR-1 ONLY** (Synchronized `d.dp` accessor core + A3 backend gate; G+H+H2 follow-up unit lives in [`followup-seed.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md), out of scope for this verdict).

---

## Verdict: `PLAN-NEEDS-MINOR`

### Summary
The PR-1 surface in v70 is sound, tightly bounded, and successfully addresses the r68 armed-state backend race (Work Item A3) without regressing existing behaviors or leaving unhandled escape vectors. There are **NO MAJOR defects** blocking PR-1. 

However, **one minor ordering flaw** in Work Item A3 needs a explicit line correction before implementation: `loaded.Store(false)` is specified at line 1217 (the exit of [`Close()`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1206-L1219)), which leaves `loaded == true` while link and map handles are actively being closed. It must be set at the **entry** of [`Close()`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1206) (line 1206) to gate out concurrent method calls *before* handle teardown begins.

---

## Detailed Hostile Verification

### 1. Verification of the A3 Fold
*(§4 A1 "Work item A3", §5.1 `pkg/dataplane` bullet, §7 item 12, §9 item 4a)*

* **(a) Go Memory Model Soundness**: **SOUND.**
  Under Go 1.19+ memory model rules, `m.loaded.Store(true)` (release semantics at [`loader.go:164`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L164)) is executed after all `m.maps` entries are populated during [`loadUserspaceShimObjects()`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L185-L191). Any caller executing `m.loaded.Load()` (acquire semantics) that observes `true` is guaranteed to see all `m.maps` population writes that happened prior to `Store(true)`. After `Store(true)` lands, the `m.maps` map structure itself is immutable (no new keys inserted/deleted), making concurrent lookups on `m.maps` data-race-free.

* **(b) Escaping References**: **VERIFIED SAFE.**
  A hostile check was performed for methods returning raw pointers or capabilities (e.g. `m.Map(name)`, `m.HA()`, `m.Link()`, `m.GetPersistentNAT()`):
  1. `m.HA()` returns `HAController` (which is implemented by `Manager`). Calling methods on the returned interface (`SetRGActive`, `UpdateRGActive`, `UpdateFabricFwd`) invokes methods on `Manager` that are individually gated by `if !m.loaded.Load() { return ErrDataplaneNotArmed }`. Thus, holding an `HAController` reference does not bypass the gate.
  2. `m.Map(name)` returning `*ebpf.Map`: Callers in [`pkg/dataplane/userspace/manager_ha.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_ha.go#L258) retrieve map handles locally per operation; no long-lived struct fields cache `*ebpf.Map` across operations.

* **(c) Teardown `Store(false, :1217)` vs. Concurrent eBPF Map Close**: **MINOR DEFECT IDENTIFIED.**
  In [`pkg/dataplane/loader.go:1206-1219`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1206-L1219):
  ```go
  func (m *Manager) Close() error {
      for ifindex, l := range m.xdpLinks { ... }
      for ifindex, l := range m.tcLinks { ... }
      m.loaded = false // Plan v70 specifies m.loaded.Store(false) HERE at :1217
      return nil
  }
  ```
  Placing `m.loaded.Store(false)` at line 1217 (exit of `Close()`) means `loaded` remains `true` *while* `xdpLinks` and `tcLinks` are being closed. A concurrent request arriving during `Close()` would observe `m.loaded.Load() == true` and execute against handles currently being closed.
  **Fix**: The plan must specify setting `m.loaded.Store(false)` as the **first statement** in `Close()` at [`loader.go:1206`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1206), before link/map handles are released.

* **(d) Rejected Publish-after-Start Alternative**: **SOUND RATIONALE.**
  In bootstrap mode ([`daemon_run_bringup.go:490-492`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L490-L492)), `d.dp` is constructed and published to the cell at boot, but `d.dp.Start()` is explicitly suppressed. When bootstrap mode exits ([`daemon_run_naming.go:230-236`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_naming.go#L230-L236)), `runBootstrapExitStartup()` loads `d.dataplane()` from the cell to invoke `Start()`. Delaying cell publication until after `Start()` would leave `d.dataplane()` returning `nil` throughout bootstrap mode, breaking the bootstrap-exit arming contract.

---

### 2. Verification of the "No Successful Path Changes" Claim

* **VERIFIED TRUE.**
* In master today, `m.maps` is populated exclusively inside [`loadUserspaceShimObjects()`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L185-L191) during `LoadUserspaceShim()` / `Start()`.
* Prior to `Start()`, `m.maps` is unpopulated. Any caller attempting a map lookup prior to `Start()` either gets an unpopulated key error (e.g. `"rg_active map not loaded"`) or triggers a fatal Go concurrent map read/write panic if called during `Start()`.
* No caller in the pre-arm window ever executed a maps-touching operation that succeeded. Returning `ErrDataplaneNotArmed` in the pre-arm window standardizes all pre-arm map operations onto a single typed error without altering any previously successful execution path.

---

### 3. Verification of the Four Minor Folds

1. **m1 — Pure Cell Test Leg Restored (`[CORE]`)**:
   [`plan.md:4058-4063`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4058-L4063) restores `TestDataplaneCell_ConfirmTimerStoreVsApplyReader` as a `[CORE]` test. It validates two-sided gate behavior (`setDataplane` store vs. an `applySem`-holding reader) without any dependency on G/H/H2 machinery.
2. **m2 — Nil-Receiver Guard Preserved**:
   [`plan.md:3439-3443`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3439-L3443) and §5.1 preserve `if d == nil || d.opts.NoDataplane { return nil }` in `forwardingStatusDataplane()`, matching the pre-existing constructor posture at [`daemon_forwarding_status.go:123-125`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go#L123-L125).
3. **m3 — Deletion Inventory Complete**:
   [`plan.md:3463-3465`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3463-L3465) explicitly includes the unused `errors` import at [`daemon_forwarding_status.go:3`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go#L3) alongside the deleted `var _` assertion, userspace status wrapper, and `userspaceStatusProbe` interface.
4. **m4 — Follow-up Residue Extraction & §7 Renumbering**:
   The shutdown-admission invariant (former §7 item 11) and the §6 health-message growth parenthetical were cleanly moved to [`followup-seed.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md). Section 7 items are correctly renumbered and marked.

---

### 4. Fresh Attack on Other PR-1 Claims

* **Type Safety & Reflection (`setDataplane`)**:
  `reflect.ValueOf(dp)` is safe because `dp == nil` is checked first. `v.Kind()` switches over only nillable types (`Chan`, `Func`, `Map`, `Pointer`, `Slice`, `UnsafePointer`) before calling `v.IsNil()`, preventing reflection panics on value types.
* **AST Canary Scope**:
  The extended canary ([`retirement_boundary_canary_test.go:1711`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/retirement_boundary_canary_test.go#L1711)) parses generic `*ast.IndexExpr` for `atomic.Pointer[dpSlot]`. The new `daemon_dp_canary_test.go` AST canary prevents raw `.dpCell.Load()`/`.Store()` calls outside `daemon.go`. Both direction checks are asserted in unit tests.

---

## Action Items for Plan Update (to reach PLAN-READY)

1. **[`plan.md:3491`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3491) & [`plan.md:3959`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3959)**:
   Change the `Store(false)` location description from `:1217 Store(false) at Teardown` to:
   > `:1206 Store(false) at entry of Close() / Teardown(), before closing link and map handles.`

---

### Does anything in PR-1 block PLAN-READY for #2114?
**No major architecture or concurrency defects remain.** Once the minor `Close()` entry `Store(false)` line target is updated in the plan doc, PR-1 is fully **PLAN-READY** for implementation.
