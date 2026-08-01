# AGY adversarial plan-review — round 76 (plan v77 @ 0efb3e398)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-NEEDS-MAJOR (2 MAJOR — the two-state predicate re-introduces the r68 Go-map race during re-population; false-fresh conflation on mid-population arm failure — the latter's premise falsified in v78 by the all-or-nothing population proof, which Codex's partial-load check independently PASSed). Raw output follows verbatim.

---

# Adversarial PLAN Review: #2114 — Round 76 (v77 @ `0efb3e398`)

**Verdict**: **`PLAN-NEEDS-MAJOR`**

**Verdict Surface**: PR-1 ONLY (`d.dp` accessor core + work item A3 + site conversion). Items G+H+H2 in [`followup-seed.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md) are out of scope.

---

### Executive Summary

While plan v77 successfully resolves the `:632` lock-ownership assertion proof gap (Codex M2 from r75) and folds the requested minors (named Detach test leg, error-order qualifications, §5.1 label hygiene, fixture migration inventory), **the new two-state gate predicate (`loaded == false && len(m.maps) == 0`) introduced in v77 contains two critical MAJOR flaws**:

1. **Re-introduction of the r68 Data Race during Re-Population**: On a retained manager (post-`Close()`, `loaded == false`, `m.maps` non-empty), re-arming calls [`LoadUserspaceShim`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L185-L190) which writes to `m.maps` under `m.mu`. Concurrently, callers of Class 1 methods (e.g. `UpdateRGActive` at [`maps_fabric.go:38`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go#L38)) observe `loaded == false` and `len(m.maps) != 0`, bypass the gate, and proceed as master. Since master reads `m.maps` **without** `m.mu`, this creates an unsynchronized Go map read and write (fatal panic), re-exposing the exact r68 race during re-population.
2. **False-Fresh Conflation on Mid-Population Arm Failure**: If an initial `Start()` fails mid-population (after [`loader_userspace_shim.go:186-188`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L186-L188) inserts maps into `m.maps`, but before `loaded.Store(true)` at [`loader.go:164`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L164)), `loaded` remains `false` while `m.maps` is non-empty. The gate predicate evaluates `len(m.maps) == 0` as `false` and misroutes this aborted/broken state as "retained-unarmed", causing Class 1/2/4 methods to bypass `ErrDataplaneNotArmed` and attempt operations on partial/broken map state.

---

### Detailed Hostile Verification of Prompt Questions

#### 1. THE TWO-STATE PREDICATE
*Gate predicate specification in [`plan.md:3605-3617`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3605-L3617)*

- **(a) Does the empty-check race the first population insert?**
  **NO.** Populating `m.maps` in `LoadUserspaceShim` ([`loader_userspace_shim.go:185-190`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L185-L190)) takes `m.mu`. The gated method's check of `len(m.maps) == 0` also takes `m.mu`. Mutual exclusion ensures the check evaluates to `0` before insertion or `>0` after insertion.

- **(b) Does retained-proceed reintroduce the r68 race during re-population?**
  **YES (MAJOR 1).**
  - **Trace**: Following a hitless restart/re-arm (`Close()` set `m.loaded = false` at [`loader.go:1217`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1217) while retaining `m.maps`), `m.maps` is non-empty.
  - Re-population begins: `LoadUserspaceShim` runs. At [`loader_userspace_shim.go:186-187`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L186-L187), it executes `m.maps[name] = umap` under `m.mu`.
  - Concurrently, a cluster watcher calls `UpdateRGActive` ([`maps_fabric.go:38`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go#L38)). `UpdateRGActive` sees `loaded == false` and checks `len(m.maps) == 0` under `m.mu`. Since `m.maps` contains retained maps, `len(m.maps) == 0` is `false`.
  - `UpdateRGActive` is routed to "proceed as master". On master, `UpdateRGActive` reads `m.maps["iface_zone_map"]` **without holding `m.mu`**.
  - **Fatal Failure**: Writing `m.maps` under `m.mu` while concurrently reading `m.maps` without `m.mu` triggers a fatal Go concurrent map read/write panic.

- **(c) The false-fresh case: partial arm (load error mid-population)**
  **YES (MAJOR 2).**
  - **Trace**: A fresh manager calls `Start()`. `LoadUserspaceShim` inserts map handles into `m.maps` at [`loader_userspace_shim.go:186-188`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L186-L188).
  - A subsequent step in `Start()` (e.g. `AttachXDP` or link binding) fails and returns an error. `loaded.Store(true)` at [`loader.go:164`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L164) is never reached, leaving `loaded == false`.
  - `m.maps` now contains a partial set of maps and is non-empty.
  - A subsequent Class 1/2/4 method call evaluates `loaded == false` and `len(m.maps) == 0` under `m.mu`. Because `m.maps` is non-empty, `len(m.maps) == 0` is `false`.
  - **Fatal Misroute**: The predicate misclassifies this broken, aborted load state as "retained-unarmed", bypassing `ErrDataplaneNotArmed` and attempting lookups on incomplete/un-armed BPF maps.

- **(d) Is the §4.7 L2 claim still precisely stated?**
  **NO.** [`plan.md:3837`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3837) claims "(L2) method-level ADMISSION safety against a published-but-unarmed backend — closed by A3's contract". As proven in (b) and (c), A3's gate fails to provide admission safety during re-population and mid-population load failures.

---

#### 2. THE LOCK-OWNERSHIP ASSERTION
*Specification in [`plan.md:4486-4493`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4486-L4493)*

- **Does this prove what branch execution could not?**
  **YES.**
  - In r75 (Codex M2), a mutant dropping `m.mu.Lock()`/`Unlock()` at line `:632` passed `-race` testing because earlier mutex sections (`:609`, `:613`) established a happens-before relationship between the swap and the getter.
  - In v77, inserting a test hook inside the `:632` section that holds `m.mu` while a concurrent goroutine attempts `XDPEntryProgram` (or `TryLock`) directly proves lock ownership. If `:632` drops its lock, `TryLock()` succeeds or the getter fails to block, catching the mutant.

---

#### 3. NAMED DETACH LEG, ERROR-ORDER QUALIFICATION, §5.1 FIX & INVENTORY
- **`TestManager_ArmedGate_DetachRetainedClaims`** ([`plan.md:4515-4522`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4515-L4522)): Properly specifies the fake `link.Link` embed, seeding `xdpLinks`+`xdpFlagClaims`, and qualifies that discovery errors at `loader.go:730` (`vlan_iface_map`) and `:747` (`iface_zone_map`) return before claim deletion at `:777`.
- **§5.1 label hygiene** ([`plan.md:3734-3736`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3734-L3736)): Correctly single-homes `DetachXDP` under Category G while documenting its class-3-like internal delegation.
- **Fixture migration mechanism & inventory** ([`plan.md:4504-4514`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4504-L4514)): Uses the existing `injectShimMap` reflect/unsafe helper and provides an honest inventory of the ~30 synthetic userspace tests requiring synthetic arming.

---

#### 4. FRESH ATTACK: `Close()` Entry `loaded` Store vs Retained Pass-Through
- [`plan.md:3548, 3779`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3548) moves `loaded.Store(false)` to `Close()`'s entry (`loader.go:1206`) to gate out new entrants during teardown.
- However, since `Close()` does not clear `m.maps`, any method called during `Close()` observes `loaded == false` AND `m.maps` non-empty.
- Under v77's predicate, these calls evaluate to "retained-unarmed" and **pass through to master** instead of being gated! This invalidates the claim that `loaded.Store(false)` at `Close()` entry gates new entrants during teardown.

---

### Required Remedies for Next Plan Iteration (v78)

To resolve the two MAJOR defects in the gate predicate:
1. **Explicit Manager Lifecycle State**: Do not infer retained vs fresh state via implicit map checks (`len(m.maps) == 0`). Explicitly track whether a Manager is in a valid `retained` state (set upon successful completion of `Close()` after a successful arm).
2. **Synchronized Map Access on Retained State**: Ensure all `m.maps` lookups during `loaded == false` (retained state) are protected under `m.mu` (scoped lookup locking), so re-population writes to `m.maps` in `LoadUserspaceShim` cannot race against retained reads/mutations.
3. **Reset on Arm Failure**: Ensure that a failed `Start()` / `LoadUserspaceShim` explicitly clears `m.maps` (or resets the manager state) on error so a partial arm never leaves `m.maps` non-empty with `loaded == false`.

---

### Conclusion

Does anything in PR-1 block `PLAN-READY` for #2114? **YES.** The two-state gate predicate in work item A3 re-introduces the r68 Go map data race during re-population and misroutes partial arm failures. Plan v77 is **`PLAN-NEEDS-MAJOR`**.
