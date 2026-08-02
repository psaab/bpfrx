# AGY adversarial plan-review — round 83 (plan v84 @ a30d67ebc)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (the named-publisher design verified against the real files — no hidden recursion, no ordering hazard, the canary's locked-interval shape check implementable as an AST rule; the hook protocol, privilege split, summary pointers, closure wording, propagation, and inventory fixes all verified). Raw output follows verbatim.

---

### Verdict: PLAN-READY

**Does anything in PR-1 block PLAN-READY for #2114?**  
**No.** All seven r82 findings have been folded cleanly into v84 @ `a30d67ebc`. The PR-1 scope (`d.dp` accessor core A1 + armed-state gate A3 + full site conversion + AST canaries + sampler narrowing) is sound, race-free, deadlock-free, and fully verified.

---

### Hostile Verification

#### 1. The Named-Publisher Design (`publishShimRegistryLocked`)

- **Flow**: `LoadUserspaceShim` ([`loader.go:152-166`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L152-L166)) runs:
  1. `m.SelectUserspaceXDPShimEntryProgram()` ([`:154`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L154)) (unlocked selector write).
  2. `cleanupUserspaceShimLegacyTCLinks()` ([`:155`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L155)) and `cleanupUserspaceShimLegacyOnlyMapPins()` ([`:158`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L158)) (unlocked filesystem cleanups).
  3. `acquireUserspaceShimObjects()` (unlocked, privileged eBPF spec loading, collection construction, program lookup, pin creation — extracted from [`loader_userspace_shim.go:106-184`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L106-L184)).
  4. `publishShimRegistryLocked` (takes `m.mu`, assigns `m.programs` & `m.maps` from [`loader_userspace_shim.go:185-191`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L185-L191), and executes `m.loaded.Store(true)`).

- **Hidden Recursion Check**:
  `publishShimRegistryLocked` executes only Go map assignments (`m.programs[...] = ...`, `m.maps[...] = ...`) and `m.loaded.Store(true)` under `m.mu`. Neither Go map assignments nor `atomic.Bool.Store()` invoke any methods on `Manager` or acquire any locks. There is zero hidden recursion or re-entrancy.

- **Ordering Hazards Check**:
  Acquisition constructs fresh, un-published handle collections (`userspaceCollection`, `userspaceProg`, `sharedMaps`) stored in local variables inside `LoadUserspaceShim`. No other goroutine holds pointers to these handles until `publishShimRegistryLocked` runs under `m.mu`. Nothing between acquisition and publication can mutate, close, or invalidate these local handles.

- **Canary Locked-Interval Shape Check AST Implementability**:
  The AST rule parses `pkg/dataplane` function declarations using `go/ast` ([pattern in `retirement_boundary_canary_test.go:610`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/retirement_boundary_canary_test.go#L610)). For allowlisted functions (`publishShimRegistryLocked` and the registry helper):
  - It inspects statement sequences to ensure every `m.maps` or `m.programs` `ast.SelectorExpr` is dominated by an `m.mu.Lock()` call and precedes `m.mu.Unlock()` (or is inside a block with `defer m.mu.Unlock()`).
  - Any access occurring outside `m.mu.Lock()`/`Unlock()` (e.g. `Lock -> hook -> Unlock -> access`) fails the AST shape check. This is straightforwardly implementable via Go's standard `go/ast` package.

---

#### 2. Observable Ordering of `Store(true)`

- On master, `m.loaded = true` ran at [`loader.go:164`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L164) after `loadUserspaceShimObjects()` returned.
- Under v84, `m.loaded.Store(true)` runs inside `publishShimRegistryLocked` immediately following the `m.maps` and `m.programs` assignments, all within `m.mu.Lock()`.
- **Impact**: Any reader observing `loaded.Load() == true` (whether immediately after `publishShimRegistryLocked` completes or after `LoadUserspaceShim` returns) will observe a fully populated, complete registry. No partial registry is ever observable.

---

#### 3. Folded Specifications

- **Hook Protocol**: Instance-scoped hooks, maximum of one ownership hook armed per test to avoid lock-wait deadlocks, with `TryLock() == false` asserted inside the actual access interval (or before-lock/after-acquire handshake).
- **Privilege Split**: Retained oracle tests split into:
  1. *Always-on classification/ownership legs* using sentinel/absent registries (run unprivileged in standard CI).
  2. *Privileged semantic-mutation legs* (run where eBPF root privileges exist).
- **Summary Carve-Out Pointers**: Summary text explicitly points to the carve-out for methods with pre-existing `loaded` checks (`AttachXDP`, `AttachTC`, `CompileConfig` at [`loader.go:173-183`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L173-L183)), preserving their specific rejection behaviors rather than returning `ErrDataplaneNotArmed`.
- **Closure-Wording Resolution**: Clarified that registry selection is closed across all states under the uniform rule. `Close()` retains a non-empty registry, so teardown narrowing is strictly limited to the loaded-check set.
- **Qualification Propagation**: `ApplyConfig` context cancellation ([`daemon_apply.go:238`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go#L238)) wins before loaded rejections.
- **Inventory Fixes**: Canary pair corrected to set, and obsolete status references updated.

---

#### 4. Audit of PR-1 Scope

- **All 134 `d.dp` Sites**: Cataloged and mapped to explicit accessor conversions in §5.4.
- **Delivery Boundary**: PR-1 remains cleanly isolated from the G+H+H2 follow-up unit (`followup-seed.md`).
- **Safety**: No main-loop blocking, no thread-deadlock risks, and complete backward compatibility of public API contracts.

---

### Summary
Plan v84 for PR-1 is fully converged and ready for implementation (`/engineer 2114`).
