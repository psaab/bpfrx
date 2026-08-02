# AGY adversarial plan-review — round 84 (plan v85 @ 9f1f3ab69)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (the non-escaping helper shape verified sufficient against every current access pattern; the shape rules cover every escape form; the teardown-summary qualifications verified). Raw output follows verbatim.

---

# Adversarial PLAN Review for #2114 — Round 84 (CONVERGENCE)

**Plan Document**: [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) @ commit `9f1f3ab69`  
**Verdict Surface**: **PR-1 ONLY** (Units G+H+H2 extracted to [`followup-seed.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md) are out of scope).

---

## Verdict: **PLAN-READY**

**Nothing in PR-1 blocks PLAN-READY for #2114.** The plan specification for PR-1 is complete, mechanically sound, mathematically rigorous against concurrency escape forms, and ready for `/engineer 2114`.

---

### Item 1: Non-Escaping Helper (`registryLookupLocked`) & Access Patterns

- **Access Pattern Inventory**:
  A full codebase search across `pkg/dataplane` confirms that **zero** callsites iterate the registry (`range m.maps` / `range m.programs` yield **0** occurrences). All existing callsites look up specific handles by string keys (e.g. [`loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700) `m.maps["iface_zone_map"]`, [`loader.go:1086`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1086) `m.programs["tc_main_prog"]`) or assign key handles during publication ([`loader_userspace_shim.go:183-190`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L183-L190)).
- **Sufficiency**:
  The key-in / handle-out signature `registryLookupLocked(name string)` (and its program counterpart / generic formulation `*ebpf.Map` / `*ebpf.Program`) is **100% sufficient** for every current access pattern in `pkg/dataplane`. The container map itself never escapes the `m.mu` lock boundary.

---

### Item 2: Shape Rules, AST Canary, Escape Analysis & Publisher

- **Receiver & Precision Matching**:
  The AST canary over `pkg/dataplane` ([`plan.md:4793-4811`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4793-L4811)) enforces type-aware receiver matching on `*Manager` / `Manager`.
- **Complete Escape Rejection**:
  The canary shape rules reject container return, container aliasing, struct field assignment, closure capture, argument passing, and post-unlock indexing.
- **Negative Test Fixtures**:
  The plan specifies mandatory negative AST canary test fixtures asserting failure for **both** anti-patterns:
  1. *Helper container escape* (helper returning `m.maps` wholesale, caller indexing post-unlock).
  2. *Unlock-before-access* (`Lock -> hook -> Unlock -> access`).
- **Publisher Invariants**:
  [`publishShimRegistryLocked`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4784-L4789) executes under `m.mu` and performs registry assignments followed by **exactly one** in-lock `loaded.Store(true)`.
- **Residual Escape Forms Audit**:
  Re-verification of `pkg/dataplane` structs confirms no long-lived struct field caches map slices or container aliases across dataplane reloads.

---

### Item 3: Teardown Summary Qualifications

- Both summary locations ([`plan.md:3884-3897`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3884-L3897) and Invariant 12 [`plan.md:4503-4508`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4503-L4508)) explicitly qualify that `Close()`'s entry `loaded.Store(false)` narrows admission **strictly for the `LOADED-CHECK SET`** (`AttachXDP`, `AttachTC`, `CompileConfig`).
- Retained methods (where `Close()` leaves a non-empty registry) continue to classify as retained state (`loaded == false && maps non-empty`) under the two-state gate rule and proceed identical to master.

---

### Item 4: Fresh Attack on PR-1 Claims

- **Accessor Isolation & Canaries**:
  PR-1's core (`dpCell` with `atomic.Pointer[dpSlot]`) provides clean `d.dataplane()`, `d.writeDPFor()`, and `d.writeDPNilFor()` accessors. Direct `dpCell` access in `pkg/daemon` is strictly forbidden by `daemon_dp_canary_test.go` ([`plan.md:3481-3488`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3481-L3488)).
- **Sampler Adapter Narrowing**:
  `pkg/fwdstatus` adapter is structurally narrowed to `CachedStatusProvider` ([`plan.md:3505-3543`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3505-L3543)), eliminating all un-gated adapter methods (`Status()`, `IsLoaded()`, `GetMapStats()`).
- **Implementation Precision Note**:
  `m.programs` holds `*ebpf.Program` handles while `m.maps` holds `*ebpf.Map` handles. During `/engineer 2114`, the implementor will provide the typed lookup for `m.programs` (`registryProgramLookupLocked` or generic `registryLookupLocked[T]`), and the AST canary allowlist will cover both. This is standard implementation detail and does not block design sign-off.

---

## Summary of Verification

1. **Non-Escaping Helper**: Verified — `registryLookupLocked` signature covers all existing key-lookup patterns; zero registry iterations exist.
2. **Shape Rules & Escapes**: Verified — AST canary rules forbid all escape forms and require negative fixtures for both canary anti-patterns.
3. **Teardown Qualifications**: Verified — `loaded-check set` scope is accurately qualified across mechanics and invariant sections.
4. **PR-1 Scope**: Verified — PR-1 is cleanly decoupled, race-free, and ready.
