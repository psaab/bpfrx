# AGY adversarial plan-review — round 78 (plan v79 @ ea91b14da)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (per-section consistency audit clean — stale clauses eliminated; Store-inside-hold proven safe for external IsLoaded callers; attach carve-out verified complete against the tree; class-3 fresh-state behavior preserved under the uniform rule). Raw output follows verbatim.

---

### Verdict: PLAN-READY

**No blocking issues found in PR-1 for #2114.** Plan v79 @ `ea91b14da` is internally consistent, mechanically sound, and ready for implementation (`/engineer 2114`).

---

### Hostile Verification Summary

#### 1. Uniform-Rule Consistency
- **Audit**: Inspected §4 A1 (`plan.md:3614-3677`), §5.1 (`plan.md:4031-4058`), §5.5 (`plan.md:4223`), §6 (`plan.md:4330-4345`), §7 item 12 (`plan.md:4378-4402`), and §9 item 4a (`plan.md:4530-4618`).
- **Findings**:
  - Every class text explicitly routes classification and handle selection through the single `m.mu`-scoped registry helper. Only post-selection BPF operations run lock-free.
  - Stale clauses ("needs NO `m.mu`", "no `m.mu` needed", one-state gate forms, pre-v79 Store placement) have been completely eliminated.
  - `Store(true)` of `loaded` is uniformly specified as the **final step inside the whole-batch `m.mu` hold** across all sections (`loader.go:164` context).
  - The gate predicate is consistently stated across all sections as two-state: firing **only** on `loaded == false` **AND** `m.maps` empty.

#### 2. The Oracle Split & `Store(true)` Placement
- **Implementability**: The split into (ia) quiescent `FreshOutcomes` (`plan.md:4536`) and (ib) in-batch `BlockedStart` (`plan.md:4539`) is physically accurate and implementable. Under Go's `sync.Mutex` semantics, any reader invoking a Class 1/2/3/4 method during a held `m.mu` batch will block on `m.mu` rather than observing a intermediate fresh outcome. Once `m.mu` unlocks, the reader observes the ARMED state (`loaded == true` and fully populated `m.maps`).
- **External `IsLoaded` Callers**: Placing `Store(true)` inside the hold as the batch's final step does **not** create a new hazard for unlocked `IsLoaded()` callers. `Store(true)` executes only after all map/program insertion loops (`loader_userspace_shim.go:183-190`) complete. Therefore, any external caller observing `IsLoaded() == true` before `m.mu` releases observes a true statement: map population is 100% complete. Any subsequent map operation by that caller will enter the `m.mu`-scoped registry helper, waiting for `m.mu` release if necessary, and safely obtain populated map handles.

#### 3. Attach Carve-Out Inspection
- **Code Audit**: Full codebase search across `pkg/dataplane` for pre-existing `!m.loaded` or `IsLoaded()` checks on `*Manager`.
- **Evidence**:
  - `pkg/dataplane/loader.go:490` (`AttachXDP`): `if !m.loaded { return fmt.Errorf("eBPF programs not loaded") }`
  - `pkg/dataplane/loader.go:1082` (`AttachTC`): `if !m.loaded { return fmt.Errorf("eBPF programs not loaded") }`
- **Result**: `AttachXDP` and `AttachTC` are the **only** methods carrying pre-existing `!m.loaded` checks. The plan captures both in the attach carve-out (`plan.md:3642-3647`). No other method with a pre-existing `!m.loaded` check was missed.

#### 4. Scope & Ownership Alignment (§4.7 & §10)
- **Narrowed L2 Scope**: §4.7 (`plan.md:3961-3965`) accurately bounds L2 to fresh-unarmed admission safety and registry-selection race safety in every state, explicitly excluding current-generation delivery, re-arm linearizability, or teardown safety.
- **Generation-Hazard Ownership**: §10 (`plan.md:4663-4682`) correctly separates the general retained-generation confusion on teardown-retain recurrence paths (`bootstrap.go:470` / `daemon_apply_commit.go:645`) from work item H. It assigns this generic lifecycle/generation redesign to its own follow-up issue rather than overloading H (which is FirstCommit+cluster scoped).

#### 5. Class-3 Hybrid Fresh-State Behavior
- **Analysis**: Inspected `ClearGlobalCounters` (`maps_counters.go:176`), `ClearZoneCounters` (`maps_counters.go:227`), `ClearInterfaceCounters` (`maps_counters.go:201`), and `ClearAllCounters` (`maps_counters.go:245`).
- **Behavior under Uniform Rule**:
  - Class-3 methods execute their required Go-side side effects first (e.g., clearing offset maps under `m.mu`).
  - They then perform a scoped `m.mu` lookup to obtain map handles.
  - On a fresh-unarmed state (`m.maps` empty), the lookup returns `ok == false`. `ClearGlobalCounters` and `ClearZoneCounters` return `nil` (preserving master's behavior). `ClearInterfaceCounters` (called directly or via `ClearAllCounters`' raw helper) returns its legacy error `interface_counters map not found`.
- **Result**: No Class-3 hybrid's fresh-state behavior changes under the uniform rule; lookups are simply protected against concurrent `Start` population.

---

### Conclusion
PR-1 is fully specified, mutually consistent across all sections, and ready for execution. Nothing in PR-1 blocks **PLAN-READY**.
