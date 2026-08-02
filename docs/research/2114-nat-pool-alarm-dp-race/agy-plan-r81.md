# AGY adversarial plan-review — round 81 (plan v82 @ c4005f7c2)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (the corrected precedence re-derived against the tree — all 157 methods partition cleanly; the carve-out ordering chain audited per entry point; no ordering gap). Raw output follows verbatim.

---

### Adversarial PLAN Review Verdict: **PLAN-READY**

**Target Surface**: PR-1 ONLY (`d.dp` synchronized accessor + backend method gating A3 + canaries + snapshot boundaries).  
**Branch**: `research/2114-nat-pool-alarm-dp-race`  
**Plan Doc**: [`docs/research/2114-nat-pool-alarm-dp-race/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) @ commit `c4005f7c2` (v82)

---

### Hostile Verification & Audit

#### 1. Corrected Precedence Order & Predicate Sweep
- **Plan Reference**: [`plan.md:L3595-3608`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3595-L3608)
- **Rule Hierarchy**:
  1. **Escaping references** $\rightarrow$ **Class 4** (`Map`, `Program`, `NewEventSource`).
  2. **Go-side pre-error side-effects** $\rightarrow$ **Class 3** (`ClearNATRuleCounters`, `ClearGlobalCounters`, `ClearZoneCounters`, `ClearAllCounters`).
  3. **NEUTRAL missing-map outcome (nil/zero/empty, never an error)** $\rightarrow$ **Class 2** (`SessionCount`, `GetMapStats`, `ClearStaticNATEntries`, `UpdatePolicyScheduleState`, `ClearSessionCounts`).
  4. **Error missing-map outcome** $\rightarrow$ **Class 1** (`UpdateRGActive`, `UpdateFabricFwd`, `SetDefaultPolicy`, `AttachXDP`, etc.).
- **Code Audit Verification**:
  - In [`maps_fabric.go:L18-L38`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go#L18-L38), methods like `UpdateRGActive` and `UpdateFabricFwd` return `fmt.Errorf("... map not found")`. Under v80's un-scoped predicate, they were incorrectly swept into Class 2. Under v82's precedence rule (check neutral outcome first; if error outcome $\rightarrow$ Class 1), these fabric methods land cleanly in **Class 1**.
  - Methods like `ClearStaticNATEntries` ([`maps_nat.go:L258-L287`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L258-L287)) and `UpdatePolicyScheduleState` ([`maps_policy.go:L244-L256`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_policy.go#L244-L256)) return `nil` on missing map. They match the NEUTRAL predicate and land in **Class 2**.
  - All 157 exported methods in `pkg/dataplane` form a total, mutually exclusive partition without collision or ambiguity.

#### 2. Carve-Out Predicate & Per-Entry-Point Ordering
- **Plan Reference**: [`plan.md:L3672-3687`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3672-L3687), [`plan.md:L4621-4638`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4621-L4638)
- **Predicate**: Carve-out applies **whenever `loaded == false`** (on both fresh and retained states).
- **Ordering Chain Audit**:
  - `Manager.Compile` / `ApplyConfig`: Evaluates `CompileConfig`, which immediately checks `!dp.IsLoaded()` at [`compiler.go:L182`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L182) before any map access and rejects with `"dataplane not loaded"`.
  - `CompileUserspaceShim`: Executes legacy cleanups ([`loader.go:L174-L177`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L174-L177)), updates selector under `m.mu` at [`loader.go:L181`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L181), then evaluates `CompileConfig` at [`compiler.go:L182`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L182).
  - `userspace.Manager.Compile`: Invokes selector update at [`manager_compile.go:L184`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go#L184), then calls `CompileUserspaceShim`, which rejects at [`compiler.go:L182`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L182).
- **Synchronization Check**: Any selector invocation (`m.SelectUserspaceXDPShimEntryProgram()`) acquires `m.mu`. If `Start()` is concurrently executing, `Start()` holds `m.mu` until all maps are populated and `loaded=true` is set. The selector call blocks on `m.mu`, unblocks post-Store(true), and proceeds to `CompileConfig` with `loaded == true`. No ordering gap exists.

#### 3. Class-3 Reverse-Schedule Seam & AST Canary
- **Plan Reference**: [`plan.md:L4689-4701`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4689-L4701), [`plan.md:L3467-3475`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3467-L3475)
- **Seam & Canary Design**:
  - Class-3 hybrids (`ClearGlobalCounters`, etc.) release `m.mu` after Go side-effects before entering BPF lookups. The writer-first held-batch test could previously pass by locking at side-effect entry rather than lookup entry.
  - The lookup-entry reverse-schedule seam simulates `Start()` publishing maps precisely between the side-effect unlock and the lookup entry.
  - The AST canary in `pkg/dataplane` strictly limits direct `m.maps` / `m.programs` accesses to:
    1. The single `m.mu`-scoped registry helper (`lookupMapLocked` / `lookupProgramLocked`).
    2. The whole-batch publication writer in `Start` / `LoadUserspaceShim` ([`loader_userspace_shim.go:L183-L190`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L183-L190)).
  - The AST canary in `pkg/daemon/daemon_dp_canary_test.go` forbids direct `dpCell` references outside accessor definitions.
- **Implementability**: The lookup-entry seam integrates cleanly with existing `xpf` package-internal test-seam conventions (e.g. `var ...Seam` pattern seen in `proxyarp.go`).

#### 4. Obsolete-Generation Wording & Retained-Fixture Scope Pin
- **Plan Reference**: [`plan.md:L3928-3947`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3928-L3947), [`plan.md:L4661-4674`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4661-L4674)
- **Accuracy**: Wording explicitly acknowledges that `Teardown()` does not close `m.maps` FDs ([`loader.go:L1221-L1235`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1221-L1235)). Retained map handles are live FD-backed objects belonging to an obsolete forwarding generation. A retained-proceed mutation executes BPF updates against the old map, which fails to reach the live generation created by a subsequent `Start()`. This accurately models master's pre-existing recurrence behavior (handled by follow-up work item H).
- **Scope Pin**: Both `Close()` and `Teardown()` present `loaded == false` with non-empty maps. A single seeded retained fixture (`loaded == false` + maps present) is sufficient for state matrix tests; duplicate matrices for `Close` vs `Teardown` are eliminated.

---

### Blocking Issues Check (PR-1 Scope)

Does anything in PR-1 block **PLAN-READY** for #2114?  
**No.** All precision, consistency, precedence, ordering, and test-seam requirements identified in previous rounds have been completely resolved in plan v82.

---

### Summary of Work

Plan document `plan.md` (v82 @ `c4005f7c2`) is completely sound, hostiles-verified, and ready to move to implementation via manual `/engineer 2114`.
