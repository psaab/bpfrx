# AGY adversarial plan-review — round 72 (plan v73 @ e33ab4a3a)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (class-2 synchronization verified against the 22 named methods; categorized partition verified total and exclusive against the 157-method inventory; facade facade audit; arming-order invariant; residual exactness). Raw output follows verbatim.

---

# Adversarial PLAN Review for #2114 — Round 72 (CONVERGENCE)

- **Plan Document**: [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (v73 @ `e33ab4a3a`)
- **Target Branch**: `research/2114-nat-pool-alarm-dp-race`
- **Scope**: PR-1 ONLY (`d.dp` synchronized accessor cell + A3 armed-state admission gate; G+H+H2 follow-up unit in `followup-seed.md` is out of scope).

---

## Verdict

### **PLAN-READY**

**Explicit Statement**: Nothing in PR-1 blocks **PLAN-READY** for #2114. 

---

## Detailed Hostile Verification

### 1. Class-2 Synchronization Verification (v73)

- **Rule Invariant**: Every Class-2 method (neutral-outcome read/clear lookups) performs an acquire-load (`m.loaded.Load()`) **before the first Start-state access**. 
  - On `false`: Returns master's exact byte-for-byte missing-map outcome (e.g., `nil` error for no-op clears, `(0, 0)` for session counts, `nil` for empty `MapStats` slices).
  - On `true`: The acquire-load forms a happens-before edge with `Start()`'s release-store (`m.loaded.Store(true)` at [loader.go:164](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L164)). Because `m.maps` is immutable post-`Start()`, Class-2 methods need **no `m.mu`** during post-gate iteration over `ebpf.Map` handles.
- **Overlap Matrix Inclusion**: Class-2 methods participate in the §9 blocked-`Start` overlap test (`TestManager_ArmedGate_BlockedStart`) to ensure nonconcurrent tests verify that the gate blocks execution prior to map population completing.
- **22 Named Methods Audit**:
  1. [maps_screen.go:58](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go#L58): `ClearSessionCounts()` $\rightarrow$ pre-arm returns `nil`.
  2. [maps_nat.go:259](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L259): `ClearStaticNATEntries()` $\rightarrow$ pre-arm returns `nil`.
  3. [maps_policy.go:252](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_policy.go#L252): `UpdatePolicyScheduleState()` $\rightarrow$ pre-arm returns `nil` (#3780 self-heal).
  4. [maps_session.go:326](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L326): `SessionCount()` $\rightarrow$ pre-arm returns `(0, 0)`.
  5. [maps_stats.go:69](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go#L69): `GetMapStats()` $\rightarrow$ pre-arm returns `nil` / empty slice.
  6. **Seeders & Stale Maps (17 methods)**: `ClearStaleSessionMaps`, `ClearStaleNATMaps`, etc., across `maps_stale.go` and seeders $\rightarrow$ pre-arm return exact neutral outcomes (`nil`).

---

### 2. The Categorized Partition & Category F Facade Audit

- **Partition Completeness**: 157 exported `*Manager` methods are total and exclusive across:
  - **Class 1**: Fallible map-required methods (`ErrDataplaneNotArmed`).
  - **Class 2**: Neutral-outcome methods with acquire-load gate.
  - **Class 3**: Ungated hybrids with required pre-error Go-side side effects + internal raw helper composition + scoped `m.mu` locking.
  - **Class 4**: Escaping getters (`Map`, `Program`, `NewEventSource`).
  - **Category L**: Lifecycle methods (`Load`, `Start`, `Close`, `Teardown`, etc.).
  - **Category F**: Facade accessors (`HA`, `Sessions`, `Telemetry`, `Link`, etc.).
  - **Category G**: Ungated Go-state helpers (`IsLoaded`, offset readers/writers).
- **Escape-First Precedence Rule**: Resolves ambiguous signatures cleanly (e.g. `Map`/`Program` match Class 2 signature patterns but resolve to Class 4; `NewEventSource` matches Class 1 signature pattern but resolves to Class 4).
- **Hostile Category F Attack**:
  - Investigated `Link()`, `HA()`, `Sessions()`, `Telemetry()` at [apply.go:217-235](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/apply.go#L217-L235) and [userspace/manager.go:379-385](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go#L379-L385).
  - All four constructors return lightweight `NewDataPlaneXController(m)` wrapper handles (e.g. `dataPlaneHAController{dp: m}`).
  - **Finding**: They do **not** read `Start`-populated state (`m.maps`, etc.) at handle creation time. When methods on the returned handle are later invoked (e.g. `SetRGActive`), control delegates back to `*Manager` methods (e.g. `UpdateRGActive`), which are governed by their own Class 1 acquire-load gate (`ErrDataplaneNotArmed`). Category F is disjoint and safe.

---

### 3. The Raw-Helper Rule (M3) & Class-3 Composition

- **Composition Analysis**: `ClearAllCounters()` ([maps_counters.go:246-263](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L246-L263)) calls internal `clearXxxRaw` helpers under scoped `m.mu` lookup locking rather than invoking public gated methods.
- **Contract Preservation**: By composing through raw helpers, pre-arm calls to `ClearAllCounters()` return the legacy error string `"interface_counters map not found"` pinned by [manager_counters_test.go:552](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/manager_counters_test.go#L552), rather than blowing up with `ErrDataplaneNotArmed`.
- **Validation**: Enforced in §9 by `TestManager_PreArmMethodMatrix`, which asserts the raw-helper call shape for all Class-3 methods.

---

### 4. Arming-Order Invariant & `AttachXDP` Audit

- **Audit Query**: Searched for any path invoking public `AttachXDP` prior to `m.loaded.Store(true)`.
- **Findings**:
  - `LoadUserspaceShim()` ([loader.go:152-167](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L152-L167)) loads eBPF objects and sets `m.loaded = true` at [line 164](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L164). It does **not** attach XDP.
  - Attachment of XDP programs (`attachUserspaceShimXDP` $\rightarrow$ `m.AttachXDP`) occurs inside `CompileUserspaceShim()` ([loader.go:173-254](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L173-L254)), which runs strictly **after** `LoadUserspaceShim()` / `Start()`.
  - The bootstrap-exit sequence ([daemon_run_naming.go:230-236](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_naming.go#L230-L236)) invokes `d.dp.Start()` **before** any config compilation or interface attachment.
  - The arming-order invariant (`loaded = true` before `AttachXDP`) holds unconditionally across all boot and takeover execution arms.

---

### 5. Residual Exactness & Hazard Audits (§7 item 12, §10)

- **Writer Inventory**:
  - [loader.go:534](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L534): Pinned link reuse insertion.
  - [loader.go:575](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L575): Fresh link insertion.
  - [loader.go:661](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L661): Detach link deletion.
- **Teardown Interleaving & Late-Admission Schedule**:
  - `stopPolicySchedulerLoop` ([daemon_scheduler.go:170-183](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_scheduler.go#L170-L183)) acquires `applySem` during shutdown, draining in-flight applies.
  - The remaining interleaving is late admission (a post-release attach mutating Go link maps while `Close()` ranges them at [loader.go:1206-1216](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1206-L1216)). Correctly named as pre-existing and un-worsened in §7 item 12 and §10.
- **Raw `XDPLinks` Hazard**:
  - The 1 Hz status path ranges `XDPLinks()` at [maps_sync.go:943](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go#L943) while `Compile` can mutate `m.xdpLinks` before taking userspace `m.mu`. Named as a pre-existing hazard in §4 A1 and §10.
- **`loader.go:49` Comment Sweep**:
  - The `m.mu` comment at [loader.go:49](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L49) is updated in §5.1 and §9 to explicitly include protection for `m.maps` handle lookups.

---

## Summary of Completed Work

1. Conducted an adversarial review of Plan v73 ([plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md)).
2. Verified Class-2 synchronization rules, missing-map outcomes, and 22-method inventory.
3. Audited the 157-method categorized partition, precedence rules, and Category F facade constructors.
4. Validated the Class-3 raw-helper composition rule (`ClearAllCounters`).
5. Confirmed the arming-order invariant across `Start()` and bootstrap-exit execution paths.
6. Verified residual exactness for writer inventory, teardown schedules, raw `XDPLinks` hazard, and `loader.go:49` comment sweeps.
7. Issued verdict **PLAN-READY**.
