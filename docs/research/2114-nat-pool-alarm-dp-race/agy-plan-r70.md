# AGY adversarial plan-review — round 70 (plan v71 @ 3f4d46d39)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (four-class partition audited complete; class-3 m.mu deadlock/reentrancy audit clean; retracted teardown claim verified; blocked-Start test design implementable; corrected alternative rationale sound; userspace adapter gate routing verified end-to-end — no ungated path). Raw output follows verbatim.

---

### Hostile Plan Review Verdict: **PLAN-READY**

**Target Surface**: PR-1 ONLY (`d.dp` accessor core, A1 atomic cell, A3 four-class backend admission gate, AST canaries, `fwdstatus` structural narrowing).
*(Work items G + H + H2 are in `followup-seed.md` and out of scope for this verdict).*

---

### Detailed Verification & Hostile Attack Analysis

#### 1. The Four-Class A3 Contract (§4 A1, §5.1, §6, §7 item 12)
* **(a) Class-3 `m.mu` mechanism**:
  * **Lookup & Population under `m.mu`**: Today, `ClearNATRuleCounters` ([`pkg/dataplane/maps_nat.go:396-410`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L396-L410)) and `ClearGlobalCounters` ([`pkg/dataplane/maps_counters.go:176-196`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L176-L196)) acquire `m.mu` for internal offset clears but read `m.maps` *outside* `m.mu`. Moving the `m.maps` map lookup under `m.mu` and wrapping `Start`'s `m.maps` population inserts ([`pkg/dataplane/loader_userspace_shim.go:185-191`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go#L185-L191)) under `m.mu` eliminates the concurrent read/write race during population.
  * **Deadlock / Reentrancy Audit**: `m.mu` in `dataplane.Manager` ([`pkg/dataplane/loader.go:49`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L49)) is a standard `sync.Mutex`. Callers in `userspace.Manager` ([`pkg/dataplane/userspace/natcounters.go:27-40`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/natcounters.go#L27-L40)) invoke `m.bpfShim.ClearNATRuleCounters()` *before* acquiring `userspace.Manager.mu`. `Start` populates `m.maps` during boot on the `Run` goroutine without holding any outer locks. No caller holds `m.mu` prior to invoking Class-3 methods, and Class-3 methods release `m.mu` prior to BPF map operations. **No deadlock or reentrancy hazard exists.**
* **(b) Partition Completeness**:
  * An audit of all exported methods on `*dataplane.Manager` ([`pkg/dataplane/loader.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go), [`maps_*.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go)) confirms every method touching `m.maps`/`m.programs`/`m.xdpLinks`/`m.tcLinks` is cleanly partitioned:
    * **Class 1 (Fallible)**: `UpdateRGActive`, `UpdateFabricFwd`, `AttachXDP`, `DetachXDP`, `AttachTC`, `DetachTC`, `SetZone`, `SetVlanIfaceInfo`, `ClearIfaceZoneMap`, `ClearVlanIfaceMap`, `AddTxPort`, `SwapToUserspaceXDPShimEntryProgram`, `ReadGlobalCounter`, `IncrementGlobalCounter`, `ReadInterfaceCounters`, `ReadZoneCounters`, `ClearInterfaceCounters`, `ClearZoneCounters`, `ClearAllCounters`, `ReadNATPortCounter`, etc. $\rightarrow$ Returns `ErrDataplaneNotArmed` pre-arm.
    * **Class 2 (Neutral)**: `IsLoaded()`, `SessionCount()`, `GetMapStats()`, `ClearZoneCounterOffsets()` $\rightarrow$ Returns neutral pre-arm values (`false`, `(0,0)`, `[]MapStats{}`, or no-op).
    * **Class 3 (Hybrid)**: `ClearNATRuleCounters`, `ClearGlobalCounters`, `ClearNATRuleCounterOffsets` $\rightarrow$ Ungated pre-arm success, lookups/population under `m.mu`.
    * **Class 4 (Getters)**: `Map()`, `Program()`, `NewEventSource()`, `XDPLinks()`, `TCLinks()`, `GetPersistentNAT()` $\rightarrow$ Returns `nil` pre-arm.
    * **Ungated**: `Mode()` (construction-time value) and `IsLoaded()` (reads `loaded.Load()`).
* **(c) Class-2 Neutral Outcomes vs. Master**:
  * On master, if `m.maps` is missing or unpopulated, `GetMapStats` returns an empty slice, `SessionCount` returns `(0,0)`, and offset clear functions no-op. Class 2 preserves this exact behavior without divergence.

---

#### 2. Retracted Teardown Claim (§7 item 12, §10 residual)
* **Accuracy of Retracted Claim**: `m.loaded.Store(true)` at [`pkg/dataplane/loader.go:164`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L164) is an acquire/release visibility boundary for population. Placing `m.loaded.Store(false)` at `Close()` entry ([`loader.go:1206`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1206)) prevents *new* callers from entering pre-teardown.
* **Impact on Teardown Exposure**: It does not drain existing in-flight callers that already read `loaded == true`. The pre-existing shutdown-window link-map race (`Close()` ranging maps while attach writes occur after the apply-drain timeout) is accurately acknowledged as an un-worsened pre-existing residual (§10). A3 narrows new entrant exposure and leaves in-flight exposure unchanged. The retracted claim is exact and honest.

---

#### 3. Respecified Blocked-Start Test (§9 item 4a)
* **Determinism & Mechanics**: The test seam uses fixed `entered` and `resume` channel barriers around the `m.maps` population loop inside `pkg/dataplane`. The population writer signals `entered` and blocks on `resume`, allowing class-1/3/4 readers to run concurrently under `-race`.
* **AST Inventory Enforcement**: `TestManager_PreArmMethodMatrix` parses `pkg/dataplane/*.go` using `go/ast` to discover all exported `*Manager` methods and asserts every method is declared in the test's contract matrix. This makes un-gated method regressions impossible. The test design is fully implementable and deterministic.

---

#### 4. Corrected Publish-After-Start Rationale
* The decision to keep `d.setDataplane(dp)` publication timing and rely on A3's internal backend gate is justified by three solid reasons:
  1. **Standardized Defense**: A backend-level admission gate (`loaded.Load()`) protects all callers holding a `*dataplane.Manager` reference regardless of how obtained, whereas pending-owner only protects callers querying `d.dataplane()`.
  2. **Single Channel**: Avoids introducing dual lifecycle tracking fields (`d.dpCell` and `d.pendingDp`) on `Daemon`.
  3. **Purely Additive**: Keeps daemon boot sequence program order intact while standardizing backend admission error handling.

---

#### 5. Userspace Adapter Gate Routing
* **Call Chain**:
  `d.dp.HA().SetRGActive(ctx, rgID, active)` ([`daemon_ha.go:297`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go#L297))
  $\rightarrow$ `userspace.LegacyDataPlaneAdapter.HA().SetRGActive` ([`pkg/dataplane/userspace/controllers.go:92`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/controllers.go#L92))
  $\rightarrow$ `userspace.Manager.UpdateRGActive` ([`pkg/dataplane/userspace/manager_ha.go:657`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_ha.go#L657))
  $\rightarrow$ `m.bpfShim.UpdateRGActive(rgID, active)` ([`manager_ha.go:664`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_ha.go#L664))
  $\rightarrow$ `dataplane.Manager.UpdateRGActive` ([`pkg/dataplane/maps_fabric.go:38`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go#L38)).
* **Gate Inspection**: Line 664 of `manager_ha.go` calls `m.bpfShim.UpdateRGActive` as its **very first action**. Under A3 Class 1, `m.bpfShim.UpdateRGActive` executes `if !m.loaded.Load() { return ErrDataplaneNotArmed }` before touching `m.maps["rg_active"]`.
* **Conclusion**: `SetRGActive` routes directly through `bpfShim`'s Class-1 gated method. **There is no ungated path to Start-populated state.**

---

#### 6. Fresh Attack on PR-1 Claims
* **Scope Boundary**: PR-1 cleanly isolates the atomic accessor cell (`dpCell atomic.Pointer[dpSlot]`), kind-gated typed-nil protection (`setDataplane`), structural `fwdstatus` adapter narrowing (`CachedStatusProvider`), and A3 four-class backend gate without any hidden dependency on follow-up items G/H/H2.
* **Compiler & Canary Protection**: The retype of `d.dp` forces compiler-verified conversion across 134 executable production references, backed by AST canary tests preventing raw `dpCell` bypasses.

---

### Conclusion & Verdict

Nothing in PR-1 blocks **PLAN-READY** for #2114. The design in plan v71 is complete, technically sound, and ready for `/engineer 2114` implementation.
