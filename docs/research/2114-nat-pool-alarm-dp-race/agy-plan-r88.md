# AGY adversarial plan-review — round 88 (plan v89 @ 14d74b3628dc)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-NEEDS-MINOR (2 blocking minors — b1: §9 completely lacks the IsLoaded-window test leg that v89's text claimed "the §9 teardown legs assert directly"; b2: the inventory arithmetic contradicts itself — summary "13+3=16" vs body's 14 enumerated if-ok sites, true mixed subset 14+3=17 — plus the terminology overclaim: the 17-site set is the mixed/multi-access subset, not the complete optional set (~41 total neutral-outcome accesses)). Fold-free verifications: the ClearNAT64Configs oracle VERIFIED DISCRIMINATING; the per-access gating audit found no residual method-gated phrasing; the IsLoaded chain verified (loader.go:457, legacy_dataplane.go:86, health.go:107, server_show_status.go:22). Raw output follows verbatim.

---

### Adversarial PLAN Review Verdict for #2114 (Round 88 — CONVERGENCE)

**Target Plan**: v89 @ `14d74b3628dc`  
**Verdict Surface**: **PR-1 ONLY**  
**Verdict**: **`PLAN-NEEDS-MINOR`**

---

### Detailed Findings & Item-by-Item Verification

#### 1. Inventory Derivation & Arithmetic Check
* **Derivation Analysis**:
  Gretting all production `m.maps[...]` and `m.programs[...]` reads in `pkg/dataplane` yields **41 total optional accesses** (where an absent map does not return an error):
  - **`maps_nat.go`**: 4 optional-if-ok (`:261` static_nat_v4, `:274` static_nat_v6, `:300` nat64_prefix_map, `:328` nat64_prefix_map).
  - **`maps_session.go`**: 2 optional-if-ok (`:327` sessions, `:337` sessions_v6).
  - **`loader.go`**: 1 optional-if-ok (`:730` vlan_iface_map) + 2 nil-guards (`:591` interface_counters, `:700` iface_zone_map).
  - **`compiler.go`**: 1 nil-guard (`:353` redirect_capable).
  - **`maps_stale.go`**: 7 optional-if-ok in multi-map functions (`:224`, `:241`, `:285`, `:291`, `:322`, `:328`, `:336`) **PLUS 12 optional accesses** in single-map cleanup functions (`:18`, `:41`, `:65`, `:93`, `:117`, `:148`, `:178`, `:201`, `:262`, `:309`, `:348`, `:371` — e.g. `DeleteStaleIfaceZone`).
  - **`maps_stats.go`**: 1 optional loop lookup (`:72`).

* **Flaws in Plan v89**:
  1. **Arithmetic Error**: In [`plan.md:3`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3), [`:9`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L9), and [`:4969`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4969), the plan claims `13 optional-if-ok + 3 nil-guard = 16 sites`. However, in [`plan.md:4972-4984`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4972-L4984), the body text actually enumerates **14 optional-if-ok sites** ($4 + 7 + 2 + 1 = 14$):
     - `maps_nat.go`: 261, 274, 300, 328 (4)
     - `maps_stale.go`: 224, 241, 285, 291, 322, 328, 336 (7)
     - `maps_session.go`: 327, 337 (2)
     - `loader.go`: 730 (1)  
     $14 + 3 = 17$ sites. The plan's summary header ($13+3=16$) contradicts its own enumerated 14-item list.
  2. **Terminology Overclaim**: Calling this 17-site set *"the complete list"* or *"the true count"* of optional sites in `pkg/dataplane` is an overclaim. It represents only the **mixed / multi-access subset** of optional lookups, excluding the 12 single-map stale cleanups in `maps_stale.go` and `GetMapStats`.

---

#### 2. The Discriminating Oracle Verification
* **Codebase Mechanics**: [`pkg/dataplane/maps_nat.go:318-340`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L318-L340) (`ClearNAT64Configs`) accesses required `nat64_configs` (`:319`), optional `nat64_prefix_map` (`:328`), and required `nat64_count` via `SetNAT64Count(0)` (`:340` via `:309`).
* **Oracle Discrimination**:
  - If a buggy implementation treats an optional miss on `nat64_prefix_map` as an early `return nil`, execution never reaches `:340`, leaving `nat64_count` non-zero ($\rightarrow \text{FAIL}$).
  - A correct implementation skips the `:328` block on optional miss and proceeds to `:340`, setting `nat64_count` to $0$ ($\rightarrow \text{PASS}$).
* **Verdict on Oracle**: **VERIFIED DISCRIMINATING**. Asserting `ClearNAT64Configs() == nil` AND `nat64_count == 0` discriminates correct optional fallthrough from premature optional miss returns.

---

#### 3. Per-Access Gating Syntax Audit
* **Audit**: Verified that Class 1 is defined as *"contains at least one REQUIRED access"* with gating occurring **AT EACH REQUIRED ACCESS** ([`plan.md:3717-3725`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3717-L3725), [`:4236-4238`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4236-L4238), [`:4959-4965`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4959-L4965)).
* **Residual Check**: All old method-level gating phrasing (*"gate before the first Start-state access"*) has been updated.

---

#### 4. The `IsLoaded` Surface & Missing §9 Test Specification
* **Call Chain Verification**:
  - [`pkg/dataplane/loader.go:457`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L457): `Manager.IsLoaded() bool` (cited as `:456`)
  - [`pkg/dataplane/userspace/legacy_dataplane.go:86`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/legacy_dataplane.go#L86): `LegacyDataPlaneAdapter.IsLoaded() bool` (cited as `:86`)
  - [`pkg/api/health.go:107`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/api/health.go#L107): `DataplaneLoaded: s.dp != nil && s.dp.IsLoaded()` (in `statusHandler`, cited as `:104`)
  - [`pkg/grpcapi/server_show_status.go:22`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/grpcapi/server_show_status.go#L22): `DataplaneLoaded: s.dp != nil && s.dp.IsLoaded()` (in `GetStatus`, cited as `:19`)
* **Missing Test Leg**:
  - [`plan.md:25`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L25) and [`:3990-3994`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3990-L3994) state: *"The §9 teardown legs assert this directly: a status read during the Close window observes DataplaneLoaded==false from the entry Store..."*
  - **DEFECT**: Section 9 ([`plan.md:4657-5080`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4657-L5080)) **completely lacks any test leg** specifying the assertion for observing `DataplaneLoaded == false` during the `Close()` window.

---

### Blocking Issues for PR-1 `PLAN-READY`

1. **Section 9 Missing Test Specification**:
   Add the explicit test leg specification in Section 9 (`pkg/dataplane` / `pkg/api` test plan) to assert that calling REST `statusHandler` or gRPC `GetStatus` (or calling `Manager.IsLoaded()`) during an in-flight `Close()` entry window returns `DataplaneLoaded == false` due to the entry `loaded.Store(false)`.
2. **Inventory Arithmetic & Terminology Correction**:
   Correct the summary arithmetic in lines 3, 9, and 4969 from `13 + 3 = 16` to `14 optional-if-ok + 3 nil-guard = 17 sites` (matching the 14 enumerated optional-if-ok sites in the body), and qualify the list as the **mixed / multi-access subset** of optional map lookups in `pkg/dataplane` (distinguishing it from the 41 total optional accesses across `pkg/dataplane`).
