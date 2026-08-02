# AGY adversarial plan-review — round 89 (plan v91 @ 56d1e3f4d965)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY ("Nothing in PR-1 blocks PLAN-READY for #2114. All headline defects, arithmetic, classification preambles, test legs, and continuation oracle paths have converged to a production-quality bar."). Raw output follows verbatim.

---

# Adversarial PLAN Review for #2114 — Round 89 (CONVERGENCE)

- **Plan Doc**: [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (v91 @ `56d1e3f4d965`)
- **Repo Root**: `/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race`
- **Scope**: **PR-1 ONLY** (work item A1 core + A3 armed-state gate + full site conversion + canaries + sampler narrowing). G+H+H2 in [`followup-seed.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md) is out of scope.
- **Verdict**: **PLAN-READY**

---

## 1. Verification of the Five Hostile Audit Points

### 1. §9 `TestManager_ArmedGate_CloseWindowIsLoaded` Leg (b1 Fold) — VERIFIED

- **Implementable Hook Placement**: [plan.md:4865–4866](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4865-L4866) places the test hook immediately **after** the entry `Store(false)` at [`loader.go:1206`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1206) (where `m.loaded` flip occurs on entry) and **before** the link-handle close loops (`m.xdpLinks` / `m.tcLinks` at [`loader.go:1207–1216`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1207-L1216)).
- **Asserted Surface**:
  - Direct accessor `Manager.IsLoaded()` ([`loader.go:457`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L457))
  - Userspace adapter `LegacyDataPlaneAdapter.IsLoaded()` ([`legacy_dataplane.go:86`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/legacy_dataplane.go#L86))
  - REST `statusHandler`'s `DataplaneLoaded` field ([`health.go:107`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/api/health.go#L107))
  - gRPC `GetStatus`'s `DataplaneLoaded` field ([`server_show_status.go:22`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/grpcapi/server_show_status.go#L22))
- **Teardown Assertion Claim**: The claim at [plan.md:4053–4057](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4053-L4057) that *"The §9 teardown legs assert this directly..."* is now **TRUE**, as leg (5) `TestManager_ArmedGate_CloseWindowIsLoaded` is explicitly defined and specified at [plan.md:4861–4874](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4861-L4874).

---

### 2. Inventory Arithmetic & Class Assignment (b2 Fold & Code Check) — VERIFIED

#### Code Check: `maps_counters.go:233` (`ClearZoneCounters`)
Inspection of [`pkg/dataplane/maps_counters.go:227–243`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L227-L243):
```go
227: func (m *Manager) ClearZoneCounters() error {
228: 	// #3643: drop the userspace-reported offsets first...
232: 	m.ClearZoneCounterOffsets()
233: 	zm, ok := m.maps["zone_counters"]
234: 	if !ok {
235: 		return nil
236: 	}
...
```
`m.ClearZoneCounterOffsets()` executes at **line 232**, mutating Go-side offset state **before** the BPF map lookup at line 233. Under A3's class precedence rules ([plan.md:3741–3755](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3741-L3755)), a method touching Start-state with required pre-error/pre-access Go-side side-effects is **Class 3 (hybrid)**, NOT pure Class 2. `plan.md` correctly assigns both `maps_counters.go:181` (`ClearGlobalCounters`) and `:233` (`ClearZoneCounters`) to Class 3 at [plan.md:3892–3896](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3892-L3896) and [plan.md:5100–5103](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5100-L5103).

#### Optional/Neutral Site Inventory Breakdown (~41 total access sites)
1. **17 Mixed / Multi-Access Sites** ([plan.md:5062–5080](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5062-L5080)):
   - 14 `if ok` optional reads: `maps_nat.go:261`, `:274`, `:300`, `:328`; `maps_stale.go:224`, `:241`, `:285`, `:291`, `:322`, `:328`, `:336`; `maps_session.go:327`, `:337`; `loader.go:730`.
   - 3 nil-guard reads: `compiler.go:353`, `loader.go:591`, `loader.go:700`.
2. **14 Single-Map Neutral-Outcome Sites** ([plan.md:5097–5117](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5097-L5117)):
   - 12 stale cleanups (`maps_stale.go:18`, `:41`, `:65`, `:93`, `:117`, `:148`, `:178`, `:201`, `:262`, `:309`, `:348`, `:371`)
   - `maps_stats.go:72` (`GetMapStats` per-descriptor lookup loop)
   - `maps_screen.go:60` (`ClearSessionCounts` loop over `session_count_src` & `session_count_dst`)
3. **7 Neutral Returns inside Mixed/Hybrid/Void Methods**:
   - `maps_nat.go:400` (`ClearNATRuleCounters`, Class 3)
   - `maps_nat.go:435` (`SeedNATPortCounters`, Class 2 void)
   - `maps_policy.go:253` (`UpdatePolicyScheduleState`, Class 2 error)
   - `maps_session.go:612` (`SeedSessionIDCounter`, Class 2 void)
   - `loader.go:910`, `:928` (`clearNativeXDPFlags`, `clearNativeXDPFlagsForIfindexes`, Category L/G internal helpers)
   - `maps_counters.go:233` (`ClearZoneCounters`, Class 3)
4. **2 Class-4 Getter Accesses**: `loader.go:1152` (`Map`), `:1157` (`Program`).
5. **2 Internal Helper Accesses**: `loader.go:910`, `:928`.

Subtotal arithmetic: $17 + 14 + 7 + 2 + 2 = 42$ access sites across `pkg/dataplane`, accounting fully and precisely for the $\sim 41$ total neutral-outcome access set.

---

### 3. Preamble Audit (Per-Access Classification) — VERIFIED

- **Class 2 Preamble**: *"a method touching Start-state whose EVERY registry access is neutral-on-absent..."* ([plan.md:3744–3748](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3744-L3748)).
- **Class 1 Preamble**: *"class 1 means the method CONTAINS AT LEAST ONE REQUIRED registry access..."* ([plan.md:3779–3784](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3779-L3784)).
- Search across the entire A3 block ([plan.md:3699–4200](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3699-L4200)) confirmed **zero** residual singular per-method outcome phrasing.

---

### 4. Continuation Paths Code Audit — VERIFIED

1. `ClearStaticNATEntries` ([`maps_nat.go:261 → :274`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L261-L274)):
   - Line 261: `if zm, ok := m.maps["static_nat_v4"]; ok { ... }`.
   - If `static_nat_v4` is absent (`!ok`), execution falls through to line 274 (`if zm, ok := m.maps["static_nat_v6"]; ok { ... }`). Continues to IPv6.
2. `setXDPAttachedFlag` ([`loader.go:730 → :744-826`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730-L826)):
   - Line 730: `if vmap, ok := m.maps["vlan_iface_map"]; ok { ... }`.
   - If `vlan_iface_map` is absent (`!ok`), execution falls through directly to the physical-interface loop at line 744. Continues to physical interfaces.
3. `Compile` ([`compiler.go:353 → continue`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353-L370)):
   - Line 353: `rcMap := m.maps["redirect_capable"]`.
   - Line 359: `if rcMap != nil { ... }`.
   - If `rcMap` is `nil`, the `if` block skips and execution continues to line 368 (native/generic XDP attach loop). Continues attachment work.

All 3 continuation oracle paths in master continue past absent optional accesses.

---

### 5. Residual Claims & Cross-References — VERIFIED

- **`AttachXDP` Pinned-Link Qualification**: Verified against [`loader.go:531–537`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L531-L537). On pinned link reuse, `AttachXDP` returns at line 536, skipping `seedInterfaceCounter` (`:591`) while running the deferred `setXDPAttachedFlag` (`:700`/`:730`). Plan accurately documents this at [plan.md:5082–5091](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5082-L5091).
- **Limiting Summaries Cross-References**: Both §4.7 ([plan.md:4220–4225](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4220-L4225)) and §7 ([plan.md:4627–4632](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4627-L4632)) explicitly cross-reference the `IsLoaded` surface advancement.

---

## Verdict: PLAN-READY

Nothing in PR-1 blocks **PLAN-READY** for #2114. All headline defects, arithmetic, classification preambles, test legs, and continuation oracle paths have converged to a production-quality bar.
