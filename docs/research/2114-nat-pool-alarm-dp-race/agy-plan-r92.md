# AGY adversarial plan-review — round 92 (plan v95 @ ddfd4e52203b)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY ("Blockers: NONE. Nothing in PR-1 blocks PLAN-READY for #2114."). Raw output follows verbatim.

---

# Adversarial PLAN Review: #2114 — Round 92 (CONVERGENCE), Plan v95

**Verdict**: `PLAN-READY`

**Blockers**: **NONE**. Nothing in PR-1 blocks `PLAN-READY` for #2114.

---

## Hostile Verification Report

### 1. The Label Consistency Sweep
Every normative label was searched across `plan.md` and verified against the Go implementation:

*   **`optional-if-ok`**: 14 sites across `pkg/dataplane/maps_nat.go`, `maps_stale.go`, `maps_session.go`, and `loader.go`. Syntactically, every single site uses the comma-ok idiom (`if zm, ok := m.maps[...]; ok` or `if ok`), where an absent map causes the conditional body to be skipped while the parent operation continues normally.
*   **`single-value read`**: Exactly 2 sites — [`pkg/dataplane/compiler.go:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353) (`rcMap := m.maps["redirect_capable"]`) and [`pkg/dataplane/loader.go:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591) (`ic := m.maps["interface_counters"]`). Neither uses comma-ok assignment.
*   **`comma-ok early return`**: Exactly 1 site — [`pkg/dataplane/loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700) (`zm, ok := m.maps["iface_zone_map"]` with `if !ok { return nil }`). It is a comma-ok TWO-value read that returns `nil` early on absence.
*   **`nil-guard`**: Syntactically applies ONLY to [`pkg/dataplane/loader.go:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591) (`if ic == nil { return }`). Plan v95 cleanly corrected the previous overgeneralized "nil-guard SKIPS" label in §9 to distinguish skip-and-continue from nil-guard return.
*   **`MULTI-ACCESS`**: Refers strictly to methods containing >1 registry access.
*   **`SINGLE-ACCESS-SELECTOR`**: Refers to syntactic selector sites for methods with only 1 registry access (e.g., `ClearSessionCounts` looping map names, `GetMapStats` looping descriptors).

**Result**: Zero label overloading, zero code-shape mismatches.

---

### 2. The 14 + 2 + 1 Split Verification
The 17 mixed/multi-access neutral sites break down into:

1.  **3 Other-Shape Reads**:
    *   [`pkg/dataplane/compiler.go:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353) (`redirect_capable`): Single-value read; skips redirect-map population on `nil` and continues into XDP attachment at L368.
    *   [`pkg/dataplane/loader.go:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591) (`interface_counters`): Single-value read; nil-guard return (`if ic == nil { return }`).
    *   [`pkg/dataplane/loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700) (`iface_zone_map`): Comma-ok TWO-value read; early return `nil` on `!ok` (`if !ok { return nil }`).
2.  **14 Optional-If-Ok Reads**:
    *   `maps_nat.go`: [`:261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L261) (`static_nat_v4`), [`:274`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L274) (`static_nat_v6`), [`:300`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L300) (`nat64_prefix_map`), [`:328`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L328) (`nat64_prefix_map`).
    *   `maps_stale.go`: [`:224`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L224) (`static_nat_v4`), [`:241`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L241) (`static_nat_v6`), [`:285`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L285) (`nat64_configs`), [`:291`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L291) (`nat64_prefix_map`), [`:322`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L322) (`nat_pool_configs`), [`:328`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L328) (`nat_pool_ips_v4`), [`:336`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L336) (`nat_pool_ips_v6`).
    *   `maps_session.go`: [`:327`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L327) (`sessions`), [`:337`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L337) (`sessions_v6`).
    *   `loader.go`: [`:730`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730) (`vlan_iface_map`).

**Result**: Verified. The 14+2+1 split equals exactly 17 sites.

---

### 3. Multi-Access Scoping Audit
Inspected the code signatures of the 4 methods highlighted in Codex minor-3:

*   [`DeleteStaleStaticNAT`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L223): `func (m *Manager) DeleteStaleStaticNAT(...)` — 2 accesses (`static_nat_v4` @ 224, `static_nat_v6` @ 241), void return (no `error`).
*   [`DeleteStaleNAT64`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L284): `func (m *Manager) DeleteStaleNAT64(...)` — 2 accesses (`nat64_configs` @ 285, `nat64_prefix_map` @ 291), void return (no `error`).
*   [`ZeroStaleNATPoolConfigs`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L321): `func (m *Manager) ZeroStaleNATPoolConfigs(...)` — 3 accesses (`nat_pool_configs` @ 322, `nat_pool_ips_v4` @ 328, `nat_pool_ips_v6` @ 336), void return (no `error`).
*   [`SessionCount`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L326): `func (m *Manager) SessionCount() (v4, v6 int)` — 2 accesses (`sessions` @ 327, `sessions_v6` @ 337), integer return (no `error`).

**Result**: Scoping as "MULTI-ACCESS methods" is factually true and precise. The prior v90 phrasing ("methods that ALSO carry a required access or an error signature") was false for these 4 methods.

---

### 4. Census Arithmetic Sweep
The full access inventory across `pkg/dataplane` is verified as:
$$\text{Total Accesses} = 135 = 130\ (\text{m.maps}) + 5\ (\text{m.programs}) = 91\ (\text{required}) + 41\ (\text{optional}) + 3\ (\text{writes})$$

The 41 optional accesses break down into:
*   **17 Mixed / Multi-Access Optional Sites** (14 optional-if-ok + 2 single-value + 1 comma-ok early return)
*   **24 Single-Access-Selector Neutral Sites** (12 stale cleanups, 1 global counter, 1 map stat, 6 void/single-access neutral returns, 1 nat_rule_counter class-3 hybrid, 2 class-4 getters, 1 screen config).

**Result**: $17 + 24 = 41$. Every census reference in `plan.md` (lines 26, 61, 5960) aligns with 135 = 91 + 41 + 3. No conflicting figures exist in the document.

---

### 5. Final Attack & PR-1 Isolation Check
*   **PR-1 Scope**: Consists solely of `d.dp` core (`atomic.Pointer[Manager]`), A3 armed-state gate, full site conversion, AST canary enforcement, and structural sampler status provider (`CachedStatusProvider`).
*   **Follow-up Scope (G+H+H2)**: Fully segregated into `followup-seed.md`. PR-1 contains zero code dependencies on startup gates or confirm-record tombstones.
*   **Tri-Site Detach Consistency**: `DetachXDP` treatment across A3, §5.1, and §9 is in 100% agreement. `TestManager_ArmedGate_DetachRetainedClaims` explicitly seeds `iface_zone_map` to exercise both in-memory claim cleanup and BPF map removal.

---

## Conclusion

Plan v95 is complete, mathematically sound, syntactically accurate to the Go codebase, and ready for implementation.

**Verdict: `PLAN-READY`**
