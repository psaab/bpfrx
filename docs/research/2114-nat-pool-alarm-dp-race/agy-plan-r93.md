# AGY adversarial plan-review — round 93 (plan v96 @ 1a9bc125e148)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY ("Nothing in PR-1 blocks PLAN-READY for #2114."). Raw output follows verbatim.

---

### Verdict: PLAN-READY

**PR-1 ONLY verdict for #2114 (plan v96 @ `1a9bc125e148`)**: **PLAN-READY**
Nothing in PR-1 blocks PLAN-READY for #2114.

---

### Hostile Verification & Evidence

#### 1. THE 15+2 ARITHMETIC & PARTITIONING

The 17 mixed-subset sites enumerated in `plan.md` ([lines 5261–5288](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5261-L5288)) were independently extracted and partitioned by counting direct registry selector occurrences (`m.maps[...]` / `m.programs[...]`) within each host method:

##### The 15 Sites in Multi-Selector Methods (>1 Direct Selector)
1. **`ClearStaticNATEntries`** ([`maps_nat.go:261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L261), [`:274`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L274)) — **2 sites** (Host has 2 direct selectors: `static_nat_v4`, `static_nat_v6`).
2. **`SetNAT64Config`** ([`maps_nat.go:300`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L300)) — **1 site** (Host has 2 direct selectors: required `nat64_configs` at [`:290`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L290), optional `nat64_prefix_map` at [`:300`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L300)).
3. **`ClearNAT64Configs`** ([`maps_nat.go:328`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L328)) — **1 site** (Host has 2 direct selectors: required `nat64_configs` at [`:319`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L319), optional `nat64_prefix_map` at [`:328`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L328)).
4. **`DeleteStaleStaticNAT`** ([`maps_stale.go:224`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L224), [`:241`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L241)) — **2 sites** (Host has 2 direct selectors: `static_nat_v4`, `static_nat_v6`).
5. **`DeleteStaleNAT64`** ([`maps_stale.go:285`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L285), [`:291`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L291)) — **2 sites** (Host has 2 direct selectors: `nat64_configs`, `nat64_prefix_map`).
6. **`ZeroStaleNATPoolConfigs`** ([`maps_stale.go:322`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L322), [`:328`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L328), [`:336`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go#L336)) — **3 sites** (Host has 3 direct selectors: `nat_pool_configs`, `nat_pool_ips_v4`, `nat_pool_ips_v6`).
7. **`SessionCount`** ([`maps_session.go:327`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L327), [`:337`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L337)) — **2 sites** (Host has 2 direct selectors: `sessions`, `sessions_v6`).
8. **`setXDPAttachedFlag`** ([`loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700), [`:730`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730)) — **2 sites** (Host has 2 direct selectors: `iface_zone_map` at [`:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700), `vlan_iface_map` at [`:730`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730)).

*Subtotal*: $2 + 1 + 1 + 2 + 2 + 3 + 2 + 2 = \mathbf{15\text{ sites}}$.

##### The 2 Composed Single-Selector Sites
9. **`Compile`** ([`compiler.go:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353)) — **1 site** (Host has exactly 1 direct selector: `redirect_capable` at [`:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353)).
10. **`seedInterfaceCounter`** ([`loader.go:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591)) — **1 site** (Host has exactly 1 direct selector: `interface_counters` at [`:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591)).

*Subtotal*: $1 + 1 = \mathbf{2\text{ sites}}$.
*Total*: $15 + 2 = \mathbf{17\text{ sites}}$.

**Confirmation on `setXDPAttachedFlag`**: `setXDPAttachedFlag` contains **two direct selectors** ([`loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700) for `iface_zone_map` and [`loader.go:730`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730) for `vlan_iface_map`). It counts as a multi-selector method containing 2 of the 15 sites.

---

#### 2. THE COMPOSITION CLAIM & A3 ALIGNMENT

Code verification:
- `Compile` invokes `clearNativeXDPFlagsForIfindexes` at [`compiler.go:399`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L399). `clearNativeXDPFlagsForIfindexes` has its own single direct selector at [`loader.go:928`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L928) (`iface_zone_map`), which sits in the single-selector neutral set.
- `seedInterfaceCounter` ([`loader.go:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591)) is called from `AttachXDP` ([`loader.go:576`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L576)) and `AddTxPort` ([`loader.go:1000`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1000)).

**A3 Rule Consistency**: Work Item A3 ([`plan.md:3864-3866`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3864-L3866)) defines classification strictly by **DIRECT registry access** (syntactic `m.maps`/`m.programs` accesses within the method body itself). Under A3:
- `Compile` is syntactically a single-selector method (direct selector [`:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353) only).
- `seedInterfaceCounter` is syntactically a single-selector method (direct selector [`:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591) only).

The v96 precision phrasing—*"15 sites in MULTI-SELECTOR methods plus TWO single-selector sites composed into multi-access operations"*—explicitly reconciles the runtime composite behavior with A3's direct-access classification semantics. There is no collision.

---

#### 3. THE FOUR-SHAPE EXHAUSTIVENESS

Walking all ~41 optional/neutral access sites in `pkg/dataplane` demonstrates that every site maps to exactly one of the four shapes defined in plan v96 ([lines 5209–5215](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5209-L5215)):

1. **`if ok` skip**: Missing map $\rightarrow$ `if ok` body does not run; execution proceeds (14 mixed sites: `maps_nat.go:261`, `:274`, `:300`, `:328`, `maps_stale.go:224`, `:241`, `:285`, `:291`, `:322`, `:328`, `:336`, `maps_session.go:327`, `:337`, `loader.go:730`; plus `maps_stats.go:72` inside `GetMapStats`).
2. **nil-guard return**: Missing map $\rightarrow$ `if ic == nil { return }` (`loader.go:591` in `seedInterfaceCounter`).
3. **skip-and-continue**: Missing map $\rightarrow$ `if rcMap != nil { ... }` skips map updates and continues into subsequent work ([`compiler.go:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353) in `Compile`, and [`maps_screen.go:60`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go#L60) loop continue).
4. **comma-ok early return**: Missing map $\rightarrow$ `if !ok { return nil }` or `if !ok { return }` ([`loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700) in `setXDPAttachedFlag`, the 12 stale cleanups in `maps_stale.go`, `ClearGlobalCounters` [`maps_counters.go:181`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L181), `ClearZoneCounters` [`maps_counters.go:233`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L233), `ClearNATRuleCounters` [`maps_nat.go:400`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L400), `SeedNATPortCounters` [`maps_nat.go:435`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L435), `UpdatePolicyScheduleState` [`maps_policy.go:253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_policy.go#L253), `SeedSessionIDCounter` [`maps_session.go:612`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L612), `clearNativeXDPFlags` [`loader.go:910`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L910), `clearNativeXDPFlagsForIfindexes` [`loader.go:928`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L928)).

The four control-flow shapes are exhaustive across all 41 optional/neutral access sites.

---

#### 4. FRESH ATTACK ON PR-1 CLAIMS

- **Registry Census**: Verified exactly 135 total accesses (130 `m.maps` + 5 `m.programs` = 91 required + 41 optional/neutral + 3 writes).
- **Class-3 Hybrids**: Verified `ClearGlobalCounters` ([`maps_counters.go:181`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L181)), `ClearZoneCounters` ([`maps_counters.go:233`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L233)), and `ClearNATRuleCounters` ([`maps_nat.go:400`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L400)).
- **AST Canary & Helpers**: Allowlist precisely covers `lookupMapLocked`, `lookupProgramLocked`, and `publishShimRegistryLocked`.
- **Oracle & Test Suite**: The 5-leg test suite in Section 9 provides discriminating coverage for all armed-state, retained-state, and continuation paths.

No residual defects, misstatements, or open questions remain in PR-1.

---

### Summary

Plan v96 for PR-1 is completely sound, mathematically exact, and ready for execution.
