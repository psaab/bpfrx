# AGY adversarial plan-review — round 91 (plan v93 @ 9a30b5087a4a)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-NEEDS-MINOR (exactly ONE residual: the summary line at plan.md:5149 still said "3 nil-guard reads" after the v93 body rename — "Once this single string correction is folded, PR-1 will be completely converged and PLAN-READY"; NO MAJOR deflations or blockers, "nothing in PR-1's technical design blocks implementation"). Raw output follows verbatim.

---

# Adversarial PLAN Review for #2114 (v93 @ `9a30b5087a4a`)

**Verdict**: **PLAN-NEEDS-MINOR**  
**PR-1 Blocking Status**: **NO MAJOR DEFLATIONS OR BLOCKERS.** Nothing in PR-1's technical design blocks implementation. A single document-consistency minor residual remains on line 5149.

---

## 1. Hostile Audit of the Four Folded Minors

### (a) Three-Way Per-Site Outcome Phrasing & Bucket Rename
- **Rule Phrasing**: Verified at [`plan.md:5142-5144`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5142-L5144). It explicitly reads: `"the if ok body does not run, the nil-guard returns, OR the skip-and-continue proceeds past the skipped block"`.
- **Per-Site Behavior Verification**:
  - `compiler.go:353` (`redirect_capable`): Verified at [`compiler.go:353-366`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353-L366). If `rcMap == nil`, the update loop is skipped and control continues to line 368 (`// Try native XDP first...`).
  - `loader.go:591` (`interface_counters`): Verified at [`loader.go:591-594`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591-L594). `if ic == nil { return }` — a true nil-guard return.
  - `loader.go:700` (`iface_zone_map`): Verified at [`loader.go:700-705`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700-L705). `zm, ok := m.maps["iface_zone_map"]; if !ok { return nil }` — a comma-ok early return.
- 🚨 **RESIDUAL MINOR DEFECT**: Line 5149 in §9 item 4a contains a missed instance of the old bucket label:
  - [`plan.md:5149`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5149): `14 optional-if-ok reads + 3 nil-guard reads = 17 sites;`
  - While line 8 claims the bucket was renamed from `"3 nil-guard reads"` to `"three non-comma-ok single-value reads"`, and line 5171 uses the new label, line 5149 was missed in the v93 fold. It should be: `14 optional-if-ok reads + 3 non-comma-ok single-value reads = 17 sites;`.

### (b) A3 + §5.1 + §9 Detach Consistency
- Verified all three sites carry the `iface_zone_map`-seeding + absent-map-no-op qualification:
  - **A3**: [`plan.md:4043`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4043) (`(with the §9 qualification... a usable iface_zone_map seeded, and "always runs" excludes master's absent-iface_zone_map no-op at loader.go:700...)`).
  - **§5.1**: [`plan.md:4388`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4388) (`(with the same §9 qualification... a usable iface_zone_map seeded, the absent-map no-op excluded)`).
  - **§9**: [`plan.md:5338`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5338) (`"cleanup always runs" means UNLESS a discovery failure returns first... AND EXCLUDES the absent-iface_zone_map no-op`).

### (c) Single-Registry-Access / Void-Host Enumeration & Source Pin
- **Void-Host Enumeration**: Verified at [`plan.md:5233-5238`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5233-L5238). Accurately names the four void hosts (`SeedNATPortCounters`, `SeedSessionIDCounter`, `clearNativeXDPFlags` @ `loader.go:909`, `clearNativeXDPFlagsForIfindexes` @ `loader.go:927`) and two error-returning hosts (`UpdatePolicyScheduleState`, `ClearZoneCounters`).
- **Source Pin**: Verified against [`maps_nat.go:399-400`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L399-L400): line 399 is `m.ClearNATRuleCounterOffsets()` (offset reset), line 400 is `zm, ok := m.maps["nat_rule_counters"]` (sole map lookup).

### (d) Count Label Update
- Verified at [`plan.md:3929`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3929): `"leaving 22 best-fit class-2 METHODS"`. All stale `"lookups"` occurrences for this count have been eliminated.

---

## 2. Cross-Section Sweep

- Checked all qualified A3 claims against summaries in §4.7, §6, §7, and §8:
  - **Close-entry `loaded=false` timing change**: All summaries ([`§4.7:4283`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4283), [`§6:4700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4700), [`§7:4766`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4766), [`§8:4801`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4801)) consistently qualify this narrowing to the `loaded-check set` admission + the externally observable `IsLoaded()` surface.
  - **Pre-arm rejections / Carve-outs**: Consistently qualified across §4, §6, §7, §8.
- No residual unconditional summaries were found across §4.7, §6, §7, or §8.

---

## 3. Five-Leg Oracle Protocol Verification

- Checked the five test legs in §9 ([`plan.md:4932-4950`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4932-L4950)):
  1. `(1)` `TestManager_ArmedGate_FreshOutcomes` — Quiescent FRESH (0 hooks).
  2. `(2)` `TestManager_ArmedGate_RetainedOutcomes` — Quiescent RETAINED (0 hooks).
  3. `(3)` `TestManager_ArmedGate_BlockedStart` — Blocked FRESH-Start (1 hook: in-batch hold in `Start`).
  4. `(4)` `TestManager_ArmedGate_RetainedReStartOverlap` — Blocked RETAINED-re-Start (1 hook: in-batch hold in `Start`).
  5. `(5)` `TestManager_ArmedGate_CloseWindowIsLoaded` — Close-window `IsLoaded` (1 hook: Close-entry hook after `Store(false)`).
- Every leg uses strictly $\le 1$ hook per test execution context. The protocol is instance-scoped and fully implementable.

---

## 4. Fresh Attack on PR-1

- **Memory Ordering & Reflection**: `dpCell atomic.Pointer[dpSlot]` load/store semantics guarantee sequential consistency / acquire-release ordering for interface publication. The reflection-based nillability guard correctly handles nillable kinds (pointers, slices, maps, chans, funcs) without panicking on value structs.
- **Lock Ordering & Concurrency**: The `m.mu` whole-batch publication in `publishShimRegistryLocked` combined with `loaded.Store(true)` ensures that readers released from the lock always observe a fully-populated registry.
- **Canary Enforcement**: Dual AST canaries (`pkg/dataplane/retirement_boundary_canary_test.go` and `pkg/daemon/daemon_dp_canary_test.go`) structurally prevent ungated field access outside defined accessors.

---

## Summary of Actionable Items for Convergence (v94)

1. **Line 5149 Residual**: Change `3 nil-guard reads` to `3 non-comma-ok single-value reads` at [`plan.md:5149`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5149).

Once this single string correction is folded, PR-1 will be completely converged and **PLAN-READY**.
