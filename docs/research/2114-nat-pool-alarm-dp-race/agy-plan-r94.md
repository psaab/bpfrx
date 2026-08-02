# AGY adversarial plan-review — round 94 (plan v97 @ 3dd09a5de908)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (PR-1 ONLY — "Nothing in PR-1 blocks PLAN-READY for #2114. The v97 plan @ 3dd09a5de908 is completely converged, hostiles-checked, and sound."). Raw output follows verbatim.

---

### Verdict: **PLAN-READY** (PR-1 ONLY)

Nothing in PR-1 blocks `PLAN-READY` for #2114. The v97 plan @ `3dd09a5de908` is completely converged, hostiles-checked, and sound.

---

### 1. THE ORACLE-ROLE DEFINITION

* **Circularity Analysis**:
  * **Not Circular**: The 17-site subset is extensionally defined by its exact 17 file:line locations ([plan.md:L5302–5328](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5302-L5328)). Framing the subset by its **§9 oracle role** clarifies why these 17 sites are distinguished from the 24 single-access-selector neutral sites: they are precisely the optional read sites where an absent map must **not** abort execution of subsequent operations in the host method or composition chain. The structural description ("15 sites in multi-selector methods + 2 single-selector sites composed into multi-access operations") is a valid, non-defining property of those 17 sites ([plan.md:L5279–5289](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5279-L5289)).

* **Coverage Gap Audit**:
  * **Zero Coverage Gaps**: Every single one of the 17 sites is explicitly covered by §9's partial-registry and continuation oracle legs ([plan.md:L5405–5437](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5405-L5437)):
    1. `ClearNAT64Configs` (`nat64_prefix_map` at [`maps_nat.go:328`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L328)): Exercises `nat64_configs` present + `nat64_prefix_map` absent, asserting trailing `nat64_count` zeroing.
    2. `SetNAT64Config` (`nat64_prefix_map` at [`maps_nat.go:300`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L300)): Exercises required `nat64_configs` present + optional `nat64_prefix_map` absent.
    3. `ClearStaticNATEntries` (`static_nat_v4` at [`maps_nat.go:261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L261), `static_nat_v6` at [`maps_nat.go:274`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L274)): Exercises continuation from absent v4 to v6.
    4. `DeleteStaleStaticNAT` / `DeleteStaleNAT64` / `ZeroStaleNATPoolConfigs` (7 sites at [`maps_stale.go:224, 241, 285, 291, 322, 328, 336`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go)): Multi-map stale cleanup continuation legs.
    5. `SessionCount` (`sessions` at [`maps_session.go:327`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L327), `sessions_v6` at [`maps_session.go:337`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L337)): Exercises v4+v6 report continuation.
    6. `AttachXDP` / `seedInterfaceCounter` / `setXDPAttachedFlag` (`interface_counters` at [`loader.go:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591), `iface_zone_map` at [`loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700), `vlan_iface_map` at [`loader.go:730`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730)): Exercises program lookup → optional seed → deferred access continuation.
    7. `Compile` (`redirect_capable` at [`compiler.go:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353)): Exercises continuation past skipped redirect population into attachment work.

---

### 2. THE 41-READ BREAKDOWN

* **Arithmetic Verification**:
  $$\text{Shapes}: 14 \text{ (if-ok)} + 1 \text{ (nil-guard)} + 3 \text{ (skip/continue)} + 21 \text{ (comma-ok early return)} + 2 \text{ (direct nil)} = 41$$
  $$\text{Per-File}: 1 + 7 + 2 + 6 + 1 + 1 + 3 + 19 + 1 = 41$$
  Both arithmetic identity sums match exactly.

* **Per-File Code Base Verification**:
  * `compiler.go`: **1** ([`compiler.go:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353) `redirect_capable` skip-and-continue)
  * `loader.go`: **7** ([`:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591) `interface_counters` nil-guard, [`:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700) `iface_zone_map` comma-ok early return, [`:730`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730) `vlan_iface_map` if-ok, [`:910`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L910) `iface_zone_map` comma-ok early return, [`:928`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L928) `iface_zone_map` comma-ok early return, [`:1152`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1152) `Map` direct nil, [`:1157`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1157) `Program` direct nil)
  * `maps_counters.go`: **2** ([`:181`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L181) `global_counters`, [`:233`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L233) `zone_counters` comma-ok early returns)
  * `maps_nat.go`: **6** ([`:261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L261) `static_nat_v4`, [`:274`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L274) `static_nat_v6`, [`:300`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L300) `nat64_prefix_map`, [`:328`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L328) `nat64_prefix_map` if-ok skips; [`:400`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L400) `nat_rule_counters`, [`:435`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L435) `nat_port_counters` comma-ok early returns)
  * `maps_policy.go`: **1** ([`:253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_policy.go#L253) `policy_rules` comma-ok early return)
  * `maps_screen.go`: **1** ([`:60`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go#L60) `iface_screen_map` comma-ok early return)
  * `maps_session.go`: **3** ([`:327`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L327) `sessions`, [`:337`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L337) `sessions_v6` if-ok skips; [`:612`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L612) `session_id_gen` comma-ok early return)
  * `maps_stale.go`: **19** (12 comma-ok early returns at [`:18, 41, 65, 93, 117, 148, 178, 201, 262, 309, 348, 371`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go); 7 if-ok skips at [`:224, 241, 285, 291, 322, 328, 336`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go))
  * `maps_stats.go`: **1** ([`:72`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go#L72) `bm, ok := m.maps[rm.name]; if !ok || bm == nil { continue }` skip-and-continue)

---

### 3. THE SHAPE TAXONOMY

* **Mutual Exclusivity & No Double Counting**:
  The 5 syntactic/control-flow shapes partition the 41 optional reads without overlap:
  1. **Direct nil returns** (2): `return m.maps[...]` / `return m.programs[...]` — No `if` statement.
  2. **Nil-guard return** (1): `ic := m.maps[...]`; `if ic == nil { return }` — Single-value assignment with explicit `nil` check returning from a void function.
  3. **Skip-and-continue** (3): Single-value or comma-ok lookup where missing map skips a sub-task or loop iteration (`continue`) and proceeds into subsequent code (`compiler.go:353`, `maps_stats.go:72`).
  4. **Comma-ok early returns** (21): `m, ok := m.maps[...]`; `if !ok { return ... }` — Comma-ok read where `!ok` immediately terminates host function execution.
  5. **If-ok skips** (14): `if m, ok := m.maps[...]`; `ok { ... }` — Comma-ok read where `!ok` skips the `if` block and control falls through to subsequent statements in the function.

---

### 4. FRESH ATTACK ON OTHER PR-1 CLAIMS

* **Publication Cell & Typed-Nil Safety**: `setDataplane(dp)` uses `reflect.ValueOf(dp).Kind()` to guard pointer/map/func/slice/chan kinds before calling `v.IsNil()` ([plan.md:L3733–3748](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3733-L3748)). This prevents `reflect.IsNil` panics on struct values while correctly filtering typed-nil interface values.
* **Compiler Enforcement**: Renaming `d.dp` to `d.dpCell` guarantees complete conversion across `pkg/daemon` at compile time.
* **fwdstatus Narrowing**: Retyping the daemon adapter to satisfy only `fwdstatus.CachedStatusProvider` prevents misrouting into `Build` paths ([plan.md:L3795–3840](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3795-L3840)).
* **A3 Gate & Classification Totality**: The two-state gate (`loaded` atomic + `m.mu` registry classification) properly handles fresh vs retained states across all 4 method classes + categories G/L/F.
* **§9 Test Harness**: Uses a two-sided barrier without channels between conflicting accesses ([plan.md:L4949–4970](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4949-L4970)), preventing false race-clean results.

---

### Conclusion

PR-1 is fully converged and **PLAN-READY**. Nothing blocks proceeding with PR-1.
