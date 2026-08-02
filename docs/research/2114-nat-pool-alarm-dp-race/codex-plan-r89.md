# Codex adversarial plan-review — round 89 (plan v91 @ 56d1e3f4d965)

Codex companion task-msbcv8ah-okiitj (session 019fc0ee-1554-7f92-bb6c-2e37957d589d). Verdict: PLAN-NEEDS-MINOR (5 minors, no MAJOR — the first all-minor Codex verdict since r68): m1 the optional-site class partition incomplete (maps_nat.go:400 omitted from the class-3 assignment; the "OTHER accesses are required" claim false for the five single-access methods; the exact census 135 = 91 required + 41 optional + 3 writes, per-file counts given — the "79 required" arithmetic does not reconcile); m2 the generic optional rule's "simply returns" contradicts the Compile continuation (compiler.go:353 skips and continues; loader.go:700 is comma-ok early return not a nil guard); m3 §6/§8 still omit the externally visible Close-window change; m4 the Detach oracle does not seed the iface_zone_map its asserted cleanup requires (absent → loader.go:700 early return before claim discovery); m5 §9 stale four-leg bookkeeping after adding leg 5. Verified folds (fold-free): the Close-window leg implementable; the class-3 assignments correct; all three continuation paths real; the pinned-link reuse confirmed; the per-access preamble; the §4.7/§7 cross-references; no G+H+H2 leakage. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MINOR

Yes. Five PR-1 plan inconsistencies still block `PLAN-READY` for #2114. None requires architectural redesign.

1. **MINOR — the optional-site class partition is still incomplete.**

   The omitted 24 optional sites correctly divide as:

   `17 class-2 + 3 class-3 + 2 class-4 + 2 internal = 24`

   The three class-3 sites are `maps_counters.go:181/:233` and `maps_nat.go:400`. V91 assigns only the counter pair at [plan.md:5097](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5097>), omitting `maps_nat.go:400`, although A3 correctly lists `ClearNATRuleCounters` as class-3 at [plan.md:3890](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3890>). The source resets offsets before its sole registry lookup at [maps_nat.go:399](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:399>).

   The follow-on claim that the seven “mixed-method neutral-returns” have “OTHER accesses [that] are required” is false at [plan.md:5118](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5118>). `ClearNATRuleCounters`, `ClearZoneCounters`, `SeedNATPortCounters`, `UpdatePolicyScheduleState`, and `SeedSessionIDCounter` each have only that one registry access.

   The exact census is:

   `135 = 91 required reads + 41 optional reads + 3 publisher writes`

   Per-file required/optional counts are: compiler 0/1, loader 9/7, counters 3/2, fabric 5/0, filter 10/0, flow 2/0, mirror 2/0, NAT 25/6, policy 17/1, screen 4/1, session 14/3, stale 0/19, stats 0/1.

   Therefore `79 required + 41 optional + writes/getters` does **not** reconcile. `Map`/`Program` at [loader.go:1152](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1152>) are already among the 41 optional reads; `NewEventSource` at [loader.go:1162](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1162>) is among the 91 required reads.

2. **MINOR — the generic optional-access rule contradicts the new `Compile` continuation oracle.**

   The normative text says an optional nil guard “simply returns” at [plan.md:5049](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5049>). But `Compile`’s missing `redirect_capable` access at [compiler.go:353](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353>) skips population and continues into attachment work at [compiler.go:368](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:368>). V91 itself correctly says “it does not return” at [plan.md:5153](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5153>).

   The rule should require preserving each site’s exact skip/continue/return behavior. Also, `loader.go:700` is a comma-ok early return, not syntactically a nil guard.

3. **MINOR — §6 and §8 still omit the externally visible Close-window change.**

   A3 and §7 now correctly name both loaded-check rejection and direct `IsLoaded` observability at [plan.md:4044](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4044>) and [plan.md:4689](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4689>). However, §6 still describes the divergence only as loaded-check admission narrowing at [plan.md:4626](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4626>), and §8 repeats that incomplete summary at [plan.md:4725](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4725>).

   REST and gRPC expose the bit directly at [health.go:107](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/api/health.go:107>) and [server_show_status.go:22](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/grpcapi/server_show_status.go:22>). Those summaries need the same qualification as §4.7/§7.

4. **MINOR — the Detach oracle does not guarantee the map required for its asserted cleanup.**

   The plan says claim cleanup “always runs” at [plan.md:3979](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3979>) and specifies a test seeding only `xdpLinks` and `xdpFlagClaims` at [plan.md:5202](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5202>). But absent `iface_zone_map` returns nil at [loader.go:700](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700>), before claim discovery and deletion at [loader.go:711](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:711>) and [loader.go:777](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:777>).

   The test must explicitly seed/seam a usable `iface_zone_map`; “always runs” must exclude the preserved absent-map no-op. Relatedly, pinned AttachXDP always executes the defer, but `:730` is reached only if the earlier `:700` selection succeeds.

5. **MINOR — §9 still has stale four-leg bookkeeping after adding leg five.**

   Section 9 calls four legs the “complete” set at [plan.md:4849](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4849>), then enumerates the fifth Close-window leg at [plan.md:4861](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4861>). “Four-leg form” also survives at [plan.md:4941](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4941>). Immediately after describing the Close hook after `Store(false)`, [plan.md:4875](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4875>) silently switches to discussing the separate Start hook before `Store(true)`.

Verified folds:

- The Close-window leg is implementable, and §9 now directly requires the early `IsLoaded`/REST/gRPC observation.
- `ClearGlobalCounters` and `ClearZoneCounters` are correctly class-3: both reset Go offsets before lookup.
- All three new continuation paths match the code.
- Pinned-link reuse returns at `loader.go:536`, skips the seed, and runs the deferred helper.
- The A3 partition preamble is now per-access.
- §4.7 and §7 contain the requested `IsLoaded` cross-reference.
- No G+H+H2 dependency leaked into PR-1.

Nothing architectural blocks convergence, but the five PR-1 minors above block `PLAN-READY` as written.

Codex session ID: 019fc0ee-1554-7f92-bb6c-2e37957d589d
Resume in Codex: codex resume 019fc0ee-1554-7f92-bb6c-2e37957d589d
