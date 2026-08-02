# Codex adversarial plan-review — round 95 (plan v98 @ f9137e30ee67)

Codex companion task-msbi1nt2-zpgm60 (session 019fc172-cf2d-73a2-9dd1-8cc236964e3d). Verdict: PLAN-NEEDS-MINOR (1 minor — "the r94 behavioral fold itself is correct; this is not a design major"): the extensional 17-site oracle inventory is load-bearing but mechanically unchecked (a missing site would be silent — the definition and its coextensive tests would both simply omit it; no specified mechanism checks code↔list equality: the registry canary only forbids raw access outside the two helpers + publisher, TestManager_PreArmMethodMatrix inventories methods not per-access roles, and the plan expressly leaves semantic labels to handwritten review). Required fix: a stale-checked helper-callsite manifest mapping every registry read to required/optional outcome, with the 17 mixed sites mapped to their named semantic legs — it need not infer semantics, only force explicit review when callsites change. Fold-free verification: all 17 sites have coverage (the per-site table maps each to its named leg); the three new legs match real control flow and are compatible with the two-state/whole-batch design; the absent-iface_zone_map fixture is separate from the Detach fixture; the pattern-not-membership wording correct; A3/§7/§9 otherwise agree; no G+H+H2 dependency. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MINOR

Yes—one PR-1 assurance gap still blocks `PLAN-READY`. The r94 behavioral fold itself is correct; this is not a design major.

1. **MINOR — the extensional 17-site oracle inventory is load-bearing but mechanically unchecked.**

   The current list is complete, but a missing site would be silent: the definition and its purportedly coextensive tests would both simply omit it ([plan.md:5303](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5303)).

   No specified mechanism checks code↔list equality:

   - The registry canary only forbids raw `m.maps`/`m.programs` access outside the two helpers and publisher ([plan.md:5222](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5222)). An omitted or newly added `lookupMapLocked` call therefore passes.
   - `TestManager_PreArmMethodMatrix` inventories exported methods, not per-access required/optional roles ([plan.md:5144](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5144)).
   - The plan expressly leaves semantic labels to handwritten review ([plan.md:3955](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3955)) and says the canary cannot distinguish required from optional consumption—the continuation legs are the only net ([plan.md:5497](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5497)).

   Require a stale-checked helper-callsite manifest mapping every registry read to required/optional outcome, with the 17 mixed sites mapped to their named semantic legs. This need not infer semantics; it only needs to force explicit review when callsites change.

### Fold verification

All current 17 sites do have coverage:

| Sites | Count | Named coverage |
|---|---:|---|
| `ClearStaticNATEntries` [`:261`, `:274`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:261>) | 2 | Fresh/retained outcomes plus absent-v4→present-v6 continuation |
| `SetNAT64Config` [`:299`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:299>) | 1 | New required-present/optional-absent leg |
| `ClearNAT64Configs` [`:328`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:328>) | 1 | Required→optional→required/count-zeroed leg |
| Stale cleanup selectors [`:224`, `:241`, `:285`, `:291`, `:322`, `:328`, `:336`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go:224>) | 7 | Named all-maps-processed pattern |
| `SessionCount` [`:327`, `:337`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:327>) | 2 | v4/v6 reporting pattern |
| `setXDPAttachedFlag` VLAN lookup [`:730`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:730>) | 1 | Absent VLAN map→physical processing |
| `Compile` [`:353`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353>) | 1 | Absent redirect map→attachment continuation |
| `seedInterfaceCounter` [`:591`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:591>) | 1 | New absent/present pair |
| `setXDPAttachedFlag` iface lookup [`:700`](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700>) | 1 | New absent-map nil/no-claims leg |

The three new legs match real control flow and are compatible with the two-state/whole-batch design. The absent-`iface_zone_map` fixture is separate from the Detach fixture that deliberately seeds that map present ([plan.md:5541](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5541)).

`ClearSessionCounts` and `GetMapStats` each have one syntactic selector inside a loop over multiple runtime map names/descriptors ([maps_screen.go:58](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go:58), [maps_stats.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go:69)); the pattern-not-membership wording is correct.

A3, §7, and §9 otherwise agree. No G+H+H2 dependency was considered. Reviewed against `f9137e30ee67`; no files changed.

Codex session ID: 019fc172-cf2d-73a2-9dd1-8cc236964e3d
Resume in Codex: codex resume 019fc172-cf2d-73a2-9dd1-8cc236964e3d
