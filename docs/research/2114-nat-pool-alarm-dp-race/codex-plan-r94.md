# Codex adversarial plan-review — round 94 (plan v97 @ 3dd09a5de908)

Codex companion task-msbh4im4-4wr1gx (session 019fc15b-35b4-7e51-9fff-911abb0281b6). Verdict: PLAN-NEEDS-MAJOR (1 MAJOR — the oracle-role definition is non-exclusive and leaves real absent-outcome gaps: §9 applies the continuation oracle to ClearSessionCounts/GetMapStats (OUTSIDE the 17), while three intended sites have no named leg — SetNAT64Config's optional nat64_prefix_map (the generic fresh oracle stops at required nat64_configs first), seedInterfaceCounter's interface_counters, and setXDPAttachedFlag's absent-iface_zone_map path (the Detach leg requires the map PRESENT); the criterion selects at least 19 sites while failing to map at least three intended sites. Material because the AST canary cannot distinguish required from optional consumption and the continuation legs are the only semantic net). Fold-2 verification (fold-free): the five-shape taxonomy correct and disjoint with the per-file breakdown table (14+1+3+21+2 = 41 matching per-file 1+7+2+6+1+1+3+19+1); no double count (classification follows the absent-key branch — loader.go:730 is an if-ok skip because absence continues at :744 even though its present body can return an error); the A3/§7/§9 cross-block agreement otherwise intact; no additional synchronization hazard, taxonomy defect, or G+H+H2 leakage. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR

Reviewed PR-1 only at `3dd09a5de908`. One major finding blocks convergence.

1. **MAJOR — fold 1 fails: the oracle-role definition is non-exclusive and leaves real absent-outcome gaps.**

   [plan.md:5270](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5270>) defines the 17 sites as those whose absent outcomes §9 exercises. It does not:

   - `SetNAT64Config`: the generic fresh oracle stops first at required `nat64_configs`; it cannot reach optional `nat64_prefix_map` at [maps_nat.go:299](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:299>). The only named NAT64 partial-registry leg now exercises `ClearNAT64Configs`, not this site ([plan.md:5412](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5412>)).
   - `seedInterfaceCounter`: [loader.go:591](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:591>) has no required-present/`interface_counters`-absent fixture.
   - `setXDPAttachedFlag`: absent `iface_zone_map` returns nil at [loader.go:700](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700>). The Detach oracle instead requires that map present and expressly excludes absence ([plan.md:5480](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5480>), [plan.md:5495](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5495>)).

   Conversely, §9 explicitly applies the same continuation oracle to `ClearSessionCounts` and `GetMapStats` ([plan.md:5419](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5419>)), although both are assigned outside the 17-site set at [plan.md:5295](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5295>). Thus the criterion selects at least 19 sites while failing to map at least three intended sites.

   The extensional list identifies the intended 17, but cannot rescue the defining predicate. This is material because the AST canary cannot distinguish required from optional consumption ([plan.md:5402](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5402>)), and the plan calls the continuation legs the only such semantic net ([plan.md:5434](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5434>)). Wrong handling can turn `SetNAT64Config` success into error or make `DetachXDP` abort before link cleanup.

### Fold 2 verification

The five-shape taxonomy is correct and disjoint:

| File | Optional-site breakdown | Total |
|---|---|---:|
| compiler | 1 skip/continue | 1 |
| loader | 1 if-ok + 1 nil-guard + 3 early-return + 2 direct-nil | 7 |
| counters | 2 early-return | 2 |
| NAT | 4 if-ok + 2 early-return | 6 |
| policy | 1 early-return | 1 |
| screen | 1 continue | 1 |
| session | 2 if-ok + 1 early-return | 3 |
| stale | 7 if-ok + 12 early-return | 19 |
| stats | 1 continue | 1 |

Therefore `14 + 1 + 3 + 21 + 2 = 41`, matching the per-file `1+7+2+6+1+1+3+19+1`.

There is no double count: classification follows the absent-key branch. For example, [loader.go:730](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:730>) is an if-ok skip because absence continues at `:744`, even though its present body can return an error.

Apart from finding 1, the A3 block, §7, and §9 agree on state classification, loaded-check carve-outs, Close-window behavior, Detach qualifications, and teardown exclusions. I found no additional synchronization hazard, taxonomy defect, or G+H+H2 leakage.

**Yes: finding 1 is within PR-1 and blocks `PLAN-READY` for #2114.** No files were changed.

Codex session ID: 019fc15b-35b4-7e51-9fff-911abb0281b6
Resume in Codex: codex resume 019fc15b-35b4-7e51-9fff-911abb0281b6
