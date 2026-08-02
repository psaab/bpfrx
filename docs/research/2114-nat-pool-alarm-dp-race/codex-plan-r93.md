# Codex adversarial plan-review — round 93 (plan v96 @ 1a9bc125e148)

Codex companion task-msbgkhfm-zvcspx (session 019fc14c-f2be-7112-b457-19e194a5b6fa). Verdict: PLAN-NEEDS-MINOR (2 documentation-only minors, NO MAJOR — "No architectural, synchronization, or oracle redesign is needed"): m1 MULTI-ACCESS OPERATIONS still does not define an exhaustive 17/24 partition (the 15+2 arithmetic is correct and both compositions are real, but the transitive "operation" criterion makes loader.go:928 necessarily a third composed site — yet it sits in the single-selector remainder — and ClearSessionCounts/GetMapStats are single-selector-but-multi-runtime-map; the fix is to describe the host shapes of the chosen 17 without claiming transitivity-exhaustiveness); m2 the four optional-read shapes are not exhaustive across all 41 reads (the class-4 Map/Program getters at loader.go:1152/:1157 return nil directly on missing keys — none of the four named shapes; the complete breakdown is 14 if-ok skips + 1 nil-guard return + 3 skip/continue outcomes + 21 comma-ok early returns + 2 direct nil returns = 41). Fold-free passes: the 15+2 arithmetic itself correct; both compositions real; the three other-shape occurrences mutually consistent; the full A3/§7/§9 read consistent; no PR-1 regression, synchronization hazard, oracle gap, teardown overclaim, or G+H+H2 leakage. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MINOR

Two documentation-only minors remain. No architectural, synchronization, or oracle redesign is needed.

1. **MINOR — `MULTI-ACCESS OPERATIONS` still does not define an exhaustive 17/24 partition.**

   The `15 + 2` arithmetic is correct:

   - 13 if-ok sites outside `setXDPAttachedFlag`, plus its two direct selectors at [loader.go:700](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700) and [loader.go:730](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:730), gives 15 sites in multi-selector methods.
   - The two named single-selector sites are correctly identified: [compiler.go:353](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353) and [loader.go:591](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:591).
   - Both compositions are real: `Compile` calls the helper at [compiler.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:399); `seedInterfaceCounter` is called by `AttachXDP` and `AddTxPort`.

   But [plan.md:5233](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5233) claims these are *the* sites inside multi-access operations. The same proof composes `Compile` with `clearNativeXDPFlagsForIfindexes`, whose selector at [loader.go:928](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:928) is nevertheless assigned to the single-selector remainder at [plan.md:5321](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5321). Under the new transitive “operation” criterion, `:928` is necessarily a third composed site.

   `ClearSessionCounts` and `GetMapStats` are further counterexamples: each has one syntactic selector but executes it across multiple map names/descriptors, as the plan itself acknowledges at [plan.md:5254](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5254).

   This also collides with A3’s explicit DIRECT-access classification at [plan.md:3864](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3864). The fix is to describe the host shapes of the chosen 17 without claiming they exhaust all transitive/runtime multi-access operations.

2. **MINOR — the four optional-read shapes are not exhaustive across all 41 reads.**

   [plan.md:5208](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5208) claims four exhaustive shapes. However, the optional inventory includes the class-4 `Map`/`Program` getters at [plan.md:5320](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5320), whose implementations directly return `m.maps[name]` and `m.programs[name]` at [loader.go:1152](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1152) and [loader.go:1157](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1157). Missing entries return nil directly—none of the four named shapes.

   The complete breakdown is:

   - 14 if-ok skips
   - 1 nil-guard return
   - 3 skip/continue outcomes
   - 21 comma-ok early returns
   - 2 direct nil returns

   Thus `14 + 1 + 3 + 21 + 2 = 41`. The census is correct; a fifth shape is missing from the claimed exhaustive taxonomy.

The three current `other-shape` occurrences at [plan.md:5222](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5222), [plan.md:5226](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5226), and [plan.md:5274](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5274) are mutually consistent: two single-value reads plus one comma-ok early return.

Beyond these two minors, the full A3, §7, and §9 read is consistent. No additional PR-1 regression, synchronization hazard, oracle gap, teardown overclaim, or G+H+H2 leakage was found.

**Yes: findings 1–2 block formal `PLAN-READY` for #2114 PR-1 at v96.**

Codex session ID: 019fc14c-f2be-7112-b457-19e194a5b6fa
Resume in Codex: codex resume 019fc14c-f2be-7112-b457-19e194a5b6fa
