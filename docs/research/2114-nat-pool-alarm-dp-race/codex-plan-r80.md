# Codex hostile plan-review — round 80 (plan v81 @ ef86de7b0)

Task: task-msb2s6db-ls4hls (session 019fbfeb-9f82-7b10-9b57-22b352ca079f).
Verdict: PLAN-NEEDS-MAJOR (4 MAJOR — the class-2 predicate literally sweeps error-outcome methods; the 'every state' carve-out phrasing false for armed; the CompileUserspaceShim exception contradicts the adjacent universal + leaves the blocked oracle underspecified; the class-3 blocked test passes even with unlocked lookups (reverse-schedule blind spot) — 2 MINOR: obsolete-generation wording + fixture scope; idempotency overstated + citation). Verified passes: fold presence for r79 M1/m1/m2; all-or-nothing; lock order. Raw companion output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 4 major, 2 minor

Yes. Findings 1–4 are entirely within PR-1 and block `PLAN-READY` for #2114.

### Fold verification

- r79 M1: the old retained-outcomes-during-hold assertion is gone. `RetainedOutcomes` is now quiescent, while `RetainedReStartOverlap` says block then armed ([plan.md:4631](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4631), [plan.md:4637](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4637)). Fold present.
- r79 M2: real ordering verified: cleanups at [loader.go:174](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:174)/`:177`, selector at `:181`—not plan’s `:180`—then `CompileConfig` at `:183`; production selects first at [manager_compile.go:184](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:184). The new text nevertheless remains contradictory; finding 3.
- r79 M3: the carve-out was inserted, but “EVERY state” makes it false; finding 2.
- r79 m1/m2: clean. The acquire-load remnants are gone, and §5.5 now limits H to its recurrence class while assigning generic lifecycle/generation work separately ([plan.md:4230](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4230)).

### Findings

1. **MAJOR — the total/exclusive classifier assigns explicit class-1 methods to class 2.**

   The normative precedence says any no-side-effect method whose pre-arm behavior is master’s “missing-map outcome” is class 2 ([plan.md:3590](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3590)). The next paragraph explicitly makes `UpdateFabricFwd` and `UpdateRGActive` class 1 ([plan.md:3607](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3607)), although both literally return missing-map errors ([maps_fabric.go:18](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go:18), [maps_fabric.go:38](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go:38)).

   Literal precedence preserves those errors as class 2; the explicit class-1 contract replaces them with `ErrDataplaneNotArmed`. Define class 2 as the **neutral** missing-map outcome set or place fallible class 1 first.

2. **MAJOR — “reject on EVERY state and never reach the registry” includes armed state and reverses real behavior.**

   Invariant 12 says loaded-check methods reject on every state ([plan.md:4427](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4427)); §9 repeats “the rejection fires in every state” and immediately says an armed call proceeds ([plan.md:4605](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4605)).

   `AttachXDP`, `AttachTC`, and `CompileConfig` reject only while `loaded == false`; armed calls pass and reach registry work ([loader.go:490](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:490), [loader.go:1082](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1082), [compiler.go:182](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:182)). This must say “both unarmed states” or “whenever `loaded == false`.” Valid-config and successful-cleanup qualifications are also required.

3. **MAJOR — the new `CompileUserspaceShim` exception contradicts the adjacent universal and leaves the blocked oracle underspecified.**

   §9 first says the whole CompileConfig path returns immediately before Store ([plan.md:4597](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4597)), then correctly says `CompileUserspaceShim` blocks at the earlier selector and can proceed armed after release ([plan.md:4600](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4600)).

   Direct `Manager.Compile`/`ApplyConfig` can reject before registry selection. Direct `CompileUserspaceShim` instead runs cleanups, reaches the selector at `loader.go:181`, blocks, and may pass `CompileConfig` after release. Production `userspace.Manager.Compile` blocks at its outer selector even earlier.

   These need separate oracles. Otherwise an implementor waiting for the alleged immediate return can deadlock the test. The plan should also name an explicit post-Store/pre-unlock barrier if loaded-check methods must deterministically pass their check and then block.

4. **MAJOR — the class-3 blocked test passes even if the unsafe registry lookups remain unlocked.**

   All four class-3 hybrids already acquire the same `m.mu` for their required side effect before their raw `m.maps` lookup:

   - `ClearGlobalCounters`: lock at [maps_counters.go:176](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:176), lookup at `:181`.
   - `ClearZoneCounters`: offset lock at `:146`, lookup at `:233`.
   - `ClearNATRuleCounters`: lock at [maps_nat.go:389](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:389), lookup at `:400`.
   - `ClearAllCounters` starts through `ClearGlobalCounters` at `maps_counters.go:246`.

   Consequently, the writer-first held-batch test ([plan.md:4580](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4580)) blocks class 3 at the pre-existing side-effect lock even if the later lookup never adopts the registry helper. It misses the dangerous reverse schedule: side-effect unlock → Start writes → raw lookup races.

   Thus class-3 “block then armed” holds behaviorally, despite class 3 not using `loaded`, but it does not prove registry-lock ownership. Add a lookup-entry reverse-schedule seam or an AST canary forbidding direct `m.maps`/`m.programs` access outside the helper and publication writer.

5. **MINOR — Close-retained versus Teardown-retained is present but described inconsistently.**

   Close-retained maps remain pinned and live ([plan.md:3648](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3648)); mutations such as `UpdateRGActive` reach that live map. Teardown removes the pin tree ([loader.go:1221](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1221)), but it does not close the `m.maps` FDs. Those objects are therefore not literally “DEAD” as §4/§10 claim ([plan.md:3917](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3917), [plan.md:4718](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4718)); they are live FD-backed objects belonging to an obsolete forwarding generation. A mutation can succeed yet miss the new generation.

   One seeded retained fixture is sufficient for A3’s state classification because Close and Teardown both present `loaded=false` plus a nonempty registry. A duplicate Teardown outcome matrix is unnecessary and must not claim current-generation delivery. A small Close-transition assertion would still usefully prove production preservation of the registry.

6. **MINOR — “all idempotent” is stronger than the cleanup code proves.**

   The selector is a constant assignment, and both cleanup functions become no-ops after successful sequential removal. But partial `Unpin`/`Close` failures are aggregated after partial progress, and concurrent TC cleanups can both load the same pin before one removes it ([loader.go:294](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:294)). Say “safe/no-op when repeated after successful cleanup,” not unconditionally idempotent. Correct the selector citation from `:180` to `:181`.

No files were changed.

Codex session ID: 019fbfeb-9f82-7b10-9b57-22b352ca079f
Resume in Codex: codex resume 019fbfeb-9f82-7b10-9b57-22b352ca079f
