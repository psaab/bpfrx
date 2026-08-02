# Codex hostile plan-review — round 78 (plan v79 @ ea91b14da)

Task: task-msb0gf4l-f8mp88 (session 019fbfaf-fe14-7132-b3f9-d6cd97bfad70).
Verdict: PLAN-NEEDS-MAJOR (3 MAJOR — the uniform two-state rule internally contradictory (one-state class sentences survived); the oracle split still impossible as written (the legacy-oracle sentence kept the contradiction; the retained re-Start leg unsound under in-hold Store(true)); CompileConfig is a third pre-existing loaded-check path missing from the carve-out — 2 MINOR: stale Store-placement descriptions; H-attribution stragglers). Verified passes: narrowed 4.7 L2; class-3 fresh outcomes unchanged; Store-inside-hold safe; seam feasible. Raw companion output follows verbatim.

---

# Verdict: PLAN-NEEDS-MAJOR (3 MAJOR / 2 MINOR)

Yes. Findings 1–3 are wholly inside PR-1 and block `PLAN-READY` for #2114.

1. **MAJOR — the uniform two-state rule remains internally contradictory.**

   The authoritative rule requires classification plus handle selection under `m.mu` ([plan.md:3614](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3614)), with fresh defined by `loaded==false && maps empty` ([plan.md:3631](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3631)). But:

   - Class 1 still says a method during population “observes false” and returns without touching the registry ([plan.md:3610](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3610)); under the uniform mutex it blocks and later sees armed.
   - Class 2 still says acquire-load `loaded` and “on false return” ([plan.md:3662](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3662)), contradicting its immediately following under-lock classification requirement. Implemented literally, this again suppresses retained state.
   - §5.5 still documents only population plus “scoped class-3 lookups,” not every-class registry access ([plan.md:4221](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4221)).

   The literal operative “needs NO `m.mu`” clause is gone, but its one-state behavior remains.

2. **MAJOR — the oracle split is still impossible as written.**

   The new leg correctly says in-batch readers block and observe armed after release ([plan.md:4533](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4533)). Immediately afterward, the retained legacy oracle still requires those same class calls to return fresh outcomes “during a held window” ([plan.md:4543](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4543)).

   The retained re-Start test is also unsound: it expects retained methods to proceed across the held batch ([plan.md:4586](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4586)). Correct registry readers block; final in-hold `Store(true)` means they see armed after release, not retained-unarmed.

   Required split:

   - quiescent fresh outcomes;
   - quiescent retained outcomes;
   - blocked fresh Start and retained re-Start lock-ownership legs, both observing armed after release.

   Hook placement must also be explicit. Before `Store(true)`, preserved loaded-check methods return immediately; after it, they can pass their precheck and block at registry selection.

3. **MAJOR — AttachXDP/AttachTC are not the only pre-existing loaded-check exception.**

   `CompileConfig` rejects `!dp.IsLoaded()` with `"dataplane not loaded"` before registry access ([compiler.go:182](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:182)). It is reached by:

   - `Manager.Compile` ([compiler.go:316](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:316));
   - `ApplyConfig` ([apply.go:237](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/apply.go:237));
   - `CompileUserspaceShim` via the embedded Manager ([loader.go:173](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:173)).

   `Compile` directly accesses `m.maps` ([compiler.go:353](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353)), so it belongs to the plan’s classified surface. On fresh and retained `loaded=false`, master preserves its existing error; it neither produces the generic class-1 typed error nor reaches registry selection.

   This contradicts the attach-only carve-out ([plan.md:3641](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3641)) and the universal retained-proceed summaries ([plan.md:4341](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4341), [plan.md:4389](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4389)).

   Broad grep found no further root loaded checks beyond AttachXDP, AttachTC, and this `CompileConfig` path.

4. **MINOR — two pre-v79 Store-placement descriptions remain.**

   [plan.md:3563](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3563) and [plan.md:3820](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3820) still describe the current outer `loader.go:164` Store merely occurring after population. That conflicts with the new normative placement inside the batch ([plan.md:4033](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4033)).

5. **MINOR — generation-hazard ownership is still stale outside §10.**

   Section 10 is corrected, but §4 still says the “EXACT recurrence” is terminated by H ([plan.md:3885](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3885)); §5.5 repeats that attribution ([plan.md:4194](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4194)). H is FirstCommit+cluster-only, while standalone timeout also reaches `PromoteRollback` ([daemon_apply_commit.go:645](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:645)) and Teardown-retains ([bootstrap.go:470](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:470)).

Verified passes:

- §4.7 now states the narrowed L2 claim correctly.
- Quiescent scoped locking does not change the four class-3 fresh outcomes.
- `Store(true)` inside the hold creates no production safety hazard: assignments precede it, and registry consumers subsequently synchronize on `m.mu`. `IsLoaded` may observe true before unlock, but it cannot observe a partial registry.
- The synthetic seam is feasible if one publisher owns `m.mu` and its passive hook never re-enters Manager helpers. The stale oracle—not the Store placement itself—would deadlock it.

No files were changed.

Codex session ID: 019fbfaf-fe14-7132-b3f9-d6cd97bfad70
Resume in Codex: codex resume 019fbfaf-fe14-7132-b3f9-d6cd97bfad70
