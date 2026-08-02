# Codex hostile plan-review — round 79 (plan v80 @ 91dbcb631)

Task: task-msb1og1h-kuya5l (session 019fbfcf-55f1-7330-8160-d8a9cf34c7b4).
Verdict: PLAN-NEEDS-MAJOR (3 MAJOR — the retained re-Start oracle survived unchanged beside the four-leg summary; CompileConfig does not dominate the full CompileUserspaceShim overlap path (selector + cleanups precede the rejection); invariant 12 still erases the loaded-check carve-out — 2 MINOR: the two acquire-load remnants (same pair as AGY r79); the 5.5 H-attribution). Verified passes: loaded-check set otherwise complete; Store placements all in-hold; 5.5 m.mu scope correct; barrier channels safe. Raw companion output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 3 major, 2 minor

Yes. Findings 1–3 are inside PR-1 and block `PLAN-READY` for #2114.

1. **MAJOR — the retained re-Start oracle from r78 survived unchanged.**

   The new four-leg summary correctly requires retained re-Start readers to block and observe armed after release ([plan.md:4578](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4578)). But the concrete retained test still says every class crosses the held seam while “fresh methods gate, retained methods proceed” ([plan.md:4607](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4607)). Under the uniform mutex, registry methods block and then classify as armed; they cannot proceed during the hold.

   The quiescent-retained leg exists only in the four-leg summary; the paragraph claiming to supply retained coverage still points to this contradictory overlap test. The Detach test’s concurrent-population actor is present at [plan.md:4615](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4615).

2. **MAJOR — `CompileConfig` does not dominate the full `CompileUserspaceShim` overlap path.**

   The plan promises that before the in-hold Store, the CompileConfig path returns immediately, while after Store it blocks at registry selection ([plan.md:4585](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4585)). But:

   - `CompileUserspaceShim` calls `SelectUserspaceXDPShimEntryProgram` before `CompileConfig` ([loader.go:181](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:181)).
   - v80 requires that selector to acquire the same `m.mu` ([plan.md:3820](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3820)).
   - The production userspace compiler also calls the selector before `CompileUserspaceShim` ([manager_compile.go:184](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:184)).
   - The loaded rejection is only later at [compiler.go:182](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:182).

   Consequently, a pre-Store call blocks at the selector; after release it can observe `loaded=true` and proceed rather than preserving master’s rejection. The plan must choose between preserving an entry snapshot/rejection—including selector/cleanup side-effect ordering—or accepting and documenting serialization-after-Start.

   Quiescent retained Compile remains sound: with a non-nil config it still rejects `"dataplane not loaded"` before registry access.

3. **MAJOR — the retained-state invariant still erases the loaded-check carve-out.**

   The detailed carve-out is correct at [plan.md:3652](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3652). However, invariant 12 still says a retained method “proceeds against the retained registry” ([plan.md:4419](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4419)). That is literally false for AttachXDP ([loader.go:490](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:490)), AttachTC ([loader.go:1082](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1082)), and retained Compile/Apply, which reject before registry selection. This is the same universal-summary contradiction identified in r78; v80 did not edit that invariant.

4. **MINOR — two acquire-load remnants remain.**

   Class 1 still begins with the one-state instruction to acquire-load before the first Start-state access ([plan.md:3605](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3605)), conflicting with the immediately following atomic fresh/retained/armed helper rule. Section 5.1 likewise still says class 2 uses “the acquire-load rule” ([plan.md:4071](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4071)), although §4 says that reading was deleted ([plan.md:3683](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3683)).

5. **MINOR — the H-attribution sweep remains incomplete.**

   Section 5.5 still says H terminates the rollback recurrence ([plan.md:4221](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4221)). H is FirstCommit+cluster-only ([followup-seed.md:303](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md:303)); standalone timeout still enters bootstrap at [daemon_apply_commit.go:645](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:645) and Teardown-retains at [bootstrap.go:470](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:470).

Verified passes:

- The root loaded-check grep set is otherwise complete: attaches plus `CompileConfig`; no additional root checks were found.
- All operative Store-placement descriptions now put `Store(true)` inside the whole-batch hold.
- §5.5’s `m.mu` comment scope now covers every-class registry access, whole-batch publication, and `xdpEntryProg`.
- The barrier channels themselves are safe while the publisher owns `m.mu`, provided readers run in goroutines and the coordinator resumes the publisher before joining them. The current `CompileUserspaceShim` “immediate return” expectation is what can self-deadlock a literal test.

No files were changed.

Codex session ID: 019fbfcf-55f1-7330-8160-d8a9cf34c7b4
Resume in Codex: codex resume 019fbfcf-55f1-7330-8160-d8a9cf34c7b4
