# Codex hostile plan-review — round 73 (plan v74 @ ffa0b2970)

Task: task-msauk3h5-zw1x4z (session 019fbf18-da04-7dc3-9517-1437fde2c504).
Verdict: PLAN-NEEDS-MAJOR (3 MAJOR — DetachXDP mixed direct+delegation access unclassified; the trio locking deadlocks and misses the :632 writer; the blocked-Start test cannot prove the XDP synchronization — 3 MINOR: oracle disjointness wording, stale inventories, VlanSubInterfaces residual inventory). Raw companion output follows verbatim.

---

## Verdict

**PLAN-NEEDS-MAJOR — 3 major, 3 minor.**

Yes. Findings 1–3 are inside PR-1 and block PLAN-READY for #2114.

1. **MAJOR — the 157-method partition remains unsafe and ambiguous around `DetachXDP`.**

   V74 says both detaches only read construction-created link maps and assigns them to G ([plan.md:3667](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3667)). That is true for `DetachTC`, but false for `DetachXDP`: it reads `m.xdpLinks`, then delegates to `setXDPAttachedFlag` ([loader.go:639](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:639), [loader.go:650](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:650)), which reads Start-populated `m.maps` ([loader.go:700](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700), [loader.go:730](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:730)).

   The delegation rule only covers methods that “only delegate.” `DetachXDP` both directly accesses link state and delegates into Start-state access, so the rule does not order it.

   This is reachable on re-arm: `Close` never clears `xdpLinks` ([loader.go:1206](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1206)), `Teardown` retains the Manager object, and bootstrap explicitly keeps it for later re-arm ([bootstrap.go:470](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:470)). An ungated detach can therefore read `m.maps` while Start repopulates it under `m.mu`.

   Preserve the absent-link `nil` return, then gate/lock the nonempty-link path and test a seeded re-arm state.

2. **MAJOR — the `xdpEntryProg` locking design both deadlocks and misses a writer.**

   V74 says all three accessors lock `m.mu` ([plan.md:3683](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3683)). But `UsingUserspaceXDPShimEntryProgram` calls `XDPEntryProgram` ([loader.go:120](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:120)). Locking both bodies re-enters the non-reentrant `sync.Mutex`, deadlocking every `Using...` call.

   The production access inventory is also incomplete:

   - Constructor initialization: [loader.go:97](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:97), safely pre-publication.
   - Selector write: [loader.go:115](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:115).
   - Omitted direct write: `swapXDPEntryProg` at [loader.go:632](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:632).

   The design needs a single lock-owning/raw-helper scheme covering the getter, selector, predicate, and swap assignment. Whole-method locking of `swapXDPEntryProg` would also recurse through its getter and hold the mutex across link updates.

3. **MAJOR — the proposed blocked-Start test does not prove the XDP synchronization.**

   The seam is specified around a map-population write ([plan.md:4351](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4351)). Real Start writes `xdpEntryProg` earlier at [loader.go:154](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:154), before population at [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185).

   Waiting for the population barrier orders Start’s selector write before the accessor calls, so the test can pass even with unsynchronized XDP access. Require a dedicated two-sided XDP seam or explicit concurrent getter/selector/swap exercise, including the line-632 writer.

4. **MINOR — the classification/oracle text is still non-exclusive.**

   Once `xdpEntryProg` becomes `m.mu`-protected, the trio matches G’s broad predicate ([plan.md:3550](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3550)) while remaining explicitly F ([plan.md:3643](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3643)). `ApplyConfig` also delegates to differently classified `Compile` and `LastApplyResult`, with no multiple-target ordering.

   Section 9 still says the AST test asserts semantic “DISJOINTNESS” ([plan.md:4365](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4365)), contradicting §4’s correct statement that AST proves only manifest totality.

5. **MINOR — v74’s normative inventories remain stale.**

   Section 5.1 omits the XDP/swap locking edits, while §5.5 says the expanded `m.mu` comment names only map/program population and class-3 lookups ([plan.md:4058](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4058)), contradicting §4’s claim that it also names `xdpEntryProg`.

   Section 6 still says class 3 preserves only “side-effect-plus-success” ([plan.md:4170](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4170)); the correct contract includes the pinned later error.

6. **MINOR — VLAN may remain residual, but its residual inventory is incomplete.**

   Residualizing it is consistent with the precise Start-state L2 claim. `userspace.Manager.Start` only delegates to `Load` ([manager.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go:370)); the 1 Hz loop starts only after successful Compile ([manager_compile.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:399)). It is therefore a post-arm Compile/status race, not a fresh Start-overlap race.

   However, `VlanSubInterfaces` is also read during swap ([loader.go:622](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:622)) and written by legacy Compile ([compiler.go:441](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:441)); §10 names neither.

Passed checks: the method count is exactly 157; the three no-op stubs are genuinely empty and now assigned; the root Start path writes only `loaded`, `maps`, `programs`, and `xdpEntryProg`; userspace Start writes no equivalent plain field; and the `ErrDataplaneNotArmed` sentinel/`%w`/`errors.Is` contract is adequate.

**Explicit answer: yes—PR-1 still has PLAN-READY blockers.**

Codex session ID: 019fbf18-da04-7dc3-9517-1437fde2c504
Resume in Codex: codex resume 019fbf18-da04-7dc3-9517-1437fde2c504
