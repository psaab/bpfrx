# Codex hostile plan-review — round 77 (plan v78 @ a437f0246)

Task: task-msazbplm-b8pvb9 (session 019fbf93-056c-7030-8e35-0fcf3aeca234).
Verdict: PLAN-NEEDS-MAJOR (3 MAJOR — the uniform registry rule contradicted by the normative class text (class-2's 'no m.mu' clause); the blocked-Start test oracle impossible under whole-batch locking; 'every retained class proceeds' false for attaches (master gates them on IsLoaded) — 2 MINOR: residual overclaims; H-ownership error). Passed: all-or-nothing population, lock-order safety, fixture reclassification. Raw companion output follows verbatim.

---

Verdict: **PLAN-NEEDS-MAJOR (3 MAJOR / 2 MINOR).**

Yes—findings 1–3 block `PLAN-READY` for PR-1. G+H+H2 were not reviewed except to verify PR-1’s ownership pointer.

1. **MAJOR — the uniform registry rule is contradicted by the normative class design.**

   The new rule requires every registry access and classification/selection operation under `m.mu` ([plan.md:3609](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3609)). But class 2 still says `loaded==false` returns immediately and “needs NO `m.mu`” ([plan.md:3650](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3650)); §5.1 and the documentation inventory still assign scoped registry locking only to class 3 ([plan.md:4013](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4013), [plan.md:4200](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4200)).

   Exhaustive baseline grep found 135 executable selectors—130 `m.maps`, five `m.programs`—across 14 production files. Following the detailed class text leaves readers such as `SessionCount` and `GetMapStats` unlocked ([maps_session.go:327](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:327), [maps_stats.go:72](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go:72)) against the batch writer ([loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185)). Thus fold 1(a) fails: the universal intent exists, but the implementable contract still permits the original race.

2. **MAJOR — the blocked-Start test oracle is impossible under whole-batch locking.**

   Classification/selection and population use the same mutex ([plan.md:3609](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3609)), yet `TestManager_ArmedGate_BlockedStart` expects every class to return its fresh-unarmed outcome during the held population window ([plan.md:4501](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4501)).

   Correct readers must instead block. After release they see either:

   - armed state if `Store(true)` is inside the batch as invariant 12 claims ([plan.md:4355](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4355)); or
   - retained-unarmed state under the currently described placement, where registry publication returns before `loaded=true` ([loader.go:152](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:152)).

   Neither produces the asserted fresh outcome. A pre-lock hook tests fresh outcomes but does not overlap registry mutation. Split this into a quiescent fresh-state outcome test and an in-batch lock-ownership/block-until-release test. The retained overlap test needs the same correction ([plan.md:4552](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4552)).

3. **MAJOR — “every retained class proceeds exactly as master” is false for attaches.**

   `AttachXDP` and `AttachTC` are class 1 ([plan.md:3593](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3593)), while the two-state rule and retained test require every retained class to proceed ([plan.md:3635](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3635), [plan.md:4318](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4318)).

   Master explicitly rejects both whenever `loaded==false`, before registry lookup ([loader.go:489](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:489), [loader.go:1081](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1081)); `Close` creates exactly that retained-unarmed state ([loader.go:1203](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1203)). Preserve these method-specific gates or explicitly justify/test the behavior change.

4. **MINOR — the narrowed L2 statement is correct locally, but stale overclaims remain.**

   The precise claim at [plan.md:3862](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3862) is good. However §4.7 still claims all three races close “at BOTH layers” via admission safety against any published-but-unarmed backend ([plan.md:3943](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3943)), and §4 still says `Close` gates new entrants ([plan.md:3805](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3805)). Therefore fold 2 is not globally complete.

5. **MINOR — H does not own generic retained-generation recurrence.**

   PR-1 attributes the recurrence to H ([plan.md:3870](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3870), [plan.md:4629](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4629)). H is specifically `FirstCommit+cluster` and deliberately preserves standalone re-arm ([followup-seed.md:303](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md:303), [followup-seed.md:3330](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md:3330)). Same-process standalone first-commit timeout also Teardown-retains and later re-arms ([daemon_apply_commit.go:645](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:645), [bootstrap.go:470](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:470)). Point generic generation correctness to a separate lifecycle/generation follow-up.

Verified passes:

- Population is all-or-nothing: every fallible collection/pin step precedes the assignments at `:185-190` ([loader_userspace_shim.go:162](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:162)). AGY r76 M2’s partial-state premise is false.
- Lock order is safe: userspace-manager `m.mu` nests root/shim `m.mu` ([manager_compile.go:213](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:213), [maps_sync.go:121](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go:121)); population takes only the root lock. No inverse edge or required shim-lock recursion exists. The existing order is documented locally at [policycounters.go:332](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/policycounters.go:332).
- Fixture reclassification is correct: `injectShimMap` changes only the registry, and the XSK fixture already seeds program plus maps ([manager_testhelpers_test.go:22](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_testhelpers_test.go:22), [xdp_shim_decouple_test.go:32](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/xdp_shim_decouple_test.go:32)).
- Atomic classification plus composite handle selection is implementable through one locked registry closure; class 3 can keep BPF operations outside it. The plan simply does not specify that consistently yet.

No files were changed.

Codex session ID: 019fbf93-056c-7030-8e35-0fcf3aeca234
Resume in Codex: codex resume 019fbf93-056c-7030-8e35-0fcf3aeca234
