# Codex hostile plan-review — round 76 (plan v77 @ 0efb3e398)

Task: task-msayb47u-vqsqmj (session 019fbf78-f6f3-75c1-bae0-ce679b51cfe4).
Verdict: PLAN-NEEDS-MAJOR (2 MAJOR — retained-proceed leaves the Go-map race alive (locking the writer never protected unlocked readers); 'retained' conflates live-pinned and torn-down generations (dead-object mutations on the bootstrap-recurrence Teardown-retain path) — 3 MINOR: stale one-state invariant texts, absent retained coverage in 9, stale fixture-migration prescription). Passed dispositions include the partial-load check (no partial registry state exists) and the lock-ownership hook. Raw companion output follows verbatim.

---

# Verdict: PLAN-NEEDS-MAJOR (2M/3m)

Yes. Findings 1 and 2 block `PLAN-READY` for PR-1. The G+H+H2 follow-up was not reviewed.

## Findings

1. **MAJOR — retained-proceed leaves the original Go-map race alive.**

   v77 protects only the `len(m.maps)` discriminator under `m.mu` ([plan.md:3599](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3599)). Class 1/4 remain merely “gated,” while class 2 explicitly says it needs no `m.mu`; scoped lookup locking is assigned only to class 3 ([plan.md:3623](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3623), [plan.md:3649](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3649), [plan.md:3975](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3975)).

   Fatal schedule:

   1. `loaded=false`; gate locks, sees nonempty maps, unlocks and admits.
   2. Re-`Start` writes `m.maps` during population ([loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185)).
   3. `UpdateRGActive` concurrently performs its ordinary unlocked lookup ([maps_fabric.go:38](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go:38)).

   `SessionCount`, `GetMapStats`, `Map`, and `Program` have the same registry-access shape. Locking the writer does not protect unlocked readers.

   The empty check itself has no Go data race if every writer uses the same mutex, but it is not a sufficient discriminator. The plan must require:

   - every `m.maps`/`m.programs` handle selection in every state under `m.mu`;
   - classification and handle selection as one scoped operation;
   - program assignment plus both map loops at `:185-190` as one whole-batch critical section.

   Without that last rule, the first insertion changes “fresh” into “retained” while population is still partial.

2. **MAJOR — “retained” conflates live-pinned and torn-down generations; post-lookup operations can hit the wrong kernel map.**

   Bootstrap recurrence retains the manager but calls `Teardown`, not plain `Close` ([bootstrap.go:470](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:470)). Userspace delegates that to root `Teardown` ([manager.go:478](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go:478)), whose `Cleanup` removes the complete pin tree ([loader.go:1221](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1221), [loader.go:1230](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1230)).

   Root `Close` never closes or clears `m.maps`/`m.programs`, so the old FDs remain valid. Re-`Start` creates new maps when the pins are absent and later replaces the registry entries. `ensureUserspaceMapPinned` only pins/checks the newly loaded handle; it does not reuse the manager’s old one ([loader_userspace_shim.go:602](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:602), [loader_userspace_shim.go:805](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:805)).

   Therefore, even after finding 1 is fixed, a method can copy the old `rg_active` handle, re-`Start` can publish the new handle, and the method can successfully update the obsolete unpinned object. The mutation is absent from the generation that becomes live. Multi-map readers can similarly report a mixed old/new generation.

   Plain `Close` with intact pins is different: PinByName reuse makes post-lookup operations target the same kernel object. `m.maps nonempty` cannot distinguish those states.

   Consequently §4.7’s claim that A3 closes L2 for every “published-but-unarmed backend” is false ([plan.md:3900](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3900)). The defensible L2 claim is only:

   - fresh-unarmed admission safety; and
   - after finding 1, retained registry-selection race safety.

   It cannot claim current-generation delivery, re-arm linearizability, or teardown/lifetime safety without another lifecycle/generation state. “Preserve master” is not an oracle for a concurrent path whose master behavior is already racy.

3. **MINOR — several invariants still describe the rejected one-state gate.**

   v77 still says `Close`’s `Store(false)` gates new entrants and narrows teardown admission ([plan.md:3781](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3781), [plan.md:3907](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3907)). It does not: maps are nonempty, so retained-proceed admits them. Invariant 12’s “observing false never touches Start-populated state” is also directly false ([plan.md:4312](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4312)).

4. **MINOR — the promised retained coverage is absent from §9.**

   The contract says §9 gains seeded retained-state coverage ([plan.md:3618](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3618)), but §9’s blocked-Start leg remains fresh-only and `TestManager_PreArmMethodMatrix` remains AST-totality/raw-helper-only ([plan.md:4461](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4461), [plan.md:4494](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4494)). A quiescent preseed test cannot detect findings 1 or 2.

   Add a retained blocked-re-`Start` overlap covering every class and the whole-batch publication boundary. The named Detach test also says “race-free” without naming a concurrent population actor ([plan.md:4515](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4515)).

5. **MINOR — the fixture-migration prescription is stale under v77.**

   The existing XSK fixture already injects ctrl/binding maps before the Swap call ([xdp_shim_decouple_test.go:41](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/xdp_shim_decouple_test.go:41)). Under v77 it is therefore retained-unarmed and proceeds; the gate does not break it. `injectShimMap` modifies only `maps`, not `loaded`, so it cannot make a fixture “explicitly ARMED” as claimed ([manager_testhelpers_test.go:22](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_testhelpers_test.go:22), [plan.md:4501](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4501)). The mechanism exists, but the migration classification must be redone.

## Fold disposition

- M2 lock-ownership hook: **PASS**. Holding the exact `:632` section while the getter attempts distinguishes lock ownership from branch execution.
- Class-3-LIKE label: **PASS**.
- Named Detach test and `-run` discoverability: **PASS**.
- `:730`/`:747` discovery-error ordering: **PASS**; both precede claim mutation at `:763`.
- Partial-load-error attack: **PASS on current code**. All fallible pin work ends before manager assignments at `:185-190`; no returned fresh-load error currently leaves a partially populated Go registry.
- Two-state fold overall: **FAIL**, due findings 1 and 2.

No files were changed.

Codex session ID: 019fbf78-f6f3-75c1-bae0-ce679b51cfe4
Resume in Codex: codex resume 019fbf78-f6f3-75c1-bae0-ce679b51cfe4
