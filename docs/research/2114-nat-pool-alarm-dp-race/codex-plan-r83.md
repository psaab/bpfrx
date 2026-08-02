# Codex hostile plan-review — round 83 (plan v84 @ a30d67ebc)

Task: task-msb75860-4ohfda (session 019fc05b-6d0c-72f1-a8d9-c3530bf5e219).
Verdict: PLAN-NEEDS-MAJOR (1 MAJOR — the 'exact' registry canary remains unnamed for the helper and permits registry escape: a helper returning the container wholesale passes the stated rule while callers index the alias post-unlock — 1 MINOR: the 4/7 teardown summaries contradict 4.7's loaded-check-only narrowing). Verified passes: publisher recursion/order, Store ordering, userspace lock nesting, acquisition error paths, hook protocol, privilege split, carve-out summaries, context precedence, inventory. Raw companion output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 1 major, 1 minor

Yes. Finding 1 is inside PR-1 and blocks `PLAN-READY` for #2114. It is repairable, not `PLAN-KILL`. G+H+H2 were excluded.

### Findings

1. **MAJOR — r82 M1 is only partially folded: the “exact” registry canary remains unnamed and permits registry escape.**

   V84 names `publishShimRegistryLocked`, but the other allowlist member is still merely “the registry helper function,” with no identifier or signature anywhere in the plan ([plan.md:4785](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4785)). That contradicts “EXACTLY-NAMED” at [plan.md:4786](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4786); §5.1 also still calls the canary “fully specified” without defining this helper ([plan.md:4154](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4154)).

   More importantly, the locked-interval check does not enforce the real invariant—individual handle selection under the lock ([plan.md:3668](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3668)). This invalid helper passes the stated rule, ownership hook, and stale-allowlist check:

   ```go
   func (m *Manager) registryHelper() map[string]*ebpf.Map {
       m.mu.Lock()
       defer m.mu.Unlock()
       return m.maps
   }
   ```

   The caller can index that alias after unlock while the publisher writes the same Go map at [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185), preserving the fatal race.

   The shape is implementable as an AST canary only after the plan pins:

   - the helper’s exact name and non-escaping signature;
   - permitted selector-parent/read/write shapes;
   - type-aware receiver matching;
   - rejection of registry aliasing, returning, argument passing, closures, and post-unlock indexing;
   - negative fixtures for alias escape and unlock-before-access;
   - the publisher’s writes followed by exactly one in-lock `Store(true)`.

2. **MINOR — §4.7’s teardown correction remains contradicted by later summaries.**

   Section 4.7 correctly limits `Close()`-entry narrowing to the loaded-check set ([plan.md:4043](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4043)). But §4 still says all “new entrants gate out” ([plan.md:3886](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3886)), and §7 says Store(false) “gates new FRESH-state entrants” ([plan.md:4499](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4499)). `Close` clears neither registry ([loader.go:1203](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1203)); ordinary methods therefore classify retained and proceed. Qualify both summaries as loaded-check-only.

### Fold and delta verification

- **Publisher recursion/order:** Pass. The selector and cleanups precede acquisition; acquisition through the final pin contains no registry reads. The publisher is a leaf lock section.
- **Store ordering:** Pass. All assignments precede `Store(true)`, so any observer sees a complete registry. Master already exposes `loaded==true` before the success log and return ([loader.go:164](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:164)).
- **Userspace lock nesting:** Pass. `userspace.Manager.Load` delegates without holding its mutex ([manager.go:467](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go:467)).
- **Acquisition errors:** Pass. Spec, collection, program, and pin failures all return before registry publication ([loader_userspace_shim.go:106](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:106)). Preserve the existing `keepShared`/deferred-cleanup ownership at lines 111–117 and 192 when extracting the publisher.
- **Hook protocol:** Folded at [plan.md:4708](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4708).
- **Privilege split:** Folded at [plan.md:4729](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4729).
- **Three carve-out summaries:** Folded at lines 3900, 4421, and 4643.
- **Canceled-context precedence:** Folded in §7 and §9.
- **Canary-set inventory and closed escape hatch:** Folded.

No files were changed.

Codex session ID: 019fc05b-6d0c-72f1-a8d9-c3530bf5e219
Resume in Codex: codex resume 019fc05b-6d0c-72f1-a8d9-c3530bf5e219
