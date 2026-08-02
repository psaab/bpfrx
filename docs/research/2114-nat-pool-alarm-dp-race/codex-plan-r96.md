# Codex adversarial plan-review — round 96 (plan v99 @ a862aa14d77c)

Codex companion task-msbiyaem-jsp5p4 (session 019fc18a-0984-7cb2-818e-38cb8234cd44). Verdict: PLAN-READY — findings: NONE. "Nothing in PR-1 blocks PLAN-READY for #2114." The four verification points: (1) the v99 manifest is mechanically stale-checked, not review-only (the canary establishes the AST/allowlist pattern; v99 requires every helper callsite to match the manifest with additions/removals/moves failing the build; the existing production-file AST helpers at retirement_boundary_canary_test.go:2403/:3226 support it directly — another AST collector inside the existing canary, not a new enforcement architecture); (2) the real-code census matches exactly (135 registry selectors = 3 publisher writes + 132 prospective helper calls, split 91 required / 41 optional; all 17 mixed sites rechecked and mapped to the named continuation/discriminating legs); (3) required/optional + the named §9 leg is sufficient manifest granularity (exact absent-branch behavior remains normative per site; duplicating the five syntax shapes in every manifest row would not add mechanical semantic proof); (4) no residual contradiction survived (the handwritten-review wording concerns correctness of semantic labels, not inventory membership, consistent with the manifest's explicit non-inference boundary; A3, §7, and §9 agree on state classification, per-access outcomes, whole-batch publication, loaded-check carve-outs, Detach qualification, and teardown exclusions). Reviewed against a862aa14d77c (the branch advanced during review to bd73d5b88 with r96 review documents only; plan.md unchanged). Raw output follows verbatim.

---

## Verdict: PLAN-READY

Findings: none.

Nothing in PR-1 blocks `PLAN-READY` for #2114.

1. The v99 manifest is mechanically stale-checked, not review-only. The existing canary establishes the AST/allowlist pattern ([plan.md:5225](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5225)); v99 explicitly requires every helper callsite to match the manifest and makes additions, removals, or moves fail the build ([plan.md:5340](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5340)). This needs another AST collector/comparison inside the existing canary, not a new enforcement architecture. The existing production-file AST helpers support that directly ([retirement_boundary_canary_test.go:2403](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/retirement_boundary_canary_test.go:2403), [retirement_boundary_canary_test.go:3226](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/retirement_boundary_canary_test.go:3226)).

2. The real-code census matches exactly: 135 registry selectors = 3 publisher writes + 132 prospective helper calls, split 91 required / 41 optional as claimed at [plan.md:6142](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:6142). The 17 mixed sites rechecked are:

   - `maps_nat.go`: 261, 274, 299, 328
   - `maps_stale.go`: 224, 241, 285, 291, 322, 328, 336
   - `maps_session.go`: 327, 337
   - `loader.go`: 591, 700, 730
   - `compiler.go`: 353

   All map to the named continuation or discriminating legs at [plan.md:5486](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5486), [plan.md:5500](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5500), and [plan.md:5511](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5511).

3. Required/optional plus the named §9 leg is sufficient manifest granularity. Exact absent-branch behavior remains normative per site ([plan.md:5278](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5278)); duplicating the five syntax shapes in every manifest row would not add mechanical semantic proof.

4. No residual contradiction survived. The handwritten-review wording concerns correctness of semantic labels, not inventory membership ([plan.md:3978](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3978)), consistent with the manifest’s explicit non-inference boundary. A3, §7, and §9 agree on state classification, per-access outcomes, whole-batch publication, loaded-check carve-outs, Detach qualification, and teardown exclusions.

Reviewed against `a862aa14d77c`. The branch advanced during review to `bd73d5b88` with r96 review documents only; `plan.md` is unchanged. No files changed by me.

Codex session ID: 019fc18a-0984-7cb2-818e-38cb8234cd44
Resume in Codex: codex resume 019fc18a-0984-7cb2-818e-38cb8234cd44
