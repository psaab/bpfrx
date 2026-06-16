PLAN-NEEDS-REVISION (blockers)

Findings:

1. Kernel scope still has a stale contradiction in Risk #2: [plan.md:621](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:621) says “kernel bumps go through image-replace (Path C)”, which conflicts with §6.7 and §11’s now-correct split: routine kernel bumps use the verify-gated in-place channel; heavy/uncertain moves use Path C.

2. Manifest location still has a stale contradiction in §8: [plan.md:529](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:529) still says codex-review-010 demands `.configdb/manifest.json` and that the plan adopts it “verbatim,” while [plan.md:548](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:548) correctly says the manifest must not be a second file. Risk #3 itself is fixed, but §8 is not yet consistent with it.

Confirmed resolved: §6.3 now agrees with §6.3a on copy → verify from `/var/lib/xpf/versions/<N+1>/` → flip only on pass, and §3/§11 now have the correct routine-vs-heavy kernel split. AGY’s two non-blocker folds are also present.

Codex session ID: 019ecf31-9d55-7671-9129-e0c3f5d57e5b
Resume in Codex: codex resume 019ecf31-9d55-7671-9129-e0c3f5d57e5b
