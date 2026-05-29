# #1661 item 8 — reviewer task IDs

Branch: pr/1661-audit-drift
PR: #1671
Head: 42efc32be

## Plan review (round 1) — all PLAN-NEEDS-MINOR, folded into plan v2
- Codex: task-mprdz18l-oa4ntx (sandbox infra-blocked -> provisional PLAN-NEEDS-MINOR);
         retry task-mpre329g-usqidy (ENV-BLOCKED). Substantive finding (recipe
         must fail on generator failure, not just diff) captured + implemented.
- AGY: review-mprdxwky-cqxgzn -> verified PLAN-NEEDS-MINOR (4 findings, all folded in)
- Claude SMR: in-conversation -> PLAN-NEEDS-MINOR (recipe set -e), folded in

## Code review (round 1) — PR #1671
- Codex: task-mpre8r8y-c847kc -> MERGE-NEEDS-MINOR (1 finding: md Historical
         section named deleted files as current candidates). Fully empirically
         verified the rest (exit 0, determinism, generator-failure path, no leak,
         16/16 LOC match, shellcheck clean). Finding fixed in 42efc32be.
- AGY: review-mpre8ybl-ec4oyg -> MERGE-READY (full empirical verification)
- Copilot: COMMENTED twice (20:48 pre-fix, 20:59 post-fix), 0 inline comments both
- Claude SMR: in-conversation -> MERGE-READY (artifact LOC match, recipe grouping,
         set -e exemption analysis)

## Code review (round 2) — confirm md fix @ 42efc32be
- Codex: task-mprem3yn-4mg706 + retry task-mprfaa0m-9ywgqy -> both lost to
         Codex session-loss infra (feedback_codex_session_loss_continuation).
         Single round-1 finding self-verified resolved: no stale file name
         presented as a current candidate; make audit-check exits 0.
- AGY / Copilot / Claude SMR: clean at 42efc32be (md-only change; guard unaffected).
