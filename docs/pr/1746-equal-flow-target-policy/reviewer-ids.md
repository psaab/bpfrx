# Reviewer task-ID ledger — PR #1867 (#1746 equal-flow target policy)

## Research phase (issue comments; branch research/1746-equal-flow-target-policy @ fb4f2fd6a)
- Converged PLAN-READY r2 (Codex + AGY + Claude SMR) — verdicts quoted in the
  issue's PLAN-READY comment.

## Implementation phase (PR #1867, head dae961b138a0)
- Codex r1: task-mq97v0x1-7kyydt (dispatched 2026-06-11, flocked)
- AGY r1: adversarial-review-mq97vg5m-r1p7st (dispatched 2026-06-11)
- Claude SMR r1: docs/pr/1746-equal-flow-target-policy/claude-smr-impl-r1.md
  (MERGE-READY; worked trace of mean-policy join/leave dynamics; O1/O2
  observations; hierarchical-AST test added during review)
- Copilot: requested via "@copilot review" comment on PR #1867

## Round 2 (head bf7014bd5, post Codex-r1 fixes)
- Codex r2: task-mq98vvoc-8l0kx8 — MERGE-READY (verified F1 reorder
  neutrality, F2 disposition "sound enough to ship the opt-in mean
  policy", F3 docs fix; SMR trace verified against code)
- AGY r2: adversarial-review-mq98we8d-xmwp8q — MERGE-READY (reorder
  neutrality verified all rate modes; default-OFF disposition judged
  correct; SMR closed-loop trace verified)
- Claude SMR r2: docs/pr/1746-equal-flow-target-policy/claude-smr-impl-r2.md
  — MERGE-READY
- Copilot: attempts 1-2 failed with quota-limit responses
  (copilot-pull-request-reviewer[bot] COMMENTED "reached their quota
  limit" twice); retry 3 requested via comment + re-request API.
- Copilot retry 3 outcome: third quota-limit response from
  copilot-pull-request-reviewer[bot] (3 documented attempts total) —
  3-of-4 fallback applies per feedback_codex_infra_must_retry.
