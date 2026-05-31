# #1700 reviewer task IDs

## Plan review round 1
- Codex: task-mpt41ogi-pga355
- AGY adversarial: adversarial-review-mpt41xer-4g2cxh
- Claude-SMR: PLAN-READY (verified cfg single-fetch @ line 96, ctx unused
  by inline bodies, prefix handlers write shared buf line 97 — adopt
  `(req, cfg, buf)` signature for prefix handlers, not fresh local buf).

Plan commit: ee8812eec6ff9229df6c0dd9c15bab6351e6fde0

## Code review round 1 (PR #1707)
- Codex: task-mpt58dac-kdjois
- AGY adversarial: adversarial-review-mpt58j48-5rxe8y
- Claude-SMR: in-progress (verbatim spot-check)

PR head: 86105b99c
