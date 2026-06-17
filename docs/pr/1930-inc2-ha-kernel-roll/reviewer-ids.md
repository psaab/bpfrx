# #1930 INC-2 (PR #1941) — reviewer task IDs

For continuation after context loss (fetch by id).

## AGY adversarial-review
- r1: see agy-review-r1.md (6 findings, all addressed)
- r2: adversarial-review-mqhgyxz9-18nuvy
  - result: ~/.gemini/antigravity-cli/brain/4d292504-b0c9-46b7-b907-f3da27960d57/agy_adversarial_review.md
  - F1 CRITICAL boot-time election window (converged with Claude SMR; already
    fixed pre-review by 4de61669c) + demote-on-arm defense in depth (92ee918c9)
  - F2 HIGH revert/reboot transient split-brain (fixed 92ee918c9 — marker-based release)
  - F3 MEDIUM gate-timeout leaked hold (fixed 92ee918c9 — OnFailure reboot unit)
- r3 (convergence): adversarial-review-mqhh81or-79tk7t

## Claude SMR (domain + CPU/arch + SW-design)
- Findings independently: leaked-hold-after-promote (d73a7a9cc), election-window
  before-UpdateConfig (4de61669c) — both before AGY r2 confirmed.
- See smr-review.md

## Codex
- INC-2 r1-r6 (drain/rejoin verbs, lease concurrency) — see prior commits
  1518cfc08, 3bb61d7e0, 8684f70a8 messages.
