# #1431 reviewer task IDs

## Round 1 (plan v1 @ commit ff242c3a8cc0428d88f98f7bc3e2abfb74f0e341)

- **Codex**: `task-mpni1t2r-fmeyxk` — adversarial PLAN review, 10 Qs incl Q1 lo0 gap, Q3 ICMP, Q5 plausibility, Q6 fake-field harness soundness.
- **AGY**: `review-mpni22am-c41y7k` — same Q set, parallel hostile review.

## Round 2 (plan v2 @ commit 29d06607fa8865e332c1fe1690a13d239f568003)

- **Codex**: `task-mpnic4wn-2f38fd` — verify all r1 findings addressed; in-source block surface; harness right-sized; Q4 dup question; lo0 note keep/shrink.
- **AGY**: `review-mpnicccj-1jngkm` — congruent verification of r1 action plan items.

## Round 3 (plan v3 @ commit d5bd4651826bb703b49f47d33c6f95f51793c936)

- **Codex**: `task-mpnijinr-08835k` — confirm r2 findings applied.
- **AGY**: `review-mpnijmli-su8ofn` — confirm v3 still PLAN-READY.

## Round 4 (plan v5 @ commit f4b7b041456d952fca10c358f95558cebab31323)

- **Codex**: `task-mpnjcswx-l02e6k` — confirm r3 stale leftovers fixed.
- **AGY**: `review-mpnjcvjj-zvj9hv` — same.

## Code review round 1 (PR #1604 @ head 705d62f6720d8fd512d5ffb36db4d946987f938c)

- **Codex**: `task-mpnkbtew-5ayuov` — hostile code review.
- **AGY**: `review-mpnkbzwi-6lhyzx` — hostile code review.

## Code review round 2 (head 778450f74e4773872272bf4d782671e20c5d41e6)

- **Codex r2**: `task-mpnlp6rw-8zl5ny` — confirm r1 findings + Copilot inline findings fixed.
- **AGY r1**: already MERGE-READY at 705d62f67 — re-attestation not required for a doc-only fix on top.
- **Copilot**: re-review requested via PR comment.
- **Claude SMR**: `docs/pr/1431-filter-cache-invariants/claude-smr-code-r1.md` MERGE-READY (covers the fixed surface inline).
