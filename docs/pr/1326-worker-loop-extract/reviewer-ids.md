# #1326 worker_loop extract — Reviewer task IDs

Rolling record so a session resume can fetch result-by-id instead of
re-dispatching.

## Plan review (round 1)

- Codex: task-mpmurao0-zek7ya — LOST from harness (session-state drop on long-running review batch)
- AGY: review-mpmurh2n-sfmiks — completed, PLAN-NEEDS-MAJOR (4 action items addressed in v2)

## Plan review (round 2, on commit 5cd177a0)

- Codex: task-mpmvbj5i-hw5hra — LOST from harness (session-state drop)
- AGY: review-mpmvbr0c-i8e6wh — completed, PLAN-NEEDS-MINOR (4 items addressed in v3)

## Plan review (round 3, on commit dc839ccb)

- Codex: task-mpmvt0z8-hbbdqk — lost from harness; re-dispatched as task-mpmvuetd-57y479
- Codex retry: task-mpmvuetd-57y479 — completed in log (harness lost the id but log captured "Verdict: PLAN-NEEDS-MINOR" 6 items)
- AGY: review-mpmvtaei-6yvid7 — completed, PLAN-NEEDS-MINOR (1 item, overlapped Codex #2)

## Plan review (round 4, on commit 7a56fb71 — v3.2)

- Codex: task-mpmw4sj7-dxkyqo — completed, PLAN-NEEDS-MINOR (3 doc-consistency items addressed in v3.3)
- AGY: review-mpmw4xjc-92bdff — completed, PLAN-READY

## Plan review (round 5, on commit 586b3095 — v3.3)

- Codex: task-mpmwas32-bbysnd — completed, PLAN-NEEDS-MINOR (1 final wording fix in v3.4)
- AGY: not re-dispatched — r4 already PLAN-READY on substantive content

## Plan review (round 6 — FINAL, on commit 6f384430 — v3.4)

- Codex: task-mpmwdrx4-kpdreh — **PLAN-READY**
- AGY: r4 review-mpmw4xjc-92bdff — **PLAN-READY** (still valid on v3.4 since v3.3→v3.4 was wording-only)

**Both reviewers PLAN-READY. Cleared to implement.**

## Code review (round 1, on PR #1569 HEAD bdd551af)

- Codex: task-mpmwyu0c-s5wj0p (background, dispatched 2026-05-26)
- AGY: review-mpmwyzpy-2vbv5h (background, dispatched 2026-05-26)
- Copilot: requested via `gh pr edit --add-reviewer Copilot` + `@copilot review` PR comment
- Claude SMR: pending post-Copilot
