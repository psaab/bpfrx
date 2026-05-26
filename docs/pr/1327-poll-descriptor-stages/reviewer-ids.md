# #1327 Step 1 — Reviewer task IDs

Recorded so continuations across sessions can fetch by id rather than
re-dispatch (per `feedback_codex_session_loss_continuation`).

## Plan review round 1 (DRAFT v1, commit 0c713258)

- **Codex** task: `task-mpmurvhf-galzxb` — PLAN-NEEDS-MAJOR
- **AGY** job: `review-mpmus86y-f87cd8` — PLAN-NEEDS-MAJOR

## Plan review round 2 (DRAFT v2, commit e61c2896)

- **Codex** task: `task-mpmv1nf2-jsjzwh` (infra-blocked) →
  retry `task-mpmv3ywr-yeiqag` — PLAN-NEEDS-MINOR
- **AGY** job: `review-mpmv1y38-oyj7ha` — PLAN-NEEDS-MINOR

## Plan review round 3 (DRAFT v3, commit 239ce870)

- **Codex** task: `task-mpmvbfiy-yehdyn` — PLAN-NEEDS-MAJOR (caught
  packet_frame borrow hazard)
- **AGY** job: `review-mpmvbnc1-l7248o` — PLAN-READY

## Plan review round 4 (DRAFT v4, commit 19d5b8ed)

- **Codex** tasks `task-mpmvjgzf-yy0ym7` + `task-mpmvl8a9-znbl58`
  infra-blocked; final retry `task-mpmvn6gb-dye2zd` —
  provisional PLAN-READY based on summary (sandbox still blocked)
- **AGY** job: `review-mpmvjkp0-mb9xux` — PLAN-READY
