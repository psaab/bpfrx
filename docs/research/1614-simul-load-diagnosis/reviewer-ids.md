# #1614 simul-load diagnosis — reviewer task IDs

Plan: docs/research/1614-simul-load-diagnosis/plan.md (v2, commit 60ef9f284)

## Round 1 (plan v2)

- Codex: task-mpsgzupl-q5t3ww (effort=high, background)
- AGY adversarial: adversarial-review-mpsh02bx-mm52n8 (background, base origin/master)
- Claude SMR: docs/research/1614-simul-load-diagnosis/claude-smr-plan-r{1,2}.md
  (r1 PLAN-READY-WITH-RESIDUALS on v1; r2 PLAN-READY on v2 after self-correcting
  the single-owner-funnel claim via the §2.4 competitor-count A/B)

Note: v1 plan (single-owner funnel) was self-refuted by measurement before
external dispatch; only v2 went to Codex + AGY.

## Round 1 verdicts (on plan v2)
- Codex task-mpsgzupl-q5t3ww: PLAN-NEEDS-MAJOR (§3.B per-worker quantum_sum
  mechanism code-false; v8 lease/root FCFS not ruled out; #1628 counters
  aggregated can't validate per-worker split; Phase-2 honored-set is
  approximate). Reframe §3.B as unresolved + instrument before fix.
- AGY adversarial-review-mpsh02bx-mm52n8: PLAN-READY (proposed Phase-2
  epoch-lockout mechanism; SMR cross-check REFUTED it as active cause via
  live waterfill_epochs counter).
- Claude SMR r2: PLAN-READY on v2 (with /engineer per-worker-counter gate).

## v3 (folds Codex r1 + AGY r1; §3.B reframed UNRESOLVED, instrument-first)
- Claude SMR r3: PLAN-READY.
- Codex r2: re-dispatched on v3 (see below).
