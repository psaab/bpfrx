# #1630 research — reviewer task-id ledger

Per `feedback_codex_session_loss_continuation`: record task ids so
continuations can fetch by id.

## Round 1

- Codex plan-review: (inline-prompt; sandbox session-wide broken — see SKILL note) task-id: codex exec session 019e6fff-0491-7301-9487-d28c2f8baab0 (read-only sandbox OK; PLAN-NEEDS-MAJOR)
- AGY adversarial plan-review: adversarial-review-mppvapja-8sjwm6 (PLAN-NEEDS-MAJOR-REWORK)
- Claude SMR plan-review: `claude-smr-plan-r1.md` (this agent)

## Round 2 (v2 — measurement-corrected root cause)

- Measurement evidence: `measurement-r1.txt` (park_root=0 all classes; small-four-alone A/B 69/79/87/86%)
- Codex plan-review: codex exec session 019e7007-9c30-7952-8a6e-a6404af8fe25 (PLAN-NEEDS-MAJOR)
- AGY adversarial plan-review: adversarial-review-mppvn7jw-khzbbp (PLAN-NEEDS-MAJOR)
- Claude SMR plan-review: `claude-smr-plan-r2.md` (this agent)

## Round 3 (v3 — fix re-targeted to lease top-up watermark)

- Codex plan-review: codex exec session 019e700e-8add-7ac1-b2c6-184a67df32c6 (r3 PLAN-NEEDS-MINOR -> r3b PLAN-READY on v3.1; session 019e7012-f58f-78f3-9047-98f4d034e05c)
- AGY adversarial plan-review: adversarial-review-mppvx6qs-lth0pl (PLAN-READY)
- Claude SMR plan-review: `claude-smr-plan-r3.md` (this agent)
