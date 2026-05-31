# #1706 reviewer task IDs

## Plan review round 1 (commit d90bc3523)

- Codex: isolated foreground session (CODEX_COMPANION_SESSION_ID =
  codex-1706-plan-<ts>). Verdict: Defect 2 PLAN-READY; Defect 1
  PLAN-KILL-as-correctness/optional-cleanup; Defect 3/4 PLAN-NEEDS-MAJOR
  (silent truncation — wants commit-time rejection/acceptance).
- AGY: adversarial-review-mptumeh6-ek4ges. Verdict: all four PLAN-READY.

Resolution: keep all four fixes (defect 1 reframed as robustness
cleanup); add commit-time warnings in ValidateConfig for >100 next-table
routes / >50 rib-group-leaking instances to address Codex NEEDS-MAJOR.
