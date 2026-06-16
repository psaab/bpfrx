# #1917 in-place upgrade — reviewer task-id ledger

Record Codex task IDs + AGY job IDs per round so continuations can fetch by id
(Codex companion is ONE job globally; long sessions hit "No jobs recorded").

## Round 1
- Codex: task-mqg8kjut-tleotn
- AGY: adversarial-review-mqg8kzn5-d7t8ps (wedged-queued, cancelled), re-dispatched adversarial-review-mqg8v8n6-7gchnc (also wedged, cancelled); stray --help launched adversarial-review-mqg8y667-304xf8 (succeeded but wrong prompt); REAL round-1 = adversarial-review-mqg95ecx-rqahpj -> PLAN-NEEDS-REVISION (4 novel blockers: dh_installsystemd auto-restart, kernel-verify-needs-boot, non-atomic manifest, upgrade-cmd bootstrapping)
- Claude SMR: in-conversation

## Round 2
- Codex: task-mqg9b1ml-ohvzsn
- AGY: adversarial-review-mqg9bbwp-77zben
- Claude SMR: in-conversation
