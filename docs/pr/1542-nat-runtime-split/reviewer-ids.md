# #1542 NAT runtime split — reviewer task IDs

## Round 1 (PLAN review on plan v1, commit 724987e6)

- Codex: `task-mpmyrnf2-1de5ha` → PLAN-NEEDS-MAJOR (3 MAJORs)
- AGY: `adversarial-review-mpmys6pk-3ut2f2` → PLAN-READY

## Round 2 (PLAN review on plan v2, commit e59c6f4e)

- Codex: `task-mpmz1whj-5t3zod` → PLAN-NEEDS-MAJOR (5 mechanical)
- AGY: `adversarial-review-mpmz27os-jlg8jq` → PLAN-NEEDS-MINOR (3 named)

## Code review (PR #1573, implementation commit a383cf23 → 3ae779e4)

- Codex attempt 1: `task-mpmzpuvi-1mu1bx` → INFRA-BLOCKED
- Codex attempt 2: `task-mpmzty83-b6m725` → INFRA-BLOCKED
- Codex attempt 3: `task-mpmzxio7-8ho68h` → INFRA-BLOCKED
- AGY: `adversarial-review-mpmzq8kd-ys1bws` → MERGE-READY
- Copilot: COMMENTED (2 inline findings on `a383cf23`); both addressed in `3ae779e4`

3-of-4 attestation: Claude (SMR) + AGY + Copilot green; Codex repeatedly
sandbox-infra-blocked.
