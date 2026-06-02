# #1748 reviewer task/job IDs

Continuations fetch by id (Codex loses session state >30min).

## Plan review round 1 (plan @ c84523b27)
- Codex: foreground-isolated (CODEX_COMPANION_SESSION_ID=1748-plan-r1-*), bash bg id `bbl5p1z6r`
- AGY: `adversarial-review-mpwpik0h-my8ni9`
- Claude-SMR: `docs/pr/1748-ntuple-rebalance/claude-smr-plan-r1.md` — PLAN-NEEDS-MINOR

## Plan review round 2 (plan v2 @ 47db3a4f4)
- Codex: foreground-isolated (CODEX_COMPANION_SESSION_ID=1748-plan-r2-*), output /tmp/codex-1748-r2.txt — PLAN-NEEDS-MAJOR (conntrack 5th site, no-close-owner leak, RebalancedOut HA/export leaks; ioctl direction CONFIRMED correct)
- AGY: adversarial-review-mpwq7ctx-qc5xfm — pending
- Claude-SMR: claude-smr-plan-r2.md — PLAN-NEEDS-MAJOR (concur)

## Plan review round 3 (plan v3 @ 0f52cc85b)
- Codex: foreground-isolated (CODEX_COMPANION_SESSION_ID=1748-plan-r3-*), output /tmp/codex-1748-r3.txt, bash bg id `baw2rokje` — pending
- AGY: adversarial-review-mpwqkxjl-cy4m05 — pending
- Claude-SMR: claude-smr-plan-r3.md — PLAN-READY (with single-tick ordering invariant folded into §4.5)

## Plan review round 3 (plan v3 @ 0f52cc85b)
- Codex: /tmp/codex-1748-r3.txt, bash bg `baw2rokje` — PLAN-NEEDS-MAJOR (async-queue zero-owner race; promote must not reuse update_session/maybe_promote_synced_session)
- AGY: adversarial-review-mpwqkxjl-cy4m05 — PLAN-READY
- Claude-SMR: claude-smr-plan-r3.md — was READY, SELF-CORRECTED to concur with Codex NEEDS-MAJOR

## Plan review round 4 (plan v4 @ d3016b922)
- Codex: /tmp/codex-1748-r4.txt, bash bg `bgiy46xot` — pending (verifying barrier + dedicated promote close r3 findings)
- AGY: adversarial-review-mpwqtig4-0q0vg7 — pending
- Claude-SMR: PLAN-READY (barrier reuses session_export_ack idiom; dedicated origin-only promote specified) — doc on reconcile
