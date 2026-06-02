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

## Plan review round 4 (plan v4 @ d3016b922)
- Codex: /tmp/codex-1748-r4.txt, bash bg `bgiy46xot` — PLAN-NEEDS-MAJOR (TTL race: promote near-expiry replica -> GC removes sole owner; rollback order unsafe; ack must be {seq,key,origin,result})
- AGY: adversarial-review-mpwqtig4-0q0vg7 — PLAN-READY (### Verdict: PLAN-NEEDS-MINOR)
- Claude-SMR: PLAN-READY concur-with-Codex (both r4 findings real; folded to v5)

## Plan review round 5 (plan v5 @ 929dbd403)
- Codex: /tmp/codex-1748-r5.txt, bash bg `bd3w287b2` — pending (verify liveness-refresh + reverse-barrier rollback close r4)
- AGY: adversarial-review-mpwqzh2x-p37bkx — pending
- Claude-SMR: PLAN-READY (liveness-refresh kills the near-expiry race; reverse-barrier rollback is the correct order)

## Plan review round 5 (plan v5 @ 929dbd403)
- Codex: /tmp/codex-1748-r5.txt, bash bg `bd3w287b2` — PLAN-NEEDS-MAJOR (r4 findings CLOSED; new: teardown of live move not barriered -> leak)
- AGY: adversarial-review-mpwqzh2x-p37bkx — PLAN-READY
- Claude-SMR: PLAN-READY concur-with-Codex (teardown barrier real; folded to v6)

## Plan review round 6 (plan v6 @ a37206bfa)
- Codex: /tmp/codex-1748-r6.txt, bash bg `b8px03pgf` — pending (transition-set completeness: second-move, rule-cap eviction, failover-mid-move)
- AGY: pending
- Claude-SMR: PLAN-READY (transition set {install,rollback,teardown,dead} appears complete; second-move + eviction are instances of the same barrier principle)

## Plan review round 6 (plan v6 @ a37206bfa) → CONVERGED
- Codex: /tmp/codex-1748-r6.txt, bash bg `b8px03pgf` — PLAN-READY (no blocking transition gap)
- AGY: adversarial-review-mpwr6tev-7agzdw — PLAN-NEEDS-MINOR (2 terminal-path gates; pre-declared their incorporation = PLAN-READY)
- Claude-SMR: PLAN-READY
- v7 @ folds AGY's two terminal-path gates → CONVERGED PLAN-READY

## CODE review round 1 (PR #1749 @ a5621aa12)
- Codex: /tmp/codex-1748-code-r1.txt, bash bg `b2cov2wgl` — pending
- AGY: (job id below) — pending
- Copilot: triggered on PR #1749
- Claude-SMR: pending (hostile diff read)
