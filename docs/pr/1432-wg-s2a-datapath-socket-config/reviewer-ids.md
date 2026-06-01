# #1432 / #1703 S2a — reviewer task IDs

Plan doc: `docs/pr/1432-wg-s2a-datapath-socket-config/plan.md`
Branch: `refactor/1432-wg-s2a-datapath-socket-config`
Plan commits: v1 `019e713f1`, v2 `c841cdb29`, v3 (this).

## Plan review round 1 — CONVERGED PLAN-NEEDS-MAJOR (two blockers → v2)
- Codex: `wg-s2a-plan-r1-1780272812` — PLAN-NEEDS-MAJOR (RX ownership + reload)
- AGY: `adversarial-review-mpugg9lm-mlr55n` — PLAN-NEEDS-MAJOR (same two)
- Claude-SMR: corrected RX premise (ESP precedent → kernel socket RX); Option A.

## Plan review round 2 — confirmed pivot, 1 mandatory edit → v3
- Codex: `wg-s2a-plan-r2-1780273508` — PLAN-NEEDS-MAJOR (shim too broad needs
  is_local_destination; reinject is TUN/kernel not policy pipeline)
- AGY: `adversarial-review-mpugvd7u-fp5fma` — PLAN-NEEDS-MINOR (same shim edit +
  rp_filter + port-conflict hazards)
- Claude-SMR: verified TUN finding; adopted coherent wgN TUN model.

## Plan review round 3 — CONVERGED PLAN-READY
- Codex: `wg-s2a-plan-r3-1780274137` — PLAN-NEEDS-MINOR (TUN-read MTU pad-aware guard; folded)
- AGY: `adversarial-review-mpuh8tsf-qvo8cp` — PLAN-READY (MTU cap + persistent TUN + telemetry + DNAT note; folded)
- Claude-SMR: agree; v3-final folds all three rounds. CLEARED TO IMPLEMENT.

## Implementation review (PR #1739)
- Codex r1 (impl): session `wg-s2a-impl-r1-*` — 2 BLOCKER + 3 MAJOR; all addressed.
- AGY r1 (impl): `adversarial-review-mpuiq5an-p0yg0d` — 2 HIGH + 3 MED + 1 LOW; addressed/accepted.
- Copilot r1: 5 inline (C1 reconcile, C2 MTU guard, C3 non-TUN link, C4 MTU reuse, C5 sym addr); addressed.
- Codex r3 (confirm): session `wg-s2a-impl-r3-*` (task b9752ybbl) — dispatched.
- AGY r2 (confirm): `adversarial-review-mpujhrq5-1gnajw` — dispatched.
- Claude-SMR: in-conversation hostile review each round; ctrl ABI byte-match, fast-path zero-cost, reload Arc reuse, control-thread-only crypto all verified.
