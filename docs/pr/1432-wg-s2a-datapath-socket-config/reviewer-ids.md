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

## Plan review round 3 — confirming v3 folds
- Codex: (pending dispatch)
- AGY: (pending dispatch)
