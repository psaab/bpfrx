# Reviewer task IDs — #1328 Coordinator decompose Phase 2

## Plan round 3 (HEAD a349be37)
- Codex: task-mpmv5brm-wiwof9 (running)
- AGY:   review-mpmv5e8p-nlw1p8 (running)

## Plan round 2 (HEAD f273aff2)
- Codex: task-mpmuziyj-tzmqo2 — PLAN-NEEDS-MAJOR
  - All 8 r1 findings resolved at the delta-block level but
    body text had stale v1 contradictions.
- AGY:   review-mpmuzmkw-3n5oiz — PLAN-NEEDS-MINOR
  - 4 stale-text findings (had_live_workers ghost,
    panic-slot helper in Open Q7, flat siblings in Open Q2,
    test name discrepancy).

## Plan round 1 (HEAD ddb1b7d2)
- Codex: task-mpmuqp90-xi2crk — PLAN-NEEDS-MAJOR (8 findings)
- AGY:   review-mpmuqxve-5cmvqa — PLAN-NEEDS-MINOR
  - Main ask: use sub-mod-dir `coordinator/reconcile/{mod,teardown,reset,snapshot,bringup}.rs`
    (not flat `reconcile_*.rs` siblings). refresh_bindings.rs stays flat.
  - Also: document `ReconcileSnapshotFds` ownership transfer to bringup.
