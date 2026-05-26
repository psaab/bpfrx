# Reviewer task IDs — #1328 Coordinator decompose Phase 2

## Plan round 1 (HEAD ddb1b7d2)
- Codex: task-mpmuqp90-xi2crk (running)
- AGY:   review-mpmuqxve-5cmvqa — PLAN-NEEDS-MINOR
  - Main ask: use sub-mod-dir `coordinator/reconcile/{mod,teardown,reset,snapshot,bringup}.rs`
    (not flat `reconcile_*.rs` siblings). refresh_bindings.rs stays flat.
  - Also: document `ReconcileSnapshotFds` ownership transfer to bringup.
