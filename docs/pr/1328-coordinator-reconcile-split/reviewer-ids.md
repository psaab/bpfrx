# Reviewer task IDs — #1328 Coordinator decompose Phase 2

## Code review round 2 (HEAD 97b81739, PR #1570)
- Codex: task-mpmxisuc-ni3rm3
- AGY:   review-mpmxiv5r-ybhx29
- Copilot: @copilot re-review requested via PR comment

## Code review round 1 (HEAD ffb57266, PR #1570)
- Codex: task-mpmx943s-q3i3fg (sandbox infra ENOENT) -> retry
  task-mpmxbgch-2gp4px (also ENOENT) -> task-mpmxdjdu-6e25by
  (summary-only best effort) MERGE-READY
- AGY:   review-mpmx98v3-pit578 — MERGE-READY (full inspection)
- Copilot: copilot-pull-request-reviewer COMMENTED with 2 findings
  - zero_unbound_slot misses 3 tx_error subset counter zeros
  - test name implies more coverage than the body asserts

## Plan round 4 (HEAD dab1ada3) — both PLAN-READY
- Codex: task-mpmvh9at-ri87j9 — PLAN-READY (best effort; sandbox
  infrastructure was intermittently broken across attempts r3/r4)
- AGY:   review-mpmvh0u7-jju520 — PLAN-READY
  - Upstream-unrelated finding: docs/userspace-dataplane-gaps.md
    uses "fail closed" but snat_contract_doc_guard.rs asserts
    "fail-closed" — pre-existing master drift, not part of #1328.

## Plan round 3 (HEAD a349be37)
- Codex: task-mpmv5brm-wiwof9 / -mpmv7063-rfsgw9 / -mpmv8wav-4ph9hv
  — PLAN-NEEDS-MINOR (5 findings: sub-file naming, mod-count,
  stage-sequence test claim, LOC over/under, histogram wording)
- AGY:   review-mpmv5e8p-nlw1p8 — PLAN-READY

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
