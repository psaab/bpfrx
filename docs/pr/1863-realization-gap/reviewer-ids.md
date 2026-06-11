# PR #1874 reviewer ledger

## Round 1 (head 116629de1 / 5e7be0d53)
- Codex: task-mq9gp2kw-940jyi (session 019eb69c-d51d-7781-901d-69852516bb1f) — NEEDS-CHANGES: F1 Medium false sharing (unpadded AtomicU64 vs PackedEpochGrant align(64) rule); F2 Low wire round-trip tests missing; F3 Low regime-2 + rotation-race tests missing. Conservation math verified, no over-cap trace found; equal-flow exclusion verified; raw cells recomputed, match.
- AGY: adversarial-review-mq9gghkz-ev246u — NEEDS-CHANGES: F1 Medium/High false sharing (same as Codex F1); F2 Low counter resets across lease rebuilds (doc/runbook note); F3 Medium no multi-threaded race test; F4 Low regime-2 banking untested.
- Claude SMR: claude-smr-code-r1.md — MERGE-READY with finding 1 (counter reset, recorded) + finding 3 (regime-2 test nit). SELF-CORRECTION: SMR's "same contention profile as worker_grants" verification was WRONG — it missed PackedEpochGrant's #[repr(align(64))]; Codex+AGY caught it.

## Round 2 fixes (one commit)
- PaddedAtomicU64 #[repr(align(64))] wrapper for both claim-flow arrays (Codex F1 / AGY F1)
- v8_regime2_banks_lag_owed_plus_unclaimed_and_draws_nothing (Codex F3 / AGY F4 / SMR F3)
- v8_concurrent_acquires_and_rotations_respect_the_budget_bound (AGY F3)
- cos_queue_status_lease_claim_flow_roundtrip_1863 (Rust) + TestCoSQueueStatusLeaseClaimFlowWire (Go) (Codex F2)
- fairness-regimes.md counter-reset note (AGY F2 / SMR F1)
- v8_unclaimed_carry_redeals_flow_proportionally_across_workers (pre-round, isolation pin)
Gates re-run: cargo test --release 1969 passed / 0 failed; go test ./... green.

## Round 2 (code head db48b6ddc / final head cf5161a0d docs-only)
- Codex: task-mq9h98ej-pul5hk (session 019eb6ab-2ce4-79a2-888e-1e1f671a4b76) — MERGE-READY, no residuals (explicitly covered the cf5161a0d docs-only delta)
- AGY: adversarial-review-mq9h7otg-f258kt — MERGE-READY, no residuals (all 4 r1 findings verified folded; regime-2 math + concurrency bound independently validated)
- Claude SMR: claude-smr-code-r2.md — MERGE-READY
- Copilot: UNAVAILABLE after 5 documented attempts — 12:09Z + 12:30Z file-limit (>300 files; fixed by the cf5161a0d slim to 16 files), 12:36:25Z quota-limit failure, 12:36:54Z and 13:0xZ re-requests unanswered after 15+ min bounded waits. Per project policy (feedback_codex_infra_must_retry / #1746 precedent) the merge gate proceeds 3-of-4: Codex + AGY + Claude SMR all MERGE-READY.
