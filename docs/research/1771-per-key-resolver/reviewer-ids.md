
## Round 1 (6fa2d15cc) — all PLAN-NEEDS-MAJOR
- Codex: task-mq1hyrjk-pk8mvp
- AGY: adversarial-review-mq1hz7qd-ntlvgy
- Claude SMR: PR #1775 comment 4636090753
- Synthesis: PR #1775 comment 4636127812
- 8 convergent findings → addressed in plan v2

## Round 2 (v2) — pending
- Codex r2: task-mq20h0l4-fy67hk
- AGY r2: adversarial-review-mq20hlfv-21p9yx
- Claude SMR r2: docs/research/1771-per-key-resolver/claude-smr-plan-r2.md (PLAN-NEEDS-MINOR; MAJOR-on-§2.1-GC-resurrection)

## Round 2 (v2 @31c4be70a) — all 3 converged on Path B
- Codex r2: task-mq20h0l4-fy67hk — PLAN-NEEDS-MAJOR (ship §2.2, fix §2.5 ownership, gate §2.1)
- AGY r2: adversarial-review-mq20hlfv-21p9yx — PLAN-NEEDS-MAJOR → Path B highly recommended
- Claude SMR r2: claude-smr-plan-r2.md — PLAN-NEEDS-MINOR
- v3 folds: §2.5 upsert-only (kernel-ownership fix), §2.3 correction, §2.1 global-monotonic-epoch + reject-on-absent + age-discard + incremental GC + API audit, test seams
- Codex r3: task-mq21criq-e26xuy
- AGY r3: adversarial-review-mq21crt9-nwiust
- Claude SMR r3: claude-smr-plan-r3.md (PLAN-READY Phases 1-3; §2.1 gated)
- Codex r3: task-mq21criq-e26xuy — Phase 1-3 NEEDS-MINOR (doc scrub); §2.1 NEEDS-MAJOR-when-built (reject-on-absent)
- AGY r3: adversarial-review-mq21crt9-nwiust — Phase 1-3 PLAN-READY; §2.1 NEEDS-MINOR (absent-slot fix)
- Claude SMR r3: PLAN-READY Phase 1-3
- v3.1 @ converge: doc scrubs + §2.1 epoch_before==0 absent-allow + bounded due-key scheduler
