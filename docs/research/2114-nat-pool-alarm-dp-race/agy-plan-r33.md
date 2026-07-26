# AGY adversarial plan-review — round 33 (plan v33 @ ee4e82ee1)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; 3 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. Action-scoped continuous EXIT: FOLDED (docs/research/2114-nat-pool-alarm-dp-race/plan.md:1184-1193, 2661-2677, 4808-4813; pkg/configstore/store_persist.go:402-428).
2. Total + observable EXIT: FOLDED (docs/research/2114-nat-pool-alarm-dp-race/plan.md:1194-1205, 2678-2708, 3166-3168, 4185-4187, 4813-4824; pkg/configstore/store_persist.go:402-428).
3. Second-swap leg: FOLDED (docs/research/2114-nat-pool-alarm-dp-race/plan.md:1205-1212, 2738-2751, 4806-4813; pkg/configstore/store_persist.go:402-428).
4. keyClass copies unified: FOLDED (docs/research/2114-nat-pool-alarm-dp-race/plan.md:1170, 1213-1214, 3441, 3515-3516, 4632, 4714).
5. Missing-key message class-split: FOLDED (docs/research/2114-nat-pool-alarm-dp-race/plan.md:1215-1218, 2220-2223, 2762-2771, 2929-2932).

(B) Fresh attacks:
- CONFIRMED-EMPTY exit proof obligation vs arm interleavings: Hypothesis that a new encrypted record could be written between proof of all-absent/all-plaintext and state exit. Outcome: FAILED (attack closed — Store-level pre-checks refuse all arm/commit entries at CommitConfirmed, SyncApply, and bootstrap import while writeUnverified holds if any encrypted write would be produced: docs/research/2114-nat-pool-alarm-dp-race/plan.md:2647-2652, 2720-2735, 3598-3601, 4798-4803; pkg/configstore/store_commit.go:550).
- Both-sides validation under s.mu: Hypothesis that ReadConfirm/decrypt on the confirm side while holding s.mu introduces lock inversion or request-path latency hazards. Outcome: FAILED (attack closed — DB.ReadConfirm holds no internal locks and runs strictly inside the background persistRetryLoop goroutine, avoiding lock inversion and request latency: pkg/configstore/db.go:242-250; pkg/configstore/store_persist.go:402-428; docs/research/2114-nat-pool-alarm-dp-race/plan.md:2667-2674).
- Stay-alive key-path probe: Hypothesis that keeping persistRetryLoop active for writeUnverified probing causes infinite loop spinning or fails to terminate post-exit. Outcome: FAILED (attack closed — the stay-alive condition evaluates writeUnverified alongside persistDegraded and confirmRemoveDegraded; upon successful positive validation, writeUnverified clears to false and the loop terminates cleanly on the subsequent pass if no other debt remains: pkg/configstore/store_persist.go:402-411; docs/research/2114-nat-pool-alarm-dp-race/plan.md:2707-2708, 4821-4824).

(C) Structure confirmation:
§4.7 delivery structure confirmed: 2-of-3 split ruling stands (PR-1 = d.dp core work item A1; follow-up unit = G+H+H2), with r28 (A) dissent recorded (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3766-3810).

PLAN-READY
