# AGY adversarial plan-review — round 44 (plan v44 @ e30ea7a3e)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; 1 fresh attack FAILED; no new findings). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED — Publication order is pinned via pre-enqueue reservation and default/nil-channel rollback decrement at pkg/cluster/sync_conn_read.go:318-331; Go select semantics guarantee mutually exclusive execution of send vs default arms (preventing double-decrements), with the publication-order test seam recorded at plan.md:6089-6094.
2. FOLDED — All ingress config frames dispatch through handleMessage's syncMsgConfig case (pkg/cluster/sync_conn_read.go:298-332), covering pre-install pending frames (pkg/cluster/sync_conn.go:122-127), superseded readers (pkg/cluster/sync_conn.go:244-267,480-498), post-Stop-cap readers (pkg/cluster/sync_conn.go:349-385), and unkeyed ingress (pkg/cluster/sync_admission.go:58-83, pkg/cluster/sync_auth.go:321-334); no production config-apply path bypasses handleMessage.
3. FOLDED — Failure-class split (pkg/fsatomic/fsatomic.go:45-53,66-72) and authority-conditional convergence (pkg/daemon/daemon_ha_sync.go:447-465, pkg/cluster/election.go:172-193) match codebase behavior; operational closure in runbook (plan.md:3946-3985) and acceptance copy (plan.md:6029-6049) correctly pins configdb directory sync plus post-restart comparison against the operator's intended config with ConfigWriteUnverified == false AND ConfirmDebtKindMask == 0.
4. FOLDED — Acceptance copy (plan.md:6029-6049) and runbook normative copy (plan.md:3946-3985) agree word-for-word on residual (iii)'s bounds and verification criteria.
5. FOLDED — Terminal exit covers all reader exit branches (pkg/cluster/sync_conn_read.go:22-93); IsSyncConnected (pkg/cluster/sync_state.go:66-74, pkg/cluster/sync.go:961-964) checks s.stats.Connected, which tracks active fabric presence across redundant sessions (pkg/cluster/sync_conn.go:273,497), ensuring status Down reflects complete termination of all session readers.

(B) Fresh attacks:
- Post-drop re-push reservation race: FAILED — The dropped frame's reservation is rolled back synchronously in the default arm of the enqueue select (pkg/cluster/sync_conn_read.go:324-331); any subsequent re-push arrives as a fresh wire message through handleMessage, taking a new reservation cleanly (+1/-1 balance preserved).

(C) New findings:
None.

(D) Structure confirmation:
§4.7 structure stands (2-of-3 majority B split: PR-1 core + follow-up G+H+H2; AGY r28 (A) dissent remains recorded at plan.md:4801,4834).

(E) Verdict:
PLAN-READY
