# AGY adversarial plan-review — round 48 (plan v48 @ 3b1b98330)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (7/7 folds FOLDED; 2 fresh attacks FAILED; no new findings). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED — Epoch advances with reservation in critical section and never rolls back (`pkg/cluster/sync_conn_read.go:318-331`, `plan.md:1972-1981,5486-5507,6772-6778`).
2. FOLDED — Done predicate requires no apply failure since bringup, closing same-text DHCP nft failure gap (`pkg/daemon/daemon_dhcp.go:231-245`, `pkg/daemon/daemon_nft.go:262-272`, `pkg/daemon/daemon_apply.go:56-70`, `plan.md:1982-1994,4490-4507,5500-5507,6715-6725`).
3. FOLDED — Capture ordered after window resolution and (1a) automation moratorium (`pkg/configstore/store_commit.go:427-461,503-524`, `pkg/configstore/store_persist.go:21-55`, `plan.md:1994-2002,4385-4409,6552-6565`).
4. FOLDED — Automation moratorium deactivates event-options, in-flight events revalidate via `staleReason` under config lock, no other local autonomous commit source exists (`pkg/eventengine/engine.go:405-428,887-897`, `pkg/daemon/daemon_apply_tail.go:446-455`, `plan.md:2003-2012,6554-6561`).
5. FOLDED — Encrypted fallback origin-node-pinned because body is keyed by source node's master.key (`pkg/configstore/crypto.go:262-285,457-480,307-356,443-455`, `pkg/configstore/db.go:105-130,435-450`, `plan.md:2013-2019,4400-4409,6687-6691`).
6. FOLDED — Residual (iii) window widened from preflight's first sub-read through peer stop in both copies (`pkg/configstore/store.go:687-746`, `plan.md:2020-2024,4510-4523,6642-6655`).
7. FOLDED — Opaque-artifact wording specifies magic-header framing line + possibly-encrypted JSON body (`pkg/configstore/envelope.go:78-99`, `pkg/configstore/db.go:445-450`, `plan.md:2025-2027,4393-4396,6679-6682`).

(B) Fresh attacks:
- Deactivate-event-options quiesce sync perturbation / intent digest: FAILED (Step (2)/(3) preflight and drain explicitly enforce local/peer `ConfigSyncOutstanding == 0` and `persistDegraded == false`, waiting out any in-flight sync or debt, and post-deactivate digest reflects active committed intent).
- No-apply-failure baseline requirement: FAILED (Process restart in step (4) resets the daemon's in-memory health state and monotonic failure counter to 0 for post-restart bringup, making post-restart `applyFailureCount == 0` an absolute zero-failure assertion without needing a pre-procedure baseline).

(C) New findings:
None.

(D) Structure confirmation:
Confirmed: §4.7 delivery structure stands (PR-1 core `d.dp` accessor; follow-up unit G+H+H2; r28 dissent recorded).

(E) Verdict line:
PLAN-READY
