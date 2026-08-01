# AGY adversarial plan-review — round 57 RULING (plan v57 @ a4094634c)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY-WITH-NITS — ruling (B) SIMPLIFY THE CLAIM ("none found" on the unsafe-construction test). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. M7 (contract synchronization): FOLDED — plan.md:2448-2454,6121-6127,6476-6490,6843-6846 verified against code at pkg/daemon/daemon.go:420-424, pkg/daemon/daemon_ha.go:438-475, pkg/dataplane/userspace/manager_compile.go:211-214,567-591, pkg/dataplane/apply.go:37-40,130-134, pkg/cluster/sync_conn_config.go:234-250.
2. M8 (§9 legs): FOLDED — plan.md:7939-7972 verified (h2j legs: OnXSKBound callback interleave, PrepareLinkCycle registration, completion-vs-next-mint transaction, slow-poll mint, returned detach failure with errors.Join, authority re-promotion leg; h2i contention leg m1).
3. m2 (pending-term omissions): FOLDED — plan.md:5246,6470 verified (post-reactivation predicate and rendering inventory both carry no-pending term).

(B) Ruling:
(B) SIMPLIFY THE CLAIM. Ten rounds (r47-r56) of expanding H2's done-predicate machinery to chase instantaneous zero-residual correctness across asynchronous IPC and cluster transport boundaries have demonstrated that each new instantaneous wire/IPC construction introduces further protocol edge cases (e.g., inventing an apply-level wire ACK protocol mid-plan). Ruling (B) stabilizes H2 on the already-converged core machinery (ConfigSyncOutstanding counter, dispatch epoch, configstore-owned versioned snapshot, tri-state with terminal/pending, per-arm registration, validate-claim-then-send serialization, interval-bracketed double digest check, operator re-drive). The remaining r56 M1-M6 mechanism-depth races degrade strictly in safe directions (false-red health/pending states, fail-closed unavailability, or digest divergence caught at the bracketing reads with operator re-drive recovery), and the apply-level ACK is appropriately scoped to a named follow-up issue to harden #5863 generally.

(C) Any construction your ruling does not make safe:
none found. (All r56 M1-M6 edge cases — receiver-acceptance gap, provider-generation linearization, demotion publication race, rollback health fork, callback identity, and debt-transfer transaction — degrade to either false-red health/pending flags, fail-closed unavailability, or detected digest divergence caught by the interval-bracketed double digest check with operator re-drive recovery).

(D) Structure confirmation:
The §4.7 two-unit delivery structure stands (r28 (A) dissent remains recorded).

(E) Verdict line:
PLAN-READY-WITH-NITS
