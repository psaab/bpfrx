# AGY adversarial plan-review — round 43 (plan v43 @ 586a0c6d9)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; 2 fresh attacks FAILED; no new findings). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED: Total retirement balance holds across all frame receipt paths — enqueue failure arms do not increment (`pkg/cluster/sync_conn_read.go:321-331`), consumer per-item defer decrements on all exit paths (`pkg/cluster/sync_conn_config.go:325-351`), and teardown drains buffered items (`pkg/cluster/sync_conn.go:349-385`, `plan.md:3760-3778,4758-4770`).
2. FOLDED: Node-lifetime counter ownership across transport replacements (`pkg/daemon/daemon_apply_tail.go:238-255`, `pkg/daemon/daemon_ha_sync.go:1405-1415`, `pkg/cluster/sync_state.go:47-63`) paired with local session EOF observation (`pkg/cluster/sync_conn_read.go:28-60`) closes all false-idle and partial-frame windows (`plan.md:3748-3760,3801-3812`).
3. FOLDED: Residual shape (iii) (push during 2a-2b window) is bounded with explicit restart `Load` classification, `OnPeerConnected` re-drive (`pkg/daemon/daemon_ha_sync.go:926-956`), and `/health` 503 error visibility on permanent disk failure (`pkg/configstore/store.go:687-746`, `pkg/configstore/store_persist.go:397-401`, `plan.md:3827-3850`).
4. FOLDED: Read surface attribution is consistent — debt mask and persist state are read via peer `/health`, and outstanding counter is read via peer cluster-status RPC (`plan.md:3786-3796,4773-4778,5805-5810`).
5. FOLDED: JOIN-COHERENCE sub-legs (a)-(e) explicitly cover framed-blocking-apply, gen-0 payloads, concurrent gen-resets, provider replacement, and retirement totality (`plan.md:5866-5885`).

(B) Fresh attacks:
- Attack 1 (5s Stop timeout with applySem-blocked apply): FAILED — Node-lifetime counter scope keeps the in-flight token counted past `Stop()`'s 5s cap, and the consumer's per-item defer decrements the counter when `OnConfigReceived` completes (`pkg/cluster/sync_conn.go:349-385`, `pkg/cluster/sync_conn_config.go:325-351`).
- Attack 2 (Heartbeat timeout / bad magic read loop termination): FAILED — Any read-loop exit invokes `defer s.handleDisconnect(conn)`, terminating frame ingestion and satisfying the session disconnection witness (`pkg/cluster/sync_conn_read.go:15-17,33-46,54-57`).

(C) New findings:
None.

(D) Structure confirmation:
The §4.7 delivery structure stands: PR-1 delivers the titled #2114 core, followed by the G+H+H2 commit-confirmed integrity PR, with AGY's r28 (A) dissent recorded (`plan.md:4652-4696`).

(E) Verdict:
PLAN-READY
