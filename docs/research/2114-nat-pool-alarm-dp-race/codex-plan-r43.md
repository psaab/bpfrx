# Codex hostile plan-review — round 43 (plan v43 @ 586a0c6d9)

Task: task-ms9uv83j-reux8h (session 019fbb86-1e39-7a02-96de-c35e6186d54c).
Verdict: NEEDS-REVISION (3 MAJOR, 2 MINOR; fold verification 1 FOLDED / 4 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification

1. PARTIAL — v43 textually assigns every path: pre-dispatch read/auth failures create no token (`pkg/cluster/sync_conn_read.go:28-89`); nil-channel and queue-full paths create none, while successful enqueue creates one (`pkg/cluster/sync_conn_read.go:298-332`); dequeue transfers retirement to a per-item defer covering stale, nil-handler, success, failure, and panic; cancellation leaves buffered items to teardown (`pkg/cluster/sync_conn_config.go:325-395`; `plan.md:3760-3778`). Consumer and drain cannot both receive one item, but publish-before-increment and post-drain enqueue still violate totality.

2. PARTIAL — Node-lifetime ownership closes provider replacement in principle (`plan.md:3749-3759`; `pkg/cluster/sync_state.go:47-63`; `pkg/daemon/daemon_ha_sync.go:906-913`). An apply blocked beyond Stop’s five-second cap remains owned: it uses `context.Background()` and can decrement when it eventually returns (`pkg/daemon/daemon_ha_sync.go:578`; `pkg/daemon/daemon_apply_commit.go:331-335`; `pkg/cluster/sync_conn.go:349-385`). The EOF/disconnection witness, however, is not an all-ingress join.

3. PARTIAL — Residual shape (iii) is now admitted (`plan.md:3827-3851`), but its claimed self-healing bound is false: reconnect re-drive is conditional on connection, authority, uptime, and config-sync state (`pkg/daemon/daemon_ha_sync.go:440-465`), and post-rename persistence failures do not leave the prior active config intact.

4. FOLDED — Normative text correctly reads peer mask/persist through `/health` and the counter through cluster status (`plan.md:4773-4778,5803-5808`). The sole contrary hit is the explicitly superseded v42 ledger at `plan.md:1610-1615`, corrected by the v43 ledger at `plan.md:1680-1684`.

5. PARTIAL — All five named sub-legs exist (`plan.md:5866-5885`), but they do not cover every M1/M2 path: nil-channel, callback failure, panic unwind, partial-frame exit, and setup/superseded-reader ingress are absent (`pkg/cluster/sync_conn_read.go:28-93,321-332`; `pkg/cluster/sync_conn_config.go:351-383`).

New findings

MAJOR 1: The counter is published in the wrong order. `plan.md:3761-3766` requires incrementing inside the successful-enqueue arm, but the channel send completes—and the item becomes receivable—before that arm’s body runs (`pkg/cluster/sync_conn_read.go:321-324`). The consumer can dequeue and block or even execute its retirement before the producer increments (`pkg/cluster/sync_conn_config.go:325-351`), yielding the exact false zero that `plan.md:3779-3780,5867-5874` claims impossible. Increment must reserve ownership before publication, with rollback on nil/full disposition, or enqueue/accounting must be serialized; the test needs a seam after publication but before producer continuation.

MAJOR 2: Neither teardown nor the runbook proves ingress quiescence. Stop caps one shared goroutine wait at five seconds and then proceeds (`pkg/cluster/sync_conn.go:132-136,341-385`), so draining afterward cannot prove an old reader will not enqueue later. Worse, a legacy pending frame is processed before connection installation (`pkg/cluster/sync_conn.go:88-130`; `pkg/cluster/sync_auth.go:363-369`), same-fabric replacement overwrites a slot while the superseded reader may continue (`pkg/cluster/sync_conn.go:244-267`), and its eventual disconnect is ignored as stale (`pkg/cluster/sync_conn.go:480-498`). Thus both registered conn0/conn1 reaching down does not cover setup or superseded readers. Stopping the intended peer also does not fence third-party/stale-process ingress in unkeyed deployments, which explicitly dual-accept unauthenticated connections (`pkg/cluster/sync_admission.go:58-83`; `pkg/cluster/sync_auth.go:321-334`). A tracked ingress/setup epoch join or local listener/enqueue fence is required.

MAJOR 3: Residual (iii)’s bound is dishonest in two independent ways. First, reconnect does not unconditionally push the repaired node’s current config: it skips until 30-second stability and unless that node remains RG0 authority (`pkg/daemon/daemon_ha_sync.go:447-465`); the stale peer can preempt under its old priorities (`pkg/cluster/election.go:172-193`), leaving convergence direction unpinned or pushing the old config backward. Second, `plan.md:3842-3848` says a failed write leaves the prior persisted active, while the plan itself and implementation say a post-rename failure leaves the new content visible (`plan.md:2381-2391`; `pkg/fsatomic/fsatomic.go:45-53,66-72`). Restart then loads and applies that visible config (`pkg/configstore/store_persist.go:21-55,110-114`; `pkg/daemon/daemon_run_bringup.go:516-520`), and an equal applied re-push skips `SyncApply` (`pkg/daemon/daemon_ha_sync.go:550-568`), so the abandoned in-memory degradation is not reconstructed and `/health` can be green despite unproven durability (`pkg/api/health.go:65-71`). This residual needs a producer fence/durable acknowledgement or a pinned authority-and-durability recovery protocol.

MINOR 1: Formal acceptance omits residual shape (iii). The normative runbook admits three shapes at `plan.md:3827-3851`, but acceptance enumerates only the deadline and D-kind abandonment cases at `plan.md:5834-5856`.

MINOR 2: “Header-read EOF” is too narrow. Heartbeat timeout, bad magic, oversized or partial payload, authentication failure, cancellation, and ordinary read errors are all valid terminal exits (`pkg/cluster/sync_conn_read.go:22-89`); dispatch happens only after complete verification (`pkg/cluster/sync_conn_read.go:90-93`). The requirement should be terminal exit of every relevant ingress reader—not literal EOF and not merely `Connected == false`.

Structure confirmation: STANDS — §4.7 still keeps the #2114 accessor core in PR-1 and G+H+H2 together in the follow-up (`plan.md:4652-4695`).

NEEDS-REVISION

Codex session ID: 019fbb86-1e39-7a02-96de-c35e6186d54c
Resume in Codex: codex resume 019fbb86-1e39-7a02-96de-c35e6186d54c
