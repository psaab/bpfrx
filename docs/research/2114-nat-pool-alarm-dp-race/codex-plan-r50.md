# Codex hostile plan-review — round 50 (plan v50 @ 2ca8da070)

Task: task-msa2ga8u-gvdceu (session 019fbc48-848e-7740-87f9-edeeada9f36b).
Verdict: NEEDS-REVISION (4 MAJOR, 1 MINOR; fold verification 2 FOLDED / 3 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The proposed inventory and tests exist (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:5598-5613,5736-5745,7094-7104`), and no whole-daemon reconcile path bypasses `applyConfigLocked` (`pkg/daemon/daemon_apply.go:49-86,141-355`; `pkg/daemon/daemon_apply_commit.go:246,489,697`). However, incoherent status sampling and an uncounted mandatory dataplane reapply still permit false green, as detailed below. Legitimate never-applied 0/false states exist in bootstrap/config-only/nil-active startup (`pkg/daemon/daemon_run_bringup.go:414-523`); the explicit last-success term rejects them, so that case fails closed.

2. PARTIAL — The runbook requires both-node reactivation, each commit’s success, and the complete predicate (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:4712-4727`), but formal §9 remains singular and digest-only (`plan.md:7027-7034`). Both copies do not carry the fold.

3. PARTIAL — Election-settle ordering and intended-holder/local-first precedence appear in both copies (`plan.md:4591-4612,6935-6951`) and match Load-before-comms plus priority preemption (`pkg/daemon/daemon_run.go:157-177,393-398`; `pkg/cluster/election.go:172-193`). The post-stability stale-push race and authority-dependent dead ends below still break the choreography.

4. FOLDED — Both copies include re-baseline/repeat and terminate after the second advancing epoch by declaring live ingress, making stopped remediation unavailable, and requiring fencing or live removal (`plan.md:4356-4367,6866-6873`).

5. FOLDED — Both baselines are covered: pre-(1a) commits invalidate the pre-quiesce digest; commits between (1a)/(1b) invalidate the fence-time pair (`plan.md:4204-4211,6810-6817`).

New findings:

MAJOR — The proposed apply-health fields have no coherent status-snapshot contract. They are independent atomics rendered beside independently locked `ActiveApplied` (`plan.md:5598-5613,5736-5745`; `pkg/configstore/store.go:797-809`), and the show path takes no `applySem` (`pkg/grpcapi/server_show_cluster_text.go:68-70`). A renderer can read old `lastApplyOK=true`, then a DHCP/feed apply enters and writes false, then read count zero and the still-true ActiveApplied, returning green while the apply is parked (`pkg/daemon/daemon_apply.go:49-56`; `pkg/daemon/daemon_dhcp.go:73-90`). h2b starts the parked apply before the predicate read and therefore misses entry between component reads (`plan.md:7101-7104`). The plan needs a linearizable snapshot/read-order contract and a mid-render-entry regression.

MAJOR — Nil return from the outer full-apply entry is not equivalent to dataplane convergence. The mandatory deferred-MAC second `ApplyConfig` can fail while merely recording retry debt (`pkg/daemon/daemon_apply_dataplane.go:390-402,466-489`); its contract explicitly says the commit still succeeds while the workerless snapshot leaves forwarding down (`pkg/dataplane/userspace/manager_worker_arm_5134.go:10-21`). Thus the proposed central wrapper records count 0/lastOK true and ActiveApplied can be marked true. Boot has another 0/true path: `dp.Start` failure clears `d.dp` but still runs the boot apply (`pkg/daemon/daemon_run_bringup.go:493-520`), whose dataplane phase skips nil `d.dp` (`pkg/daemon/daemon_apply_dataplane.go:137-163`) before the wrapper marks applied (`pkg/daemon/daemon_apply.go:56-70`). These outcomes must feed the sticky state or become explicit predicate terms.

MAJOR — The 30-second reconciler can durably overwrite the peer after the final predicate passes. It captures old text and claims the old marker before `QueueConfig`, without `applySem` serialization (`pkg/daemon/daemon_ha_sync.go:462-497`). While paused there, the operator can commit and queue intended text, then mark intended as pushed (`pkg/daemon/daemon_apply_commit.go:274-285`; `pkg/daemon/daemon_ha_sync.go:351-378`). The predicate can pass; when the stale reconciler resumes, `QueueConfig` assigns old text a newer wire generation (`pkg/cluster/sync_conn_config.go:222-243`), which the receiver accepts and applies (`pkg/cluster/sync_conn_config.go:254-272,325-395`). Because the marker remains “intended,” later reconciliation no-ops (`pkg/daemon/daemon_ha_sync.go:479-484`). A completed old push before override is detectable and re-drivable; this capture-before/queue-after interleaving is post-blessing and durable. The predicate needs an outbound-reconciler join.

MAJOR — The authority-dependent recovery branches remain non-executable. When text is unavailable, encrypted `active.json` is origin-node-only (`plan.md:4551-4567`), yet the election-aware procedure may choose another authority and then demands the unavailable intended text there (`plan.md:4577-4585,4591-4604`). The origin secondary cannot stage or commit because mutations are rejected read-only (`pkg/configstore/store.go:346-353`; `pkg/configstore/store_lock.go:9-27`). Likewise, ConfigSync-disabled reactivation demands successful commits on both nodes (`plan.md:4712-4724`), although only the RG0 primary is writable and promotion is what clears the gate (`pkg/daemon/daemon_ha.go:438-475`). Neither branch supplies the required authority-transfer/stop-promote choreography; digest failure detects the dead end but does not recover it.

MINOR — Formal §9 says only “NO dataplane apply failure” and that the fields are rendered (`plan.md:7010-7021`), unlike the runbook’s executable `failure-count == 0 AND last-outcome-success` requirement (`plan.md:4691-4705`). The formal copy can therefore omit the last-outcome gate that is essential for detecting an in-flight first apply.

Structure confirmation: STANDS — §4.7 retains PR-1 as A1/core and keeps G+H+H2 together in the follow-up (`plan.md:5543-5578`).

NEEDS-REVISION

Codex session ID: 019fbc48-848e-7740-87f9-edeeada9f36b
Resume in Codex: codex resume 019fbc48-848e-7740-87f9-edeeada9f36b
