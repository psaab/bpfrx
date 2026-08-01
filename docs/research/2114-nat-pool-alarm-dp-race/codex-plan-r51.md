# Codex hostile plan-review — round 51 (plan v51 @ 88772f3f4)

Task: task-msa3dngg-aq47j5 (session 019fbc60-4d0c-7db0-b5e3-e64e014fb991).
Verdict: NEEDS-REVISION (4 MAJOR, 1 MINOR; fold verification 2 FOLDED / 2 PARTIAL / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — v51 places “three fields” in one snapshot (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5695-5704), but still assigns ActiveApplied canonical ownership to configstore (plan.md:5850-5859); its success stamps occur after applyConfigLocked returns (pkg/daemon/daemon_apply.go:56-70; pkg/daemon/daemon_apply_commit.go:277-286,464-475), so no unified publication order is defined.
2. PARTIAL — deferred-MAC failure and nil-dp skip are explicitly classified non-converged (plan.md:5705-5724), but userspace ApplyConfig has another nil-without-convergence exit: pending XSK startup defers snapshot publication while returning success (pkg/dataplane/userspace/manager_compile.go:230-257,289-298; pkg/dataplane/userspace/manager.go:348-357).
3. NOT-FOLDED — ConfigsSent proves only its own write completed (pkg/cluster/sync_conn_config.go:234-250), not that every older marker claimant finished; a pass can remain paused after claiming at pkg/daemon/daemon_ha_sync.go:474-489 while another epoch’s pass supplies the observed tick.
4. FOLDED — the operator-callable command is request chassis cluster failover redundancy-group 0 node <0|1> (pkg/clusterfailover/failover.go:180-204; cmd/cli/request.go:184-202; pkg/grpcapi/server_diag_system_action.go:527-554). Promotion clears read-only before reconciliation and demotion restores it (pkg/daemon/daemon_ha.go:438-475); promote/commit/restore precedes the final predicate (plan.md:7072-7184).
5. FOLDED — formal acceptance requires failure-count == 0 AND last-outcome-success (plan.md:7142-7154), then reactivation on both nodes with each commit succeeding and the COMPLETE predicate repeated (plan.md:7168-7184).

New findings:
MAJOR 1 — The snapshot has no executable single-owner contract. Store promotion changes ActiveApplied’s computed truth before applyConfigLocked begins, while successful MarkActiveApplied/MarkAppliedDigest calls occur after that central boundary (pkg/daemon/daemon_apply_commit.go:194-246,277-286,464-475; pkg/configstore/store.go:781-809,831-848). Copying ActiveApplied at the boundary can therefore remain false after success; reading configstore separately recreates the cross-source tear. The plan must name one owner and make every promotion and applied-digest stamp publish the same versioned snapshot.

MAJOR 2 — A one-load atomic snapshot can still return stale green after an overlapping failed apply. The renderer can load the pre-entry snapshot, be descheduled while a DHCP/feed apply enters and fails, then resume and return the captured green snapshot because the show path takes no applySem and performs no end-version check (pkg/daemon/daemon_dhcp.go:73-90; pkg/daemon/daemon_feeds.go:26-41; pkg/grpcapi/server_show_cluster_text.go:66-74). The h2b regression tests only apply-before-read (plan.md:7251-7254), not load→failed-apply→resume. A sequence reread/retry or serialization is required.

MAJOR 3 — “Truth at convergence” lacks a signal for pending-XSK publication. Compile records the desired snapshot and returns nil while explicitly deferring its publication (pkg/dataplane/userspace/manager_compile.go:230-257,289-298); Manager.ApplyConfig propagates that nil (pkg/dataplane/userspace/manager.go:348-357), so the daemon treats the phase as successful (pkg/daemon/daemon_apply_dataplane.go:137-163). Actual publication happens asynchronously later, and rejection is merely logged and retried (pkg/dataplane/userspace/process_status.go:118-131,183-186). The predicate can therefore bless before convergence or remain green after deferred publication fails.

MAJOR 4 — The reconciler observation does not exclude the stale-capture interleaving. Pass A can capture old text and claim epoch E, then pause before QueueConfig (pkg/daemon/daemon_ha_sync.go:440-489,497). A reconnect advances the epoch (pkg/daemon/daemon_ha_sync.go:51-57), pass B sends and supplies the observed ConfigsSent tick, and the operator commits intended text. Pass A can then resume; QueueConfig obtains the current connection and assigns a later wire generation (pkg/cluster/sync_conn_config.go:234-243), so the receiver accepts OLD last (pkg/cluster/sync_conn_config.go:254-272,325-395), while the intended marker suppresses repair (pkg/daemon/daemon_ha_sync.go:479-484). Moreover, the runbook’s “marker no-op” alternative (plan.md:4673-4678) is unobservable and produces no ConfigsSent increment because it returns before QueueConfig.

MINOR 1 — §9 has no regression for either new contract. JOIN-COHERENCE remains entirely inbound-counter testing (plan.md:7194-7243), while h2 covers only sticky failure and apply-before-read (plan.md:7244-7254). It needs the paused outbound claimant/reconnect/commit/release ordering, marker-no-op rejection, stale-snapshot return, and pending-XSK rejection legs.

Structure confirmation: §4.7 stands—PR-1 remains the A1 core, G+H+H2 remain together in the follow-up, and AGY’s dissent remains recorded (plan.md:5630-5673).

NEEDS-REVISION

Codex session ID: 019fbc60-4d0c-7db0-b5e3-e64e014fb991
Resume in Codex: codex resume 019fbc60-4d0c-7db0-b5e3-e64e014fb991
