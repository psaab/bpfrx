# Codex hostile plan-review — round 44 (plan v44 @ e30ea7a3e)

Task: task-ms9vtbvj-nwpk0v (session 019fbb9e-66dd-7490-a468-2882801bfb62).
Verdict: NEEDS-REVISION (5 MAJOR, 2 MINOR; fold verification 1 FOLDED / 4 PARTIAL / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The pre-enqueue reservation and nil/full rollback close the publication-order race, and the mutually exclusive select dispositions prevent rollback plus dequeue-retirement for one token (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3835-3847; pkg/cluster/sync_conn_read.go:321-331). A queue-full object is never transferred; a later push is a fresh frame/reservation (pkg/cluster/sync_conn_config.go:226-243). Total balance nevertheless fails for enqueue after teardown drain.

2. PARTIAL — Every production config frame funnels through handleMessage: normal and pending readers enter the sole config case, then the consumer invokes handleConfigSync/SyncApply (pkg/cluster/sync_conn_read.go:90-98,298-332; pkg/cluster/sync_conn.go:119-130; pkg/cluster/sync_conn_config.go:325-395; pkg/daemon/daemon_ha_sync.go:544-578,909-913). Cold-prime uses normal outbound QueueConfig, and bulk sync carries sessions/markers, not config (pkg/daemon/daemon_ha_sync.go:926-956; pkg/cluster/sync_bulk.go:81-197). Test-only direct queue injections bypass reservation (pkg/cluster/sync_config_gen_test.go:226-237,256-267), and dispatch-time counting still is not a reader-lifetime join.

3. NOT-FOLDED — The PRE/POST-rename split and operator-intended comparison are accurate (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3948-3985), but “converges to the authority’s config” is false: the cited reconciler additionally requires the authority’s loaded config to enable ConfigSync (pkg/daemon/daemon_ha_sync.go:451-465).

4. FOLDED — The normative and acceptance copies agree on the failure-class split, authority dependence, directory sync, and comparison against the operator’s intended config rather than mere cross-node agreement (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3948-3986,6029-6049). They share the semantic defects below.

5. PARTIAL — IsConnected correctly OR-aggregates installed conn0/conn1 (pkg/cluster/sync_conn.go:244-273,480-497; pkg/cluster/sync.go:961-964), but it does not aggregate pre-install, superseded, or post-cap reader lifetimes. It therefore cannot witness every relevant terminal exit as claimed (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3897-3917,4938-4945,5978-5995).

New findings:

MAJOR — Post-teardown enqueue leaks a node-lifetime token. The plan requires Stop to drain buffered tokens while expressly allowing readers past Stop’s five-second cap (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3849-3865,4918-4925). Stop can return while producers survive (pkg/cluster/sync_conn.go:349-385), after the consumer has selected ctx.Done (pkg/cluster/sync_conn_config.go:325-330). A reader can then reserve/send into the old, still-open queue after its one-shot drain—or reserve before the drain observes empty and send afterward (pkg/cluster/sync_conn_read.go:90-93,321-323; pkg/cluster/sync.go:847-857). No consumer remains to retire it, so the mandatory zero drain can hang forever. §9 lacks this enqueue-after-teardown seam (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6076-6094).

MAJOR — Down plus zero remains a false ingress-quiescence witness. A complete legacy frame can sit pending before installation/reservation (pkg/cluster/sync_auth.go:352-369; pkg/cluster/sync_conn.go:100-130), and a normal reader can pause after verification but before handleMessage (pkg/cluster/sync_conn_read.go:84-93). Concurrent writer failure can remove the installed slot and publish Down while that reader remains runnable (pkg/cluster/sync_conn_config.go:234-248; pkg/cluster/sync_conn.go:480-497). The operator can therefore observe Down and zero before an already-received frame reserves and applies, contradicting the claimed no-false-idle all-ingress join (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3853-3876).

MAJOR — Authority-conditional convergence has a reachable disabled-sync hole. ConfigSync defaults false unless configuration-synchronize exists (pkg/config/compiler_system.go:1872-1874; pkg/config/types_chassis.go:113). A newer local config can enable it, push to the peer, and suffer a PRE-rename peer persist failure. After restart the peer loads its older ConfigSync=false config and can preempt (pkg/cluster/election.go:172-193); the newer node then fails the authority gate, while the peer fails the ConfigSync gate (pkg/daemon/daemon_ha_sync.go:451-465). Especially while the local node is still inside the 30-second stability gate, neither side pushes, so divergence can persist indefinitely. This directly contradicts plan.md:3962-3969 and acceptance plan.md:6038-6041.

MAJOR — The durability repair does not pin the filesystem containing the failed rename. Residual (iii)’s post-rename failure occurs on the peer (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3941-3955), but the runbook merely says the singular stopped “repair step” syncs “the configdb” (plan.md:3970-3974), in context of repairing the local confirm record (plan.md:3707-3739). The failed durability barrier belongs to the affected target’s parent directory (pkg/fsatomic/fsatomic.go:354-366). The peer can restart, load and mark the visible content applied, after which equality suppresses the rewrite (pkg/daemon/daemon_apply.go:49-70; pkg/daemon/daemon_ha_sync.go:550-568). The runbook must require a successful directory sync on every affected node before either restart.

MAJOR — The post-restart done predicate omits independent degradation states. It requires intended-config equality, ConfigWriteUnverified=false, and ConfirmDebtKindMask=0 (docs/research/2114-nat-pool-alarm-dp-race/plan.md:3975-3985,6043-6049), but the plan’s own state model separately includes ActivePersistDegraded and ConfirmRecordState and defines the aggregate over all of them (plan.md:4175-4192,4461-4482). A restart-time push can promote/apply the intended config while its disk write fails (pkg/configstore/store.go:687-689,738-769); both config comparisons and the named fields can pass while ConfigPersistDegraded remains true (pkg/configstore/store_persist.go:342-352). Completion must require the full derived persist-health state clean on both nodes.

MINOR — The operator-intended golden configuration lacks an executable capture/compare procedure. Current REST/gRPC show, export, and compare surfaces redact secrets (pkg/grpcapi/server_config.go:347-380; pkg/api/config.go:304-374), so a secret-only regression can compare equal. Capture an off-node canonical artifact or digest before the fence and pin the exact comparison surface.

MINOR — Existing tests enqueue unreserved configApplyItem values directly (pkg/cluster/sync_config_gen_test.go:226-237,256-267; pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:104-108). The plan must either migrate them through dispatch or give each item explicit reservation ownership so the proposed unconditional dequeue defer cannot underflow the counter.

Structure confirmation: §4.7 stands—PR-1 remains the A1 d.dp core, with G+H+H2 kept together in the follow-up (docs/research/2114-nat-pool-alarm-dp-race/plan.md:4798-4841).

NEEDS-REVISION

Codex session ID: 019fbb9e-66dd-7490-a468-2882801bfb62
Resume in Codex: codex resume 019fbb9e-66dd-7490-a468-2882801bfb62
