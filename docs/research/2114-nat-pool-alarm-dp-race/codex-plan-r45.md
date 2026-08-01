# Codex hostile plan-review — round 45 (plan v45 @ e10902e5c)

Task: task-ms9wsaqj-xhgruk (session 019fbbb7-4bad-7d41-9fac-4b302bfc863b).
Verdict: NEEDS-REVISION (5 MAJOR, 4 MINOR; fold verification 1 FOLDED / 6 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — The dead-session drop is specified at docs/research/2114-nat-pool-alarm-dp-race/plan.md:3918-3928, but the liveness check, reservation, and enqueue are not serialized against Stop’s publication and one-shot drain at plan.md:3914-3927; the actual enqueue is separate at pkg/cluster/sync_conn_read.go:321-324. A reader can observe LIVE, pause, let Stop mark dead and drain empty, then reserve/enqueue an unretirable token.
2. PARTIAL — The instantaneous-join claim is withdrawn and replaced with the composition at plan.md:3929-3944, with post-(3) local ingress admitted at plan.md:4113-4124. However, a dispatch can complete and retire before step (3), so the counter can read zero again; moreover, “true join with no false-idle window” survives at plan.md:3945-3968 and “gap-free” survives at plan.md:6127-6135.
3. PARTIAL — The disabled-sync divergence is correctly identified and the intended digest would detect unequal configurations at plan.md:4062-4073. The prescribed recovery at plan.md:4074-4077 is not executable as pinned: the intended holder may be read-only (pkg/configstore/store.go:346-352; pkg/configstore/store_commit.go:135-140), while every production push still requires either RG0 authority or locally enabled sync (pkg/daemon/daemon_ha_sync.go:336-370,445-465).
4. FOLDED — The runbook now requires a successful configdb parent-directory sync on both nodes before either restart at plan.md:4078-4088 and plan.md:6188-6191, matching the actual post-rename parent-directory barrier at pkg/fsatomic/fsatomic.go:354-366.
5. FOLDED — The planned aggregate explicitly ORs ActivePersistDegraded, every confirm-debt kind, non-OK ConfirmRecordState, and ConfigWriteUnverified at plan.md:5159-5176; the key-class fields are derived cause metadata, not independent debt. This subsumes all x14 persistence fields previously named.
6. PARTIAL — The canonical algorithm is pinned for addition at plan.md:2381-2397, and the off-node requirement appears at plan.md:4097-4102, but no capture/read/compare command or API is planned; indeed pkg/grpcapi and pkg/cli are declared untouched at plan.md:5205. Existing comparison surfaces redact secrets at pkg/grpcapi/server_config.go:347-368 and pkg/api/config.go:304-320.
7. PARTIAL — The migration rule is sound, but the claimed inventory at plan.md:5061-5068 names only five sends. It omits direct injections at pkg/cluster/sync_config_gen_test.go:293,322,340,357; pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:163,198; and pkg/cluster/sync_config_health_6387_test.go:152,207,253,281,330,338.

New findings:

MAJOR — The session-dead gate has the same leak under a narrower interleaving. Plan.md:3900-3903 places reservation before enqueue, while plan.md:3914-3927 gives Stop a one-shot drain after publishing dead. Nothing makes observe-LIVE → reserve → enqueue atomic with dead-publication → drain. Since pkg/cluster/sync_conn_read.go:321-324 uses a nonblocking send and Stop can return after its capped wait at pkg/cluster/sync_conn.go:349-385, a paused live-observing reader can enqueue after the drain. The §9 test at plan.md:6251-6255 starts dispatch only after teardown and cannot expose this race; a seam after the live observation/reservation is required.

MAJOR — The replacement composition treats a level counter as a sticky event witness. Plan.md:3941-3943 asserts every pre-(3) dispatch is caught, but pkg/cluster/sync_conn_config.go:325-396 permits the item to enqueue, apply, and retire entirely before the operator reads step (3). A successful SyncApply can promote and persist cleanly at pkg/configstore/store.go:687-755, restoring both counter and debt fields to zero. That interval is neither caught nor admitted by residual (iii), and JOIN-COHERENCE at plan.md:6216-6255 has no pulse-between-reads leg. A sticky dispatch epoch/digest or an explicit admitted-and-closed residual is needed.

MAJOR — The peer preflight still relies on the withdrawn instantaneous join. It point-reads peer zero once at plan.md:3974-3985 and never re-reads peer state. A frame already complete can be paused before dispatch at pkg/cluster/sync_conn_read.go:84-93 or held as pendingFrame at pkg/cluster/sync_auth.go:352-369, then dispatch after preflight. Normative residual (iii) covers only pushes “initiated BETWEEN” checks at plan.md:4030-4034, excluding that frame, while the acceptance copy switches to “landing” at plan.md:6169-6174. The normative runbook and acceptance contract therefore disagree.

MAJOR — The done predicate can accept an active-but-unapplied configuration. SyncApply promotes before dataplane application (pkg/configstore/store.go:687-769), and a nonfatal apply failure deliberately leaves ActiveApplied false (pkg/configstore/store.go:797-809; pkg/daemon/daemon_apply_commit.go:464-494). Both active digests and every persistence field can nevertheless pass plan.md:4089-4113 and plan.md:6192-6205. The separate config-apply health alarm is delayed and diagnostic-only (pkg/cluster/sync_conn_config.go:369-379). Completion must also require ActiveApplied, or an equivalent applied-digest/config-sync-health predicate, on both nodes.

MAJOR — Disabled-sync recovery is not operationally closed. Plan.md:4074-4077 offers “re-commit / manual sync from the node holding the intended config,” but no operator-callable manual-sync path exists: syncConfigToPeer enforces authority and pushConfigToPeer enforces ConfigSync at pkg/daemon/daemon_ha_sync.go:336-370. The intended holder can be the read-only secondary, while the only off-node artifact required by the plan is a digest, which cannot reconstruct secrets or configuration text. Pin capture of the complete intended artifact and an authority-side staging/commit procedure, or add a real manual transfer mechanism.

MINOR — The withdrawal remains internally contradictory: plan.md:3945-3968 calls zero a “true join with no false-idle window,” plan.md:5023-5025 and plan.md:6127-6135 call it gap-free, and plan.md:3989-4009 calls IsSyncConnected a terminal exit for readers the same paragraph says are unregistered. These claims should be replaced with the exact bounded composition.

MINOR — Plan.md:4119-4121 says a post-(3) persist failure is reclassified at boot, but plan.md:4047-4053 correctly explains that a post-rename directory-sync failure is not reconstructed. The directory barrier and intended-digest check—not boot classification—are the closure.

MINOR — The off-node canonical comparison remains a requirement without an executable surface. The only planned canonicalConfigHash use is internal persistence binding at plan.md:5087, while plan.md:5205 excludes CLI/gRPC work. The runbook must name how the operator captures the pre-fence digest and obtains comparable unredacted post-restart digests from both nodes.

MINOR — Twelve direct-injection test sends remain absent from the §5.1 inventory, despite the proposed unconditional dequeue retirement. The omitted locations are pkg/cluster/sync_config_gen_test.go:293,322,340,357; pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:163,198; and pkg/cluster/sync_config_health_6387_test.go:152,207,253,281,330,338.

Structure confirmation: §4.7 stands—PR-1 remains the A1 accessor core, with G+H+H2 together in the follow-up at plan.md:4925-4960.

NEEDS-REVISION

Codex session ID: 019fbbb7-4bad-7d41-9fac-4b302bfc863b
Resume in Codex: codex resume 019fbbb7-4bad-7d41-9fac-4b302bfc863b
