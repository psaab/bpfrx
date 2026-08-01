# AGY adversarial plan-review — round 51 (plan v51 @ 88772f3f4)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: NEEDS-REVISION (1 MAJOR — the ConfigsSent tick-hang on a marker no-op pass, IS Codex M4's second half; folds 5 FOLDED; 1 fresh attack FAILED, 1 SUCCEEDED as the MAJOR). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

(A) Fold verification:
1. FOLDED: `pkg/daemon/daemon.go:5685-5704` (apply-health snapshot struct via `atomic.Pointer`), `pkg/configstore/store.go:803-809` (`ActiveApplied()`), `pkg/grpcapi/server_show_cluster_text.go:66-74` (show path).
2. FOLDED: `pkg/daemon/daemon_apply.go:141-355` (`applyConfigLocked`), `pkg/daemon/daemon_apply_dataplane.go:390-402,466-489` (`reapplyAfterDeferredMAC`), `pkg/daemon/daemon_run_bringup.go:493-520` (nil `d.dp` boot skip), `pkg/daemon/daemon_apply_tail.go` (tail error join).
3. FOLDED: `pkg/daemon/daemon_ha_sync.go:462-497` (`reconcileConfigSync`), `pkg/cluster/sync_conn_config.go:243-250` (`QueueConfig` and `ConfigsSent`).
4. FOLDED: `pkg/cli/cli_request_chassis.go:8-120` (`request chassis cluster failover redundancy-group 0 node <node-id>`), `pkg/daemon/daemon_ha.go:440-442` (`SetClusterReadOnly(false)`), `pkg/configstore/store.go:349-353`, `pkg/configstore/store_lock.go:24-28`.
5. FOLDED: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:4791,4799-4810,7144,7168-7180`.

(B) Fresh attacks:
- Snapshot publication attack: FAILED — `lastApplyOK` is set to `false` in the atomic snapshot at entry of `applyConfigLocked` (`pkg/daemon/daemon_apply.go:141`), so readers loading the `atomic.Pointer` during or after an apply failure observe `lastApplyOK == false` (and `applyFailureCount > 0` post-exit).
- Reconciler-join observation attack: SUCCEEDED — A marker no-op pass (`pkg/daemon/daemon_ha_sync.go:480-484`) returns early without invoking `ss.QueueConfig(configText)`. `ConfigsSent` (`pkg/cluster/sync_conn_config.go:250`) is incremented only inside `QueueConfig` on a successful socket write, so a no-op pass yields no tick.

(C) New findings:
MAJOR:
- `pkg/daemon/daemon_ha_sync.go:480-484` + `pkg/cluster/sync_conn_config.go:250`: Post-election runbook join on `ConfigsSent` tick hangs when the reconcile pass no-ops. In `reconcileConfigSync`, if `configSyncHasPushed && configSyncPushedEpoch == epoch && configSyncPushedGen == gen` holds, the pass unlocks `configSyncMu` and returns early without calling `ss.QueueConfig(configText)`. Because `ConfigsSent.Add(1)` is executed exclusively within `QueueConfig` (`sync_conn_config.go:250`), a no-op pass never increments `ConfigsSent`. An operator following v51's runbook instruction to wait for an observed `ConfigsSent` tick post-election before issuing the re-convergence commit will block indefinitely if the current epoch/generation was already pushed prior to election settlement.

MINOR:
None.

(D) Structure confirmation:
The 2-of-3 §4.7 delivery structure (PR-1 = core A1; follow-up unit = G+H+H2) stands, with my r28 (A) dissent remaining recorded.

(E) Verdict line:
NEEDS-REVISION
