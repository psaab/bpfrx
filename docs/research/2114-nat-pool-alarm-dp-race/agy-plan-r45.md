# AGY adversarial plan-review — round 45 (plan v45 @ e10902e5c)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: NEEDS-REVISION (1 MAJOR — the session-dead gate check/reserve/enqueue not serialized against Stop's teardown drain, IS Codex M1 + SMR m1; folds 6 FOLDED / 1 PARTIAL; 1 further fresh attack FAILED). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. Session-liveness gate (Codex r44 M1): PARTIAL (`plan.md:3918-3928`, `plan.md:5047-5052`). The session-dead flag concept is documented, but the non-atomic check vs channel send allows a reservation taken on a live session to land in `configApplyCh` after `Stop()`'s teardown drain completes (`pkg/cluster/sync_conn.go:349-385`, `pkg/cluster/sync_conn_config.go:325-330`, `pkg/cluster/sync_conn_read.go:318-331`).
2. Instantaneous-join claim withdrawn (Codex r44 M2): FOLDED (`plan.md:1758`, `plan.md:3929-3944`, `pkg/cluster/sync_conn_read.go:84-93`, `pkg/cluster/sync_auth.go:352-369`, `pkg/cluster/sync_conn_config.go:234-248`, `pkg/cluster/sync_conn.go:480-497`).
3. Disabled-sync subclass named (Codex r44 M3): FOLDED (`plan.md:1786-1795`, `pkg/config/compiler_system.go:1872-1874`, `pkg/config/types_chassis.go:113`, `pkg/daemon/daemon_ha_sync.go:461-465`).
4. Durability sync pins every affected node (Codex r44 M4): FOLDED (`plan.md:1795-1803`, `pkg/fsatomic/fsatomic.go:354-366`, `pkg/daemon/daemon_apply.go:49-70`, `pkg/daemon/daemon_ha_sync.go:550-568`).
5. Done predicate is full aggregate (Codex r44 M5): FOLDED (`plan.md:1804-1810`, `pkg/configstore/store.go:687-689,738-769`, `pkg/configstore/store_persist.go:342-352`).
6. Off-node canonical digest capture (Codex r44 m1): FOLDED (`plan.md:1811-1816`, `pkg/grpcapi/server_config.go:347-356`, `pkg/api/config.go:304-374`).
7. Direct-injection tests migrated (Codex r44 m2): FOLDED (`plan.md:1816-1822`, `pkg/cluster/sync_config_gen_test.go:226-237,256-267`, `pkg/cluster/sync_config_epoch_sweep_race_6284_test.go:104-108`).

(B) Fresh attacks:
- Session-dead gate vs reservation taken on live session enqueued after Stop's drain: SUCCEEDED (becomes MAJOR finding C1 below).
- Peer-side preflight counter read relying on instantaneous join: FAILED (the preflight at (2a) is a conservative sanity check before stopping the peer; safety is guaranteed by post-stop local drain (2c) and state re-check (3)).

(C) New findings:
MAJOR:
- `plan.md:3918-3928`, `plan.md:5047-5052`: The session-dead gate check (`sessionDead == false`) in the dispatch path (`pkg/cluster/sync_conn_read.go:318-331`) is not synchronized or serialized with respect to `SessionSync.Stop()`'s teardown drain (`pkg/cluster/sync_conn.go:349-385`, `pkg/cluster/sync_conn_config.go:325-330`). If a reader goroutine evaluates `sessionDead` as `false` on a LIVE session, takes a reservation (`ConfigSyncOutstanding.Add(1)`), and is preempted right before `s.configApplyCh <- item`, `Stop()` can concurrently set `sessionDead = true`, cancel `ctx` (exiting `configApplyLoop`), and run its teardown drain of `s.configApplyCh`. When the preempted reader resumes execution, it enqueues `item` into `configApplyCh` after `Stop()`'s drain has already completed. With `configApplyLoop` dead and `Stop()` finished, no consumer or drainer exists to dequeue `item` or execute its retirement defer, causing `ConfigSyncOutstanding` to leak a token permanently (+1 deadlock on the quiescence fence). The check, reservation, and enqueue must be serialized against `Stop()`'s teardown drain (e.g. under `s.mu` or by closing `configApplyCh` under lock during teardown).

MINOR:
- None.

(D) Structure confirmation:
- The §4.7 delivery structure stands (two units: PR-1 with core A1 + site conversion + canaries + sampler narrowing; follow-up issue with G+H+H2; r28 (A) dissent recorded).

NEEDS-REVISION
