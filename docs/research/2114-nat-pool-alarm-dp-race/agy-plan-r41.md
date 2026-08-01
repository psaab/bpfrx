# AGY adversarial plan-review — round 41 (plan v41 @ 4a331d5a6)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes); first dispatch returned an empty body, retried with the same prompt (the retry prompt is identical in substance). Verdict: PLAN-READY (3/3 folds FOLDED; 2 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED: Observable join exposed read-only from `pkg/cluster/sync.go:594-616` (`applyingConfigGen` atomic + `configApplyCh` len); `pkg/cluster/sync_conn_config.go:325-351` (`configApplyLoop`) calling `pkg/daemon/daemon_apply_commit.go:326-335` (`syncAndApply`) blocks on `applySem.Acquire`, which leaves `applyingConfigGen` non-zero and queue items non-empty, exposed directly to local drain step 2a (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1525-1541,3598-3605`).
2. FOLDED: Local drain 2a ensures `pkg/daemon/daemon_ha_sync.go:417-430,500-522` reconciler pushes complete before step 2c peer stop; `pkg/configstore/store.go:687-717,738-746` (`SyncApply`) synchronously raises debts under `s.mu` upon `writeActive` failure, visible on peer status RPC before peer stop (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1537-1541,3609-3614`).
3. FOLDED: §11 baseline updated (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:5692`); retained v39 `down em0` entry annotated WITHDRAWN (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1428,1550-1553`), consistent with fabric fallback logic in `pkg/daemon/daemon_ha_sync.go:774-785,820-860`.

(B) Fresh attacks:
- Indicator Freshness: Hypothesis that status RPC reads cached snapshot subject to staleness. FAILED. `pkg/cluster/sync.go:606` `applyingConfigGen` (`atomic.Uint64`) and `configApplyCh` (`chan configApplyItem`) allow live atomic load and channel length reads upon status query execution; pinned live in `docs/research/2114-nat-pool-alarm-dp-race/plan.md:3599-3604`.
- Peer Preflight Ordering: Hypothesis that peer status RPC availability conflicts with peer stop. FAILED. Step 2b (PEER-SIDE PREFLIGHT) strictly precedes step 2c (STOP THE PEER) in `docs/research/2114-nat-pool-alarm-dp-race/plan.md:3609-3616`; peer gRPC service is fully running during step 2b preflight.

(C) Structure confirmation:
The §4.7 2-of-3 majority delivery structure (PR-1 core deliverable + G+H+H2 follow-up unit) stands (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:4437-4480`), with the r28 AGY (A) CONVERGE dissent noted.

PLAN-READY
