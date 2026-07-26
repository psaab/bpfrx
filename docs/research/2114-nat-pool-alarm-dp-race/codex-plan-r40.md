# Codex hostile plan-review — round 40 (plan v40 @ 6cabbbe0a)

Task: task-ms25q9ot-5qc5bg (session 019f9fc7-6365-7632-b3f0-01e94d5a2942).
Verdict: NEEDS-REVISION (2 MAJOR, 1 MINOR; fold verification 3 FOLDED / 3 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — The re-check now uses the correct full predicate (`plan.md:3569-3575`; `pkg/configstore/store.go:687-717,738-746`), but its claimed queue drain is false: receiving only enqueues (`pkg/cluster/sync_conn_read.go:298-324`), the consumer can block indefinitely on `applySem` (`pkg/cluster/sync_conn_config.go:325-351`; `pkg/daemon/daemon_apply_commit.go:326-335`), and the capped persistence pass is unrelated (`pkg/configstore/store_persist.go:389-465`).

2. PARTIAL — The symmetric peer preflight and local-first restart ordering are present (`plan.md:3551-3580`; `pkg/daemon/daemon_run.go:157-177,393-398`). The peer-unsent case is benign because `QueueConfig` writes directly rather than maintaining an outbound queue (`pkg/cluster/sync_conn_config.go:230-250`), with reconnect re-drive at `pkg/daemon/daemon_ha_sync.go:926-956`; however, the peer itself can become dirty after its point preflight, as detailed in M2.

3. PARTIAL — Both operative copies reject `down em0` (`plan.md:3540-3545,5507-5510`), correctly matching fabric fallback and dual transport (`pkg/daemon/daemon_ha_sync.go:774-785,820-860`). The requested literal no-copy sweep is incomplete: the retained v39 history still offers “downs the cluster control link em0” (`plan.md:1427-1429`).

4. FOLDED — LIVE records may be repaired pending-shaped, while DEAD/D-target records are removed and never repaired pending-shaped (`plan.md:3474-3483,3597-3618`). Current validation requires an object, nonzero deadline, and non-null rollback tree before any proposed `Resolved` branch (`pkg/configstore/db.go:254-281`); the old reader’s ordinary `json.Unmarshal` ignores additive fields (`pkg/configstore/db.go:262-264`).

5. FOLDED — Offline removal now requires `rm` followed by `sync -f` on `.configdb/` (`plan.md:3609-3616,5534-5539`), matching `DeleteConfirm`’s unlink-plus-directory-fsync durability contract (`pkg/configstore/db.go:284-315`; `pkg/fsatomic/fsatomic.go:178-193`).

6. FOLDED — The expired branch forbids a bare probe, requires staging before committing, and explicitly overrides clustered FirstCommit recovery with boot import/offline seeding (`plan.md:3630-3659,5524-5533`). This matches candidate reset on expiry (`pkg/configstore/store_persist.go:210-213`), the confirm-only error (`pkg/configstore/store_commit.go:729-746`), live clustered rejection (`pkg/daemon/cluster_topology_preflight.go:84-97`), and boot import (`pkg/daemon/daemon_apply_commit.go:14-61`).

New findings:

MAJOR M1 — The “one capped pass” is not a queue/in-flight barrier. Config frames enter a private 64-slot channel (`pkg/cluster/sync.go:847-857`; `pkg/cluster/sync_conn_read.go:298-324`); the independent consumer invokes `syncAndApply(context.Background())` (`pkg/cluster/sync_conn_config.go:325-351`; `pkg/daemon/daemon_ha_sync.go:571-580`), which can wait without a deadline on `applySem` (`pkg/daemon/daemon_apply_commit.go:326-335`). Nothing orders that consumer against the persistence loop (`pkg/configstore/store_persist.go:389-465`). Consequently, a pre-stop frame can begin after the clean snapshot at `plan.md:3569-3575`, promote/cancel/fail persistence (`pkg/configstore/store.go:687-717,738-746`), and have its new debt abandoned at shutdown. An observable queue-plus-in-flight join is required.

MAJOR M2 — The peer preflight has its own reverse-direction TOCTOU. When the target is RG0 authority, reconnect, promotion, or the periodic reconciler can push the current configuration without any operator commit (`pkg/daemon/daemon_ha_sync.go:417-430,500-522`). Between peer check and peer stop (`plan.md:3551-3556`), that push can enqueue/apply on the peer (`pkg/cluster/sync_conn_read.go:298-324`) and raise peer `persistDegraded` on write failure (`pkg/configstore/store.go:687-717,738-746`); process exit then abandons the retry (`pkg/configstore/store_persist.go:397-401`). Eventual restart reconciliation is insufficient because degraded health is election-neutral and crash takeover remains ungated (`plan.md:3733-3745`). The peer also needs a post-ingress-fence drain and full-state re-check.

MINOR m1 — The r40 open-questions section still instructs reviewers to return a verdict on the “v29 design” (`plan.md:6013-6017`), leaving the stated review baseline stale.

Structure confirmation: CONFIRMED — PR-1 remains the synchronized-accessor core and the follow-up remains G+H+H2 (`plan.md:4385-4428`); `origin/master...6cabbbe0a` changes only research documentation, with no production implementation.

NEEDS-REVISION

Codex session ID: 019f9fc7-6365-7632-b3f0-01e94d5a2942
Resume in Codex: codex resume 019f9fc7-6365-7632-b3f0-01e94d5a2942
