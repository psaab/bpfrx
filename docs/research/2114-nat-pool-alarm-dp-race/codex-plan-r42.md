# Codex hostile plan-review — round 42 (plan v42 @ 2e0b4df03)

Task: task-ms9u3gm6-lf8y0m (session 019fbb72-5e76-7950-b4d9-a581580a49ae).
Verdict: NEEDS-REVISION (3 MAJOR, 2 MINOR; fold verification 2 FOLDED / 3 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — The receipt-to-post-return atomic closes the three original false-idle windows for normally queued applies (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:3673-3686`; `pkg/cluster/sync_conn_config.go:325-395`); malformed/auth-failed frames are rejected before dispatch and config decoding is total (`pkg/cluster/sync_conn_read.go:55-93`; `pkg/cluster/sync_protocol.go:704-712`). Exact retirement and node-lifetime ownership remain unsolved below.
2. NOT-FOLDED — The plan acknowledges local→peer work can start between peer preflight and stop (`plan.md:3662-3668`) but retains exactly that point-check sequence (`plan.md:3687-3705`). Async reconcile can directly push after the check (`pkg/daemon/daemon_ha_sync.go:417-522`; `pkg/cluster/sync_conn_config.go:234-250`), producing unbounded peer-side persistence loss. Local-first restart ordering itself remains correct (`plan.md:3716-3720`; `pkg/daemon/daemon_run.go:157-177,393-398`).
3. FOLDED — Typed persistence state and `/health` rendering ship in the same G+H+H2 unit (`plan.md:4190-4213,4549-4563,5430-5453`), and cluster status gains counter, debt-mask, and active-persist wiring (`plan.md:4626-4638`). Today `/health` already exposes `config_persist_degraded` (`pkg/api/health.go:65-71`); peer status is read while running, and only the local counter is needed after peer stop.
4. PARTIAL — The normative and formal sequences now use peer preflight → peer stop → uncapped local drain → full re-check (`plan.md:3687-3716,5657-5684`); old capped-pass language survives only in revision history (`plan.md:1350-1353,1462-1479`). The formal copy, however, names the wrong read surface for the counter.
5. PARTIAL — Live single-atomic sampling and §5.1 implementation inventory are present (`plan.md:3673-3686,4626-4638`), but the sole JOIN-COHERENCE scenario (`plan.md:5716-5722`) directly exercises only dequeue/applySem blocking, not gen-0, concurrent `resetRecvGen`, shutdown, or provider replacement.

New findings:

MAJOR — Counter retirement is not total. V42 increments before the nonblocking enqueue but decrements only after an apply returns (`plan.md:3675-3681`). Queue-full and nil-channel dispositions never apply (`pkg/cluster/sync_conn_read.go:321-331`); stale-generation and nil-handler dispositions skip the callback (`pkg/cluster/sync_conn_config.go:330-342`); cancellation can abandon buffered items (`pkg/cluster/sync_conn_config.go:325-330`; `pkg/cluster/sync_conn.go:349-385`). Each leaks a positive token forever, making mandatory drain step 2c unavailable. Every received token needs exactly one retirement owner, including drops, shutdown, and callback unwind.

MAJOR — The plan does not pin node-lifetime counter ownership or ingress quiescence, leaving fourth false-idle windows. Current status reads a replaceable `SessionSync` provider (`pkg/cluster/sync_state.go:47-63`; `pkg/daemon/daemon_ha_sync.go:906-913`); a received transport-changing config can replace that session before its callback returns (`pkg/daemon/daemon_apply_tail.go:238-255`), with teardown capped at five seconds (`pkg/daemon/daemon_ha_sync.go:1405-1415`; `pkg/cluster/sync_conn.go:349-385`). A fresh provider can therefore report zero while the old apply remains active. Additionally, bytes sent before peer stop are invisible until full-frame dispatch (`pkg/cluster/sync_conn_read.go:28-93,298-324`). Pin the atomic in node-lifetime state across all communication epochs and require observed local EOF/disconnection before draining.

MAJOR — Peer preflight is still a TOCTOU, not an enforceable producer fence. After a clean peer read, local reconnect/promotion/reconcile can initiate `QueueConfig` (`pkg/daemon/daemon_ha_sync.go:417-522`; `pkg/cluster/sync_conn_config.go:234-250`); the peer can promote the sync then fail `writeActive`, raising `ActivePersistDegraded` (`pkg/configstore/store.go:687-746`), after which peer stop abandons its retry (`pkg/configstore/store_persist.go:397-401`). The admitted residual covers a deadline and D-kind debt only (`plan.md:3721-3727`), not this peer-side active-persist loss.

MINOR — Formal acceptance says all peer fields, including `ConfigSyncOutstanding`, come from `/health` (`plan.md:5660-5664`), but x14 adds no counter there (`plan.md:4190-4213,5430-5453`); the counter exists only on cluster status (`plan.md:4626-4638`). Name cluster status or add explicit API wiring and tests.

MINOR — The claimed three-window regression is underspecified. `plan.md:5716-5722` neither sends a legacy gen-0 payload nor invokes concurrent `resetRecvGen` (`pkg/cluster/sync_conn_read.go:183-195`; `pkg/cluster/sync_conn_gen.go:340-362`). Require those events explicitly.

Structure confirmation: §4.7 stands—PR-1 remains the accessor core, with G+H+H2 together in the follow-up (`plan.md:4528-4571`).

NEEDS-REVISION

Codex session ID: 019fbb72-5e76-7950-b4d9-a581580a49ae
Resume in Codex: codex resume 019fbb72-5e76-7950-b4d9-a581580a49ae
