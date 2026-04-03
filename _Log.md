# Action Log

## 2026-04-01

- **Timestamp**: 2026-04-01T05:30:00Z
  - **Action**: Merged PR #301 (userspace forwarding and failover gap audit doc)
  - **File(s)**: docs/userspace-forwarding-and-failover-gap-audit.md

- **Timestamp**: 2026-04-01T06:00:00Z
  - **Action**: Implemented strict userspace mode, HA install fence, deterministic reverse companions (PR #313, issues #302-#312)
  - **File(s)**: pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/protocol.go, pkg/cluster/cluster.go, pkg/cluster/sync.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/main.rs, userspace-xdp/src/lib.rs, docs/ha-forwarding-state-inventory.md, docs/bugs.md, docs/phases.md

- **Timestamp**: 2026-04-01T06:30:00Z
  - **Action**: Address PR #313 copilot review findings — rename STRICT_PASS_BLOCKED, strict ctrl=0 drop, mode reporting, fallback names, VLAN sub-interface exclusion
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-xdp/src/lib.rs, docs/phases.md

- **Timestamp**: 2026-04-01T13:52:00Z
  - **Action**: Fix HA session sync starvation — async bulk ack, HA sync throttle 5s, 6 retries (ba1c4304)
  - **File(s)**: pkg/cluster/sync.go, pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go

- **Timestamp**: 2026-04-01T14:44:00Z
  - **Action**: Replace bulk-sync gate with barrier check for failover readiness (e42c882e)
  - **File(s)**: pkg/daemon/daemon.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-01T15:39:00Z
  - **Action**: Explicit refresh_owner_rgs on RG activation + async barrier ack (a9e0501e)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/main.rs, pkg/cluster/sync.go

- **Timestamp**: 2026-04-01T15:59:00Z
  - **Action**: Re-resolve synced sessions with owner_rg_id=0 on active node (7417144e)
  - **File(s)**: userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T16:10:00Z
  - **Action**: Add logging rules to CLAUDE.md, remove debug eprintln (12478964)
  - **File(s)**: CLAUDE.md, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T16:59:00Z
  - **Action**: Mirror reverse sessions to helper, worker-completion ack, logging rules (#314, #315, #316) (24166737)
  - **File(s)**: CLAUDE.md, pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T17:00:00Z
  - **Action**: Route barrier/bulk acks through sendCh instead of direct writeMu (9d2814c4)
  - **File(s)**: pkg/cluster/sync.go

- **Timestamp**: 2026-04-01T19:32:00Z
  - **Action**: Fix RefreshOwnerRGs skipped synced sessions — refresh_for_ha_activation (71b80b3d). THE key SNAT fix.
  - **File(s)**: userspace-dp/src/session.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T20:20:00Z
  - **Action**: Simplify HA failover — epoch flow cache, resolve-on-receipt, owner_rg_id, demotion (#325, #326, #327, #330) (a21018f3)
  - **File(s)**: pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T21:52:00Z
  - **Action**: Write userspace sessions to BPF conntrack map for zone/interface display (fab9230c)
  - **File(s)**: pkg/dataplane/dataplane.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/protocol.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/main.rs

- **Timestamp**: 2026-04-01T22:00:00Z
  - **Action**: Use BPF_ANY for conntrack map writes (244912f8)
  - **File(s)**: userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T22:30:00Z
  - **Action**: Userspace/eBPF audit — counters, conntrack flush bugs, session visibility (PR #336, issues #332-#335)
  - **File(s)**: pkg/conntrack/gc.go, pkg/daemon/daemon.go, pkg/dataplane/dataplane.go, pkg/dataplane/dpdk/dpdk_cgo.go, pkg/dataplane/dpdk/dpdk_stub.go, pkg/dataplane/maps.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T23:00:00Z
  - **Action**: Address PR #336 copilot review — idle time, BPF_EXIST, counter race, safeDelta, RX counter, flush cutoff (d15d5629)
  - **File(s)**: pkg/dataplane/loader.go, pkg/dataplane/maps.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T23:15:00Z
  - **Action**: Thread conntrack FDs through DeleteSynced for BPF cleanup (671e5561)
  - **File(s)**: userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T23:30:00Z
  - **Action**: Unify synced flag + adaptive event-first session sync (#328, #320) (dcc59c67)
  - **File(s)**: pkg/daemon/daemon.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs, userspace-dp/src/afxdp/forwarding.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/tunnel.rs, userspace-dp/src/event_stream.rs, userspace-dp/src/main.rs, userspace-dp/src/session.rs

## 2026-04-02

- **Timestamp**: 2026-04-02T18:05:00Z
  - **Action**: Start `#400` — separate transfer readiness from takeover readiness in cluster status and explicit peer-failover admission, with daemon wiring for session-sync transfer-readiness reasons
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/daemon/daemon_ha.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-02T17:20:00Z
  - **Action**: Start `#398` fix — add explicit session-sync transfer-readiness snapshot and fast-fail manual failover demotion when bulk receive or pending bulk ack proves the sync path is not settled; filed `#400` for exposing transfer readiness separately from takeover readiness
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_bulk.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-02T16:45:00Z
  - **Action**: Validate `#397` on `loss-userspace-cluster` — settled RG0 manual failover now completes on explicit failover ack + commit ack instead of heartbeat observation; filed residual issue `#398` for failover admission while requester is still in bulk receive
  - **File(s)**: testing-docs/manual-failover-transfer-commit-validation.md, testing-docs/README.md

- **Timestamp**: 2026-04-02T13:15:00Z
  - **Action**: Second #390 slice — add explicit sync-channel failover ack handshake so manual RG transfer returns applied/rejected instead of inferring success from send-only behavior
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/cluster/cluster.go, pkg/daemon/daemon_ha.go, pkg/cli/cli.go

- **Timestamp**: 2026-04-02T13:45:00Z
  - **Action**: Third #390 slice — wait for actual local RG promotion after peer transfer-out ack so CLI/local control returns on observed ownership, not just request delivery
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/cli/cli.go

- **Timestamp**: 2026-04-02T14:15:00Z
  - **Action**: Address PR #396 copilot review — typed remote-failover rejection, failover request IDs, out-of-range RG guard, timeout race guard, active-conn ack routing, and consistent gRPC wording
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/grpcapi/server.go

- **Timestamp**: 2026-04-02T16:30:00Z
  - **Action**: Next #390 slice — replace heartbeat-observed manual failover completion with explicit sync-channel transfer commit, local primary commit, peer transfer-out finalization, and commit-ack coverage
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/cli/cli.go, pkg/grpcapi/server.go

- **Timestamp**: 2026-04-02T17:05:00Z
  - **Action**: Address PR #397 Copilot review — preserve in-flight peer transfer-out state across heartbeat refreshes until transfer commit completes or aborts
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go

- **Timestamp**: 2026-04-02T12:30:00Z
  - **Action**: First #390 slice — replace weight-zero manual failover with explicit secondary-hold transfer-out state, keep ForceSecondary on zero-weight drain semantics, and teach election to promote on peer transfer-out without mutating monitor weight
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/election.go, pkg/cluster/cluster_test.go, pkg/cluster/election_test.go, pkg/cluster/sync.go

- **Timestamp**: 2026-04-02T01:30:00Z
  - **Action**: Merged PR #337 (HA simple failover design doc). Fixed copilot review — issue reference swap in phases 3/5/6.
  - **File(s)**: docs/ha-simple-failover-design.md

- **Timestamp**: 2026-04-02T02:00:00Z
  - **Action**: Fix HA activation cleanup — deduplicate refresh, skip resolved, log mirror errors (#341, #342, #345, #346) (31b600d5)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-02T02:30:00Z
  - **Action**: Fix watchdog threshold (2→10s), reverse companion leak on delete, remove debug eprintln (#349, #351, #352) (52254b7e)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/main.rs

- **Timestamp**: 2026-04-02T03:30:00Z
  - **Action**: Simplify HA — remove refresh RPC, skip blackhole routes, dead code cleanup, throttle post-transition sync (#353, #354, #355, #356) (5ac423a3)
  - **File(s)**: pkg/dataplane/userspace/manager.go, pkg/daemon/daemon.go

- **Timestamp**: 2026-04-02T06:00:00Z
  - **Action**: Merged PR #357 (flow cache simplification refactors). Implemented phases 3+4 from docs/flow-cache-simplification.md — explicit is_cacheable() + 10 unit tests (624a1f83)
  - **File(s)**: userspace-dp/src/afxdp/types.rs, docs/flow-cache-simplification.md

- **Timestamp**: 2026-04-02T11:45:00Z
  - **Action**: Added HA failover implementation plan tying current simplification audit to executable phases and issue dependencies (49eaf9d6)
  - **File(s)**: docs/ha-failover-implementation-plan.md, docs/ha-failover-simplification-audit.md

- **Timestamp**: 2026-04-03T00:16:04Z
  - **Action**: First #389 slice — add derived owner-RG indexes for helper shared session stores and use them for demotion-time BPF cleanup and shared-session demotion without whole-table scans
  - **File(s)**: userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/forwarding.rs, userspace-dp/src/afxdp/tunnel.rs

- **Timestamp**: 2026-04-03T00:34:06Z
  - **Action**: Address PR #404 Copilot review — make owner-RG index updates heal missing same-owner entries and serialize demotion-time key collection against in-flight shared-session publishes
  - **File(s)**: userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/session_glue.rs
