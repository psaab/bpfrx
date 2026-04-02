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
