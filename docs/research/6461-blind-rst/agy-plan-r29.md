**Verdict:** **PLAN YES**

### Verification Summary

1. **Authority-Issued Config Epoch (`pkg/cluster/sync_conn_config.go:222,234,389`, `pkg/daemon/daemon_apply_commit.go:245,270,274`)**:
   - Reserving the epoch at apply time (before [applyConfigLocked](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go#L245)) aligns with the publication order (local apply → session invalidation at [:270](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go#L270) → peer push at [:274](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go#L274)). The invalidation cutoff and newly admitted entries share the committed epoch, and resends reuse it without re-allocating.
   - Adopting `max(own, received)` as the counter floor on authority transition ensures strict cluster-wide monotonicity across failovers.

2. **In-Place Refresh Allocator Change Detection (`userspace-dp/src/server/handlers/snapshot.rs:163,239`, `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:212,319,397`)**:
   - [snapshot.rs:163](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/handlers/snapshot.rs#L163) (`same_plan`) and [snapshot_refresh.rs:212](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs#L212) provide natural detection points for allocator key or collision domain changes (which are omitted from the binding-plan key).
   - In-place tuple migration or forcing the quiesced `reconcile_status_bindings` path from this point is safe and leverages existing fallback/restore mechanics.

3. **Persistent Lease Object Migration (`userspace-dp/src/nat/allocator.rs:1114,1224,1654,1682,1691,1894`, `userspace-dp/src/nat/tests_pool.rs:2536`)**:
   - The data model (`persistent_by_source`, `active_flows`, `expires_at_ns`) manages persistent NAT allocations as shared lease units per `PersistentSourceKey`.
   - Transferring the lease object as a unit (key, timeout, co-holder count) avoids bit occupancy collisions ([allocator.rs:1688](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L1688)) caused by per-flow `reserve_flow` calls while maintaining correct co-holder refcounting.

4. **Install-Only Priming (`pkg/cluster/sync_bulk.go:81,105,183`, `pkg/cluster/sync_conn_read.go:240`)**:
   - [sync_conn_read.go:240](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go#L240) (`reconcileStaleSessions()`) is the single invocation point for post-bulk reconciliation upon `syncMsgBulkEnd`.
   - Gating this invocation on connection capability negotiation cleanly suppresses stale-entry deletion on unnegotiated connections, leaving legacy receivers safely to their local aging and invalidation sweeps.
