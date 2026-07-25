VERDICT: PLAN NO

### Q1 (resync obligation): UNSOUND
- **Trace & Mechanism Analysis**:
  - In [sync_conn.go:L130-194](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go#L130-L194) and [sync_bulk.go:L40-90](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go#L40-L90), `doBulkSync()` is driven exclusively by the sender (on connection setup `handleNewConnection` or during `syncSweep`).
  - When receiver Node B's park buffer overflows while fabric 1 (`fab1`) remains active and connected, Node B drops the park buffer and sets its local obligation flag.
  - The plan ([plan.md:L1141-1144](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1141-L1144)) asserts that "no new wire message" is sent and that the obligation "drives the EXISTING BulkSync machinery over the SURVIVING active connection".
  - However, sender Node A receives no message or signal from Node B indicating that an overflow occurred on Node B. Node A continues streaming session deltas over `fab1` without calling `doBulkSync()`. A receiver cannot force sender-side bulk drive over an established surviving connection without either transmitting a resync request wire frame or tearing down `fab1`.
  - **Clear-on-ACK Race**: In [sync_bulk.go:L66-90](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go#L66-L90) and [plan.md:L1148-1151](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1148-L1151), clearing the obligation on `BulkAck` receipt lacks sequence/epoch matching to the specific overflow event. If a second overflow occurs on Node B while a replacement bulk (or pre-overflow bulk) is in transit, the arrival of that earlier bulk's `BulkAck` prematurely clears `forceResync` / obligation before a post-overflow bulk is complete.

---

### Q2 (group-hold): SOUND
- **Trace & Mechanism Analysis**:
  - **Early Replica Reap**: When worker W0 reaps its entry while worker W1 forwards, W0 drops its `Arc<GroupHold>` clone. W1 and the canonical entry ([plan.md:L1273-1299](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1273-L1299)) retain their respective clones. The `Arc` strong count remains greater than 0, preventing `GroupHold::drop` from releasing the `PortAllocator` reservation.
  - **Locally-Born vs Imported Coexistence**: Locally-born flows release via per-entry token `Drop` calling allocator release directly (#6522). Imported flows release via `Arc<GroupHold>::drop` when the final clone drops, calling allocator release exactly once. Both share `PortAllocator` without refcount double-release.
  - **Post-Reap Materialization**: `materialize_shared_session_hit` ([session_glue/mod.rs:L1092-1122](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1092-L1122)) looks up the canonical entry in `shared_sessions`. If the canonical entry has already reaped, the lookup yields `None`, preventing materialization against a non-existent entry. If live, it clones the canonical entry's `Arc<GroupHold>`.
  - **Escrow Keeper Clone**: The escrow keeper holds an `Arc<GroupHold>` clone during quiescence/teardown ([plan.md:L920-925](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L920-L925)), maintaining strong count $\ge 1$. Replayed entries receive clones during bring-up before the escrow keeper clone drops, preserving keeper semantics.

---

### Q3 (lock-order + publish path): SOUND
- **Trace & Mechanism Analysis**:
  - The coordinator reserve-with-receipt completes and unlocks `PortAllocator` before calling `publish_shared_session` ([session_import.rs:L115-118](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs#L115-L118)).
  - `publish_shared_session` acquires canonical shared map mutexes (`synced`, `nat`, `forward_wire`, `owner_rg_indexes`) without accessing `PortAllocator`.
  - Per-worker fan-out `reserve_synced_source_nat_allocation` ([upsert_synced.rs:L80-96](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L80-L96)) under v9.9.20 receives the pre-committed `Arc<GroupHold>` clone and no longer mutates `PortAllocator` or acquires its lock.
  - No code path in the publish/fan-out sequence re-enters `PortAllocator` while holding canonical locks. Lock hierarchy remains strict ([plan.md:L1300-1308](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1300-L1308)).

---

### Q4 (composition sweep): UNSOUND
- **Trace & Mechanism Analysis**:
  - While pairwise interactions between escrow/group-hold, token-RAII/`slot.with_current()`, and park-buffer/`BulkStart` markers are internally coherent, the overall composition depends on obligation-repair to heal park-buffer overflow drops on dual-fabric connections.
  - Because receiver-side obligation repair cannot trigger a sender-side `doBulkSync()` over a surviving fabric without wire frames or socket closure, and because `BulkAck` discharge races against secondary park overflows, the composed system fails to guarantee table resync during config-apply lag.

---

### NEW TRACES OPENED BY v9.9.20 FOLDS

1. **Silent Standby Desynchronization on Surviving Fabric Overflow**
   - **Files**: [sync_conn.go:L130-194](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go#L130-L194), [sync_bulk.go:L40-90](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go#L40-L90), [plan.md:L1130-1151](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1130-L1151)
   - **Trace**:
     1. Receiver Node B encounters park buffer overflow on `fab0` while `fab1` remains active and healthy.
     2. Node B discards its park buffer and sets its local `obligation` flag.
     3. Following the v9.9.20 clause ("no new wire message"), Node B sends no notification to Node A.
     4. Sender Node A only triggers `doBulkSync()` on socket connection setup or periodic sweep (`sync_conn.go:L139-194`). It continues streaming incremental deltas on `fab1`.
     5. Node A never initiates `doBulkSync()`. Dropped session deltas are never resynced to Node B, leaving the standby silently out-of-sync until a complete dual-fabric disconnect occurs.

2. **Premature Obligation Discharge via Unsequenced Pre-Overflow or In-Flight ACK**
   - **Files**: [sync_bulk.go:L66-90](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go#L66-L90), [sync_conn_read.go:L205-241](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go#L205-L241), [plan.md:L1148-1151](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1148-L1151)
   - **Trace**:
     1. Sender Node A initiates Bulk 1.
     2. While Bulk 1 is in-flight, Receiver Node B experiences a second park buffer overflow and sets `forceResync = true`.
     3. Node A receives the `BulkAck` for Bulk 1 and unconditionally clears `forceResync`.
     4. Because `BulkAck` lacks an explicit sequence ID tied to the second overflow event, Bulk 1's ACK prematurely clears the obligation triggered by the subsequent overflow before a full resync for the second overflow has occurred.
AGY EXIT: 0
