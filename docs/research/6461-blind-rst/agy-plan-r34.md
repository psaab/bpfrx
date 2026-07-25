VERDICT: PLAN YES

### Q1 (Epoch-park protocol): SOUND
- **Evidence**:
  - `pkg/cluster/sync_conn_gen.go:424-433`: `configEpochStale` evaluates `barrier := max(applyingConfigGen, lastAppliedConfigGen)`.
  - `pkg/cluster/sync_conn_config.go:296-310`, `:325-389`: `beginConfigApply` sets `applyingConfigGen` before `OnConfigReceived`; `endConfigApply` clears it; `lastAppliedConfigGen` advances only after `OnConfigReceived` succeeds.
  - `pkg/cluster/sync_conn.go:142-145`: `OnPeerConnected` callback runs asynchronously while `doBulkSync` proceeds.
  - `pkg/cluster/sync_conn_read.go:96-110`, `:183-200`, `:284-308`: `handleMessage` handles control frames (`syncMsgHeartbeat`/`syncMsgHeartbeatAck`/`syncMsgConfig`) alongside session state. `syncMsgBulkStart` resets `recvGen` at `:195`.
  - `pkg/cluster/readiness.go:20-25`: `SetConfigSyncHealth` is diagnostic-only and does not block takeover in existing code.
  - `docs/research/6461-blind-rst/plan.md:1070-1123`, `:1737-1738`: Watermark is node-global `max(own_committed_epoch, lastAppliedConfigGen)` (never cleared by `BulkStart`). On authority transition, the new authority adopts `max(own, received)` as its counter floor (`plan.md:1737`).
- **Analysis of New Attack**:
  - If a new authority's local epoch was lower, `epoch < stale-barrier` at the peer causes immediate refusal as stale (`sync_conn_gen.go:432`), never parking.
  - If local epoch is higher (e.g., adopted `max(own, received)` floor), selective parking (`plan.md:1085-1107`) allows the enabling `syncMsgConfig` frame to pass through unparked (`sync_conn_read.go:298`), applying the config and advancing `lastAppliedConfigGen` to unpark the buffered session frames.

---

### Q2 (Typed undo receipt): SOUND
- **Evidence**:
  - `userspace-dp/src/nat/allocator.rs:1671-1688`: `reserve_flow` today destructively removes `existing` and calls `free_translated_port` (`:1676`) *before* attempting `occupancy[addr_index].reserve(translated.port)` (`:1688`), leaving the incumbent unreserved if `reserve` fails.
  - `userspace-dp/src/nat/allocator.rs:1392-1457`: `rollback_flow` unconditionally removes the flow from `live_by_flow` (`:1405`) and decrements/frees persistent/PAT resources (`:1423`, `:1443`, `:1450`) regardless of prior ownership state.
  - `docs/research/6461-blind-rst/plan.md:1156-1178`: Replaces destructive ordering with a single critical-section typed receipt (`NoChange`, `Inserted`, `Retained`, `Replaced(old_state)`). On claim failure during replacement, `old_state` is reinstated in the same critical section. Post-reservation RAII unwinding undoes exactly the receipt.
- **Taxonomy Coverage**: Covers port-bearing persistent, address-only persistent, non-persistent, and deterministic allocations via `LiveAllocation` fields (`translated`, `persistent_key`, `address_only`, `deterministic`).

---

### Q3 (Token indirection): SOUND
- **Evidence**:
  - `docs/research/6461-blind-rst/plan.md:1376-1379`, `:1443-1490`: `NatHoldToken` references a stable allocation-slot indirection (`Arc` slot per pool allocator).
  - During in-place refresh migration, the migration gate takes the WRITE permit (`:1443`), drains in-flight mutations, snapshots complete ownership state from A into B, and atomically retargets the slot indirection A $\rightarrow$ B (`:1466-1468`).
  - Pre-cut tokens releasing after the cut dereference the slot indirection and land directly in B, decrementing B's refcount cleanly. Stale raw A-handles for *new* mutation attempts hit A's closed gate and transient-fail to re-resolve through B.
- **Trace Resolution & Refcount Continuity**: Resolves round-33 ghost-refcount and reissue traces. Refcount continuity is exact for mutations completing before snapshot and releasing after retarget.

---

### Q4 (Consistency sweep): SOUND
- **Evidence**:
  - `docs/research/6461-blind-rst/plan.md:1054`, `:1089`: "whole-stream park" explicitly identified as defective and replaced by message-class-selective park.
  - `docs/research/6461-blind-rst/plan.md:1110-1115`: "reset and re-bulk" reset loop replaced by drop-oldest + `syncBackfillNeeded`.
  - `docs/research/6461-blind-rst/plan.md:1143-1178`, `:2773-2799`: Bare `rollback_flow` prescriptions replaced by the typed undo receipt in v9.9.18 updates.
  - `docs/research/6461-blind-rst/plan.md:1376-1379`: "exact allocator HANDLE" updated to specify indirection through the stable allocation-slot indirection.
  - `docs/research/6461-blind-rst/plan.md:1074-1076`: Per-bulk watermark resets (`sync_conn_read.go:183`, `sync_conn_gen.go:324`) explicitly removed for node-global watermarks.
- **Contradiction Check**: No remaining contradictions found in `plan.md`.

---

### NEW Implementation Traces Folded Open in v9.9.18

1. **Selective-Park Queue Drain Across Reconnect**
   - **Files & Lines**: `pkg/cluster/sync_conn_read.go:96`, `:183`, `pkg/cluster/sync_conn_sweep.go:185`.
   - **Trace**: Session frames buffer behind a park during an extended config apply lag (`applyingConfigGen != 0`). If the connection drops and reconnects while parked, the peer sends `syncMsgBulkStart`. Because `syncMsgBulkStart` is a session-state frame (`plan.md:1092`), it enters the parked buffer behind pre-reconnect deltas. When config apply finishes and unparks the queue, pre-reconnect deltas apply first, followed by `syncMsgBulkStart` (`resetRecvGen()` at `sync_conn_read.go:195`), followed by post-reconnect bulk deltas. Implementation must verify that `resetRecvGen()` and `snapshotZoneOwnership()` during parked buffer drain discard stale pre-reconnect dirty state so `reconcileStaleSessions` at `BulkEnd` operates on a consistent post-reconnect snapshot.

2. **Indirection Slot Keying Across Pool Reordering / Renaming**
   - **Files & Lines**: `userspace-dp/src/nat/source.rs:327`, `:726`, `afxdp/coordinator/snapshot_refresh.rs:397`, `userspace-dp/src/nat/allocator.rs:720`.
   - **Trace**: An in-place refresh migration reorders pool rules or renames a pool. If stable allocation slots were indexed by ordinal rule index rather than `SourceNatPoolAllocatorKey`, retargeting Slot 0 from Allocator A0 to B0 when Rule 0 changes from Pool X to Pool Y would cause surviving pre-cut tokens for Pool X to release into Allocator Y (Pool Y), corrupting Pool Y's bitmap. Allocation slot indirections must be keyed by `SourceNatPoolAllocatorKey` to preserve retired allocators for deleted/renamed pools until their last pre-cut token drops.
AGY EXIT: 0
