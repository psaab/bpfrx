VERDICT: PLAN NO

### Q1 (barrier generation): UNSOUND
* **Evidence**: `pkg/cluster/sync_conn.go:244-250` (`installConn`) takes `s.mu.Lock()` to manage `conn0`/`conn1` slot assignments, but contains no check or comparison of a barrier generation. Sockets whose pre-auth setup was admitted prior to the barrier bump complete `performSyncHandshake` (`pkg/cluster/sync_conn.go:100`) and call `installConn` (`pkg/cluster/sync_conn.go:130`) after the bump without validating their setup timestamp or generation under `s.mu`. A setup racing the barrier bump can successfully slip its connection into the slot registry after the barrier start.

### Q2 (stream hygiene): UNSOUND
* **Evidence**: `pkg/cluster/sync_conn_gen.go:263, :324` (`deleteGenGuardV4`, `resetRecvGen`). `resetRecvGen` (`:324`, invoked via `sync_conn_read.go:183`) wipes the stored receiver generation maps (`recvGenV4`/`recvGenV6`) at repair `BulkStart`. If a non-survivor stream's TCP RST is lost due to a blackhole, any straggler payload arriving after `BulkStart` is checked against `stored == 0` in `deleteGenGuardV4` (`:263, :286`), causing stragglers with non-zero generations to appear fresh. Repair-ID + generation fencing fails because `resetRecvGen` destroys the receiver-side fence state prior to bulk completion.

### Q3 (Converted receipt): UNSOUND
* **Evidence**: `userspace-dp/src/session/install.rs:310, :542` and `userspace-dp/src/afxdp/session_glue/promote.rs:99`. There is no single per-entry version field on `SessionEntry` covering origin and identity together. Intervening re-promotions (`promote_synced_with_origin` at `promote.rs:99`) or RG owner demotions (`demote_owner_rg` at `install.rs:542`) mutate origin without executing a synchronized commit-time version recheck. Because `upsert_synced_with_origin` (`install.rs:310`) only checks `!existing.origin.is_peer_synced()`, un-serialized concurrent promotions break exact undo guarantees.

### Q4 (post-cut journal + staging contract): UNSOUND
* **Evidence**: `docs/research/6461-blind-rst/plan.md:1408-1412`. Performing shadow-chunked commits with the generation-map commit last exposes chunk-committed session members to external observers and packet lookups before their generation bounds are published. An observer sees a partial table operating with stale generation state, which is indistinguishable from steady state. Furthermore, if post-cut journal flushes stream across active connections out-of-order relative to bulk chunk application, generation guards in `pkg/cluster/sync_conn_gen.go:263` evaluate updates against invalid generation baselines.

---

### NEW Traces Folded Open in v9.9.27

1. **Unmonitored Pre-ACK Handshakes & Mid-Barrier Install Race** (`docs/research/6461-blind-rst/plan.md:1249-1273`):
   * Code: `pkg/cluster/sync_conn_read.go:32, :296`, `pkg/cluster/sync_conn.go:100, :388`, `pkg/cluster/sync_admission.go:66`
   * Trace: `missedHeartbeats` increments only when `peerHeartbeatAckEver` is true, leaving pre-ACK connections un-monitored during barriers. Sockets admitted before the barrier complete handshakes mid-barrier and invoke `installConn` without a barrier generation fence, populating slots after the reset.

2. **Cross-Fabric Multi-Stream Asynchronous Replay on RESYNC_REQUEST** (`docs/research/6461-blind-rst/plan.md:1303-1316`):
   * Code: `pkg/cluster/sync_bulk.go:53`, `pkg/cluster/sync_conn_write.go:268`
   * Trace: Quiescing the sender during a repair cannot recall bytes already accepted on another fabric stream. An `Install(E1)` on delayed `fab1` can land after a `Delete(E1)` on `fab0` has already committed an E1-absent repair.

3. **Post-Cut Journal Premature Obligation Discharge** (`docs/research/6461-blind-rst/plan.md:1382-1397`):
   * Code: `pkg/cluster/sync.go:805`, `pkg/cluster/sync_conn_write.go:14, :36, :69`
   * Trace: Explicit producers continue queueing into the 4,096-frame channel during repairs. If `BulkEnd` discharges readiness before the post-cut window is delivered and acknowledged, a node takeover can occur with missing entries or stale deleted state.

4. **Unbounded Staging Memory & Intermediate Generation State Exposure** (`docs/research/6461-blind-rst/plan.md:1398-1420`):
   * Code: `pkg/cluster/sync_conn_read.go:62`, `pkg/cluster/sync_conn_gen.go:324`
   * Trace: Without a table-derived staging budget, missing `BulkEnd` signals retain staged state indefinitely. Shadow-chunked commits that publish entries before the generation map commit expose partial tables with un-updated generations.

5. **`Converted(old_state)` Transition Matrix & Exact Undo Failure** (`docs/research/6461-blind-rst/plan.md:1729-1746`):
   * Code: `userspace-dp/src/session/install.rs:310`, `userspace-dp/src/afxdp/session_glue/promote.rs:99`
   * Trace: Treat `Converted` as `NoChange` leaves stale `DirectHold` double-release paths or un-dropped group clones. `Converted(old_state)` requires explicit undo (re-incrementing direct count and dropping the minted clone) tied to a versioned origin recheck.

6. **Pending Queue GroupHold Clone Leak in Cohort Cleanup** (`docs/research/6461-blind-rst/plan.md:1970-1981, :2021-2030`):
   * Code: `userspace-dp/src/session/session_import.rs:115, :187`
   * Trace: Stage 1 cohort cleanup checking only active worker replicas misses queued `GroupHold` clones inside pending command queues, leading to premature reservation cleanup while unclaimed commands still hold valid clones.
AGY EXIT: 0
