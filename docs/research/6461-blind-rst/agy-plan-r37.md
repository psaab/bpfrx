VERDICT: PLAN NO

### Question Evaluations

#### Q1 (obligation direction + causality): SOUND
- **(a) PRIMARY all-fabric reset & reconnect barrier**:
  - Existing issue: In `pkg/cluster/sync_conn.go:248`, `d.wasDisconnected` is computed as `s.conn0 == nil && s.conn1 == nil`. If fabric 0 disconnects while fabric 1 survives (or if fabric 0 reconnects before fabric 1's disconnect EOF is processed under `s.mu`), `d.wasDisconnected` evaluates to `false`, causing `d.shouldColdPrime` to be `false` (`pkg/cluster/sync_conn.go:139`).
  - Fix implementation: In `docs/research/6461-blind-rst/plan.md:1164-1176` & `:3068-3071`, buffer overflow triggers an atomic receiver-side all-fabric reset closing both `s.conn0` and `s.conn1` under `s.mu`. When the first fabric reconnects, `installConn` (`pkg/cluster/sync_conn.go:244-250`) acquires `s.mu` and observes `s.conn0 == nil && s.conn1 == nil`, ensuring `d.wasDisconnected == true` and `d.shouldColdPrime == true`. The reconnect barrier under `s.mu` is fully implementable.
- **(b) OPTIONAL rolling-gated RESYNC_REQUEST(generation N)**:
  - `docs/research/6461-blind-rst/plan.md:1177-1187` & `:3071-3072`: Sender arms an outbound-repair obligation for monotone generation N and re-drives full bulk A→B over the survivor. Generation N discharges strictly on the completion of the exact replacement bulk for N.
- **(c) Direction-split obligation bookkeeping**:
  - `pkg/cluster/sync_bulk.go:66`: Epoch is assigned monotonically via `s.bulkSendNext.Add(1)`.
  - `pkg/cluster/sync_bulk.go:169`: `pendingBulkAckEpoch` is stored before writing `BulkEnd` to the wire.
  - `pkg/cluster/sync_conn_read.go:257-258`: `syncMsgBulkAck` drops ACKs where `pending == 0 || epoch < pending`.
  - `pkg/cluster/sync_conn.go:594`: The volatile `bulkRedriveInFlight` CAS is superseded by durable obligation state (`docs/research/6461-blind-rst/plan.md:1197-1205` & `:3084-3086`). Delayed pre-obligation ACKs and intermediate ACKs during O2 are rejected because obligations require `epoch >= obligation_generation_start`.

#### Q2 (typed token): UNSOUND
- **NatHoldToken Enum Definition**: `docs/research/6461-blind-rst/plan.md:1364-1399` & `:3089-3093` defines `DirectHold` (locally-born, direct allocator refcount) vs `GroupHold(Arc)` (imported, clone distribution, finalizer releases allocator lease when last clone drops).
- **Flaw 1: Migration Gate vs. GroupHold Finalizer Deadlock (Lock Inversion & Self-Deadlock)**:
  - `docs/research/6461-blind-rst/plan.md:1674-1677`: In-place-refresh migration acquires the Migration Gate **WRITE permit**, then acquires `allocator.live` (`A.live`) lock to snapshot state.
  - `docs/research/6461-blind-rst/plan.md:1660-1668` & `:1712-1715`: `GroupHold` finalizer (`Drop` impl when the last clone drops) calls `release_flow` / `with_current()`, which attempts to acquire the Migration Gate **READ permit** before accessing `A.live`.
  - *Cross-Thread Lock Inversion*: A worker thread W holding `A.live` (or session/table locks during reap/expiry) drops the last `GroupHold` clone. The finalizer blocks waiting for Migration Gate READ permit. Simultaneously, Migration Thread M holds Migration Gate WRITE permit and blocks waiting for `A.live`. Thread M waits for W (`A.live`), while W waits for M (Migration Gate WRITE permit release) — producing a deadlock.
  - *Self-Deadlock*: If Migration Thread M drops a `GroupHold` token during snapshot/retarget cleanup while holding Migration Gate WRITE permit, the finalizer fires on Thread M and calls `with_current()`, attempting to acquire Migration Gate READ permit on the same RW lock — causing a self-deadlock.
- **Flaw 2: Incomplete Lifecycle Enumeration (`SharedPromote` missing)**:
  - `docs/research/6461-blind-rst/plan.md:1376-1395` enumerates `FAN-OUT`, `REVERSE SYNTHESIS`, `MATERIALIZATION`, `REPLACEMENT`, `ESCROW`, `REAP`, `PANIC-DROP`, but omits HA failover promotion (`SharedPromote`).
  - When an imported session becomes locally authoritative upon takeover, keeping `GroupHold` causes local worker direct refcount operations (`verify_and_retain`) to conflict with the `Arc` finalizer, resulting in premature or double allocator release.

#### Q3 (convergence sweep): UNSOUND
- The composed mechanism inherits the Q2 deadlock between the `GroupHold` finalizer and the Migration Gate's WRITE permit, as well as the unhandled HA `SharedPromote` variant transition state.

---

### NEW Traces Folded Open in v9.9.21

1. **Migration Gate WRITE Permit vs. GroupHold Finalizer Lock Inversion Deadlock**:
   - `docs/research/6461-blind-rst/plan.md:1674-1677`: Migration thread M acquires Migration Gate WRITE permit -> attempts to acquire `A.live` lock.
   - `docs/research/6461-blind-rst/plan.md:1660-1668` & `:1712-1715`: Worker thread W executing reap/expiry holds `A.live` -> drops last `GroupHold` clone -> `Drop` finalizer invokes `release_flow` -> `with_current()` -> attempts to acquire Migration Gate READ permit.
   - *Result*: Deadlock between Thread M (holding Gate WRITE permit, waiting for `A.live`) and Thread W (holding `A.live`, waiting for Gate READ permit).

2. **Migration Thread Self-Deadlock on GroupHold Drop**:
   - `docs/research/6461-blind-rst/plan.md:1674-1677`: Migration thread M holds Migration Gate WRITE permit.
   - During snapshot/retarget cleanup, Thread M drops a `GroupHold` token.
   - `Drop` finalizer invokes `release_flow` -> `with_current()` -> attempts to acquire Migration Gate READ permit on the same thread holding the WRITE permit -> self-deadlock.

3. **Unhandled `SharedPromote` HA Promotion for `GroupHold` Tokens**:
   - `docs/research/6461-blind-rst/plan.md:1364-1399`: Lifecycle enumeration omits `SharedPromote`.
   - On HA failover, an imported flow (`GroupHold(Arc)`) becomes locally authoritative. If local dataplane code attempts `DirectHold` direct allocator refcounting, the direct count and `Arc` finalizer desynchronize, causing premature port release or double release.
AGY EXIT: 0
