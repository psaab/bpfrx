VERDICT: PLAN YES

### Q1 (Overflow Repair) — SOUND
- **Full Bulk Re-drive on Reconnect**: `pkg/cluster/sync_conn.go:194` (`s.doBulkSync()`) executes a complete table iteration across all IPv4 (`pkg/cluster/sync_bulk.go:93`) and IPv6 (`pkg/cluster/sync_bulk.go:134`) sessions rather than an incremental resend.
- **Silent Loss Prevention & Reconciliation**: At `BulkEnd` (`pkg/cluster/sync_conn_read.go:242`), `s.reconcileStaleSessions()` purges any local session not present in the snapshot. Lossy bulks (discarded items during overflow) drop the parked buffer, suppress reconciliation/ACK (`pkg/cluster/sync_conn_read.go:205, 241`), and trigger a single disconnect per latched epoch. The subsequent full bulk snapshot reconstructs all installs and deletes.
- **Sender Self-Arming**: Outbound queue overflow in `queueMessage` self-arms `syncBackfillNeeded` via CAS (`pkg/cluster/sync_conn_write.go:46`), preserving the sweep window.

### Q2 (Single Reservation Point) — SOUND
- **Coordinator Import Serialization**: Coordinator imports in `userspace-dp/src/server/handlers/sync_session.rs:10` (`handle(guard: &mut ServerState, ...)`) run on the single control thread holding exclusive `&mut ServerState`, and lock `self.sessions.synced` at `userspace-dp/src/afxdp/ha/session_import.rs:44, 116`.
- **Single Reservation & Clean Failure Handling**: In `userspace-dp/src/afxdp/ha/session_import.rs:115` (`publish_shared_session`) and `:215` (`WorkerCommand::UpsertSynced`), reservations are performed *before* canonical publication and fan-out. If a coordinator-side reservation is rejected (e.g. `:59, 100`), the function returns early without publishing or fanning out to workers.
- **Worker Isolation**: Per-worker imports (`userspace-dp/src/afxdp/session_glue/mod.rs:744`) and materializations (`:1157`) assert committed state. If the coordinator rejected the reservation, `lookup_session_across_scopes` returns `None` and packet handling falls back cleanly to regular flow processing.

### Q3 (Slot Linearization) — SOUND
- **Gate READ & Revalidation**: `slot.with_current()` loads `(generation, allocator)`, acquires gate `READ` permit on `allocator`, and revalidates `slot.generation` and non-retired status (`docs/research/6461-blind-rst/plan.md:1557-1563`).
- **Read Permit Drain Before Retarget**: Migration acquires `slot-WRITE` before `allocator-WRITE` (`docs/research/6461-blind-rst/plan.md:1564`). Acquiring `allocator-WRITE` drains all active `READ` permits on allocator `A` before snapshotting state into `B`.
- **Stale Permit Catch & Bounded Retry**: Any holder holding a stale handle for `A` that pauses before acquiring `A`'s permit is caught on resume: either `A`'s gate is closed (retired) or revalidation (`generation` mismatch) fails. The holder drops the permit, reloads `B` from `slot`, and retries. Since slot retargeting happens at most once per migration, the retry loop converges in at most 2 iterations.

### Q4 (Takeover-After-Drain + Composition) — SOUND
- **Readiness Fence**: Node readiness requires published epoch $\ge$ peer high-water (`pkg/cluster/sync_conn_read.go:301-314`) AND empty parked queues with no outstanding repair (`pkg/cluster/readiness.go:20-34`).
- **Partition Era Protection & Monotonicity**: Under the `#6284` namespace rules (`pkg/cluster/sync_conn_gen.go:340-379, 398-420`), peer stamps belong to the peer's config-sync generation namespace. On reconnect after a partition, `resetRecvGen()` (`pkg/cluster/sync_conn_gen.go:340`) resets `lastRecvConfigGen`, `lastAppliedConfigGen`, and `applyingConfigGen` to 0, preventing partition-era peer stamps from causing invalid high-water over-advancements.

---

### Folds / Closed Traces in v9.9.19
No open vulnerability or correctness traces remain in v9.9.19. All round-34 edge cases are closed:
1. **Round-34 Codex B1 / SMR F1**: Lossy-bulk suppression and once-per-epoch disconnect eliminate lossy bulk reconciliation loops (`pkg/cluster/sync_conn_read.go:205, 241`).
2. **Round-34 Codex B2**: Coordinator-side single reservation point eliminates cross-worker allocation race windows (`userspace-dp/src/afxdp/ha/session_import.rs:115, 215`).
3. **Round-34 Codex B3**: `slot.with_current()` linearization eliminates ghost holders and port reissues across migration cuts (`docs/research/6461-blind-rst/plan.md:1548-1566`).
4. **Round-34 Codex H4**: High-water tracking from observed session `INSTALL` epochs prevents premature takeover during `C2` publish gaps (`pkg/cluster/sync_conn_read.go:301-314`).
AGY EXIT: 0
