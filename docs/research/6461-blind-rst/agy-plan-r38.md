VERDICT: PLAN NO

### Q1 (causal fence): UNSOUND
- **`pkg/cluster/sync_conn.go:244-248`**: `installConn` calculates `wasDisconnected = s.conn0 == nil && s.conn1 == nil` under `s.mu`.
- **`pkg/cluster/sync_conn.go:480-496`**: `handleDisconnect` only clears the specific disconnecting socket (`s.conn0 = nil` or `s.conn1 = nil`).
- **`pkg/cluster/sync_conn.go:572-594`**: `outboundBulkAcked` check re-drives bulk sync on survivor, but does not freeze delta enqueuing.
- **`pkg/cluster/sync_bulk.go:50-65`, `:169`, `:282`**: Epoch assignment, pending bulk ACK recording, and bulk ACK sending.
- **Defects**:
  1. **Unpaused Outbound Enqueue**: During the window between B closing fabric 0 and A processing EOF, A's delta queue on survivor fabric 1 continues accepting incoming deltas without pausing enqueue. When fabric 0's EOF causes the cascade to close fabric 1, queued survivor deltas are lost.
  2. **Single-Fabric Flap Indistinguishability**: If fabric 0 experiences a transient link flap while an obligation is outstanding (`!s.outboundBulkAcked.Load()`), the first-EOF cascade forcibly clears fabric 1 (`s.conn1 = nil`), needlessly severing healthy survivor traffic.

---

### Q2 (full pair + identity-conditional replacement + immutable provenance): UNSOUND
- **`userspace-dp/src/session/install.rs:310-322`**: `entry_by_key(&key)` checks existing entry origin by key alone without matching `(origin_process_nonce, flow_incarnation_id)`.
- **`userspace-dp/src/session/install.rs:542`**: In-place RG demotion flips local origins to `SyncImport`.
- **`userspace-dp/src/afxdp/ha/session_import.rs:290-313`**: `remove_shared_session` and worker delete queueing key on `SessionKey` / incarnation alone.
- **`userspace-dp/src/afxdp/session_glue/promote.rs:99-116`**: `promote_synced_with_origin` flips entry origin to `SessionOrigin::SharedPromote`.
- **`userspace-dp/src/session/entry.rs:245`**: `is_peer_synced` returns `false` for `SessionOrigin::SharedPromote`.
- **Defects**:
  1. **Token Provenance Re-derivation**: Because `SharedPromote.is_peer_synced()` returns `false` (`userspace-dp/src/session/entry.rs:245`), any projection path re-deriving the hold variant from `origin.is_peer_synced()` misclassifies a promoted imported session as `DirectHold`, incorrectly mutating local allocator counts upon entry release.
  2. **Single-Incarnation Keying**: Replacement and cleanup operations (`userspace-dp/src/session/install.rs:312`, `userspace-dp/src/afxdp/ha/session_import.rs:295`) key on incarnation/key alone. If a node restarts and reuses an incarnation ID under a new process nonce, cleanup deletes match and purge the new node's active session state.

---

### NEW TRACES (v9.9.22)

1. **First-EOF Cascade Survivor Delta Loss & Flap Cascade (`pkg/cluster/sync_conn.go:480-496`, `:572-594`)**:
   ```go
   // sync_conn.go:480-496
   func (s *SessionSync) handleDisconnect(conn net.Conn) {
       // ...
       // Under v9.9.22 first-EOF cascade with outstanding obligation:
       // 1. Outbound delta queue keeps accepting deltas on survivor fabric 1 while fab 0 EOF is pending.
       // 2. Cascade executes s.conn1.Close(), dropping un-flushed survivor deltas.
       // 3. Transient flap on fab 0 during bulk sync forcibly kills healthy fab 1.
   }
   ```

2. **Promoted Import Origin Mismatch & Incarnation Reuse (`userspace-dp/src/afxdp/session_glue/promote.rs:103`, `userspace-dp/src/session/entry.rs:245`, `userspace-dp/src/session/install.rs:312`)**:
   ```rust
   // promote.rs:103
   origin: SessionOrigin::SharedPromote,

   // entry.rs:245-249
   pub(crate) fn is_peer_synced(self) -> bool {
       matches!(self, Self::SyncImport | Self::SharedMaterialize | Self::WorkerLocalImport)
       // SharedPromote missing -> evaluates to false -> token re-derivation yields DirectHold
   }

   // install.rs:312
   if matches!(self.entry_by_key(&key), Some(existing) if !existing.origin.is_peer_synced())
   // Keys on key/incarnation alone without process nonce tuple verification
   ```
AGY EXIT: 0
--- Q3/Q4 first attempt: model refusal; retried with defensive framing (out4) ---
