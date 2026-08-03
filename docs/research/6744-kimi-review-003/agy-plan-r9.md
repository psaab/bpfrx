### Environment State Verification
- **`pwd`**: `/home/ps/git/xpf-worktrees/6744-plan-r9-review`
- **HEAD**: `ff17e6351f0e0da4fc2ac0b45d0ecdd4c4b99be5`
- **Git Working Tree Status**: Clean (not on any branch, 0 uncommitted changes)
- **Write Scope**: `NONE` (Strictly research and design review; no code, branch, issue, or PR edits)

---

# Hostile AGY Design Review: Issue #6744 Research Round 9

This adversarial design review re-derives state machines, concurrency interleavings, failure recovery sequences, and cross-node wire semantics for Revision 9 of `docs/research/6744-kimi-review-003/plan.md` ([plan.md](file:///home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md)).

---

## 1. Revision 9 Hostile-Check Analysis

### 1.1 SNMP Redacted Community Observations vs. Correlation & Credential-Aware Hash (Workstream C)
* **Secret Leakage Elimination & Observation Identity**: `prepareCompileView` performs an in-memory deep fold of top-level `snmp` and `system/snmp` AST nodes post-expansion. Secret values (communities, v3 auth/priv passwords) are classified using `ConfigTree.RedactedClone` classifiers. Observations stored in `SNMPSourceObservation` use first-appearance ordinals (e.g. `community[2]`), and `Path` strings replace all secret tokens with `<redacted>`. Secret-derived hashes are strictly prohibited from diagnostic carriers.
* **Duplicate Secret Correlation**: A private, function-local map keys duplicate detection by raw community bytes strictly inside `prepareCompileView`. This correlation map is discarded before returning `preparedCompileView`, preventing secret leaks into logs, warnings, or JSON/YAML projections while ensuring identical communities across multiple set paths are unified.
* **Credential-Aware Restart Detection**: `snmpConfigHash` remains deliberately credential-aware in process memory. It ingests raw communities and v3 passwords so secret rotations force listener updates. Reconcile metadata covers the normalized tree, rejection set, and process enable/disable state, ensuring both credential rotation and rejection-only metadata transitions trigger appropriate reconciles.

### 1.2 DDNS Claim Remove/Save/Snapshot Order & Migration (Workstream E)
* **Surface Classification**: `loadDDNSState` enforces `ownedRecordSurfaceLease` (Surface B) vs `ownedRecordSurfaceInterface` (Surface A). File paths cannot be auto-classified from ambiguous rows, preventing cross-surface state corruption.
* **Surface-A Migration Exception**: Pre-#2903 disk rows with `scope.FQDN == ""` are safely adopted into FQDN keys upon reconcile without triggering wire deletes, preserving in-place upgrades.
* **Atomic Teardown & Lock-Free Snapshot Synchronization**: Stale Surface-B rows follow a strict 3-step sequence:
  1. Matrix validation.
  2. Co-owner check: If co-owners exist, perform a claim-only release by copying the owned row, removing it from candidate state, and executing `ddnsState.save()` **before** updating `WireRRClaims` or counters.
     * *Pre-rename failure*: Reverts memory state, restores the claim in `WireRRClaims`, returns the error, and executes zero provider I/O.
     * *`*fsatomic.PostRenameSyncError`*: Converges memory and `WireRRClaims` to the new visible file (claim removed), logs a durability alarm, and executes zero provider I/O. On restart, old state retries co-owner release cleanly; new state observes the surviving claimant.
  3. Last-claimant authority selection: Executes wire deletes **only** for the last claimant using matching same-family updater fingerprints (`fpb1`).
* **Post-Reconcile Anchor Rotation**: `lastLiveUpdater`/`lastLiveFP` anchor rotation occurs post-reconcile. If any retained row still depends on the old fingerprint, the anchor is preserved across cycles to support multi-generation retries without guessing credentials.

### 1.3 RG Helper Snapshot, Pinned Slot Fencing, & Preflight Honesty (Workstream I)
* **Dataplane vs. Control-Plane Domain Split**: Control-plane RGs support canonical IDs 0..255 (up to 255 RGs). Dataplane owner-binding is strictly bounded to owner slots 1..15 (0 is unbound/standalone sentinel).
* **Helper Replacement Model**: Dataplane helper `update_ha_state` is treated as a full replacement map, not a per-slot patch.
* **Pinned Slot Fencing Sequence**:
  1. `clearHAOwnerSlotFailClosed` writes BPF `rg_active[id]=0` then `ha_watchdog[id]=0` for all removed or introduced slots before updating inventory.
  2. A complete transitional helper payload is constructed: unchanged slots retain reconciled state, introduced slots are marked inactive (`0`), and removed slots are omitted.
  3. The staged snapshot is sent to the helper via explicit payload methods.
  4. Only after BPF fences and helper snapshot succeed does the manager publish the new bound inventory.
* **Retry Ownership**: Retry debt owns the full desired generation and staged payload, preventing slot-patch ordering corruption during retries.
* **Preflight Scope**: `xpfd check-config` evaluates unredacted file syntax on node 0 and node 1. It explicitly disclaims daemon state or freshness verification, placing freshness assurance on operational automation.

### 1.4 Incarnation Architecture across Queued Callbacks & One-Fabric Replacement (Workstream I)
* **Monotonic Incarnations**: `transportEpoch` tracks the continuously connected peer interval shared by both fabrics. `connectionIncarnation` uniquely identifies each accepted TCP connection. `roleGeneration` tracks HA role state.
* **Dual-Receive Loop & Single-Fabric Replacement**: A single-fabric drop invalidates queued work tied to its `connectionIncarnation` without advancing `transportEpoch`. The surviving fabric keeps the transport alive. `transportEpoch` advances only when the last fabric disconnects, setting `baselinePending` and zeroing current-epoch high-water mirrors (`lastRecvConfigGen`, `lastAppliedConfigGen`).
* **Pre-Actuation HA Hook**: `SessionSync.PrepareConfigAuthorityTransition` runs prior to election, VIP, VRRP, or store changes. It drains pending installs, callbacks, receive reconciliation, and the bulk sender. Tokens carrying stale `(transportEpoch, connectionIncarnation, roleGeneration, gen)` are rejected and cannot open gates or clear baselines.

### 1.5 Capability Framing & Directional Compatibility (Workstream I)
* **Framing Protocol**: `syncMsgCapabilities = 30` (26 bytes: `version uint16`, `flags uint64`, `peerProcessID [16]byte`). Must be sent exactly once as the first frame on a connection. `peerProcessID` is generated once per `SessionSync` instance using `crypto/rand`.
* **Fabric Alignment**: Both fabrics must present matching `peerProcessID`s. Mismatches abort the connection and mark continuity unready.
* **Directional Compatibility**:
  * *New Sender $\rightarrow$ Old Receiver*: Old receivers parse the standard epoch prefix and ignore trailing request IDs.
  * *Old Sender $\rightarrow$ New Receiver*: Capability-less peers are assigned sentinel `zeroProcessID`. Authoritative bulk is refused without resetting guards or clearing debt; manual transfer remains unready until the peer upgrades and sends a valid barriered bulk. Automatic failover preserves previous-good state.

### 1.6 Queue Drain & Connection-Bound Barriers (Workstream I)
* **Typed Outbound Queue**: Enqueues `outboundItem` containing raw bytes or `outboundBarrier` carrying `(transportEpoch, roleGeneration, drained chan error)`.
* **Producer Gate Synchronization**: `producerMu` guards all producer entrypoints (incremental installs/deletes, sweep replay, delete-journal replay). `BulkSync` acquires `bulkSendMu` and `producerMu`, sets the producer gate, enqueues barriers across all active connections, and flushes pre-barrier frames before emitting `BulkStart`.

### 1.7 Producer Gate Lifecycle & Lock Order (Workstream I)
* **Lock Hierarchy**: `s.mu $\rightarrow$ gate.mu $\rightarrow$ producerMu $\rightarrow$ deleteJournal.mu $\rightarrow$ bulkSendMu`.
* **Gate Lifecycle**: Producer gate remains held through BulkStart, snapshot transmission, BulkEnd, and receipt of `syncMsgBulkAck`. Incremental session updates stream into a deferred journal.
* **Abort & Replay Safety**: On queue overflow, connection drop, or bulk abort, the producer gate is cleared, pending repair is re-armed, and the deferred journal is safely flushed or discarded under `producerMu`.

### 1.8 Receive State Transitions, Preemption, & Reconcile Failures (Workstream I)
* **Receive State Machine**: Transitions `receiving $\rightarrow$ reconciling`. `BulkStart` acquires a gate lease.
* **Same-Loop Config Preemption**: If a config frame arrives during `receiving`, it invalidates the bulk window, releases the gate lease, and executes config apply on the same loop without deadlocking on `BulkEnd`.
* **Protected Zero-Epoch Session Rejection**: Session installs with generation zero in protected mode are rejected fail-closed, invalidating the bulk window and arming repair debt. Bulk member installs are non-transactional; later member failures invalidate the window and trigger a full resync.
* **Reconnect Quiescence & Reconcile Failures**: Disconnect during reconciliation marks transport as draining. Reconnects cannot process frames until reconciliation completes. Any iterator or delete error in `reconcileStaleSessions` marks the bulk as failed, suppressing success ACKs and re-arming repair debt.

### 1.9 Type-29 Request Identity & BulkAck Correlation (Workstream I)
* **Request & Bulk Identifiers**: `syncMsgBulkRequest = 29` carries an 8-byte `requestID`. Repair `BulkStart`/`BulkEnd` carry 16-byte `{bulkEpoch uint64, requestID uint64}`.
* **ABA Elimination**: Receivers match BulkEnd against the exact `requestID`. In-flight bulks with ID 0 or mismatched IDs cannot satisfy a pending type-29 request.
* **Causal BulkAck**: Capable `syncMsgBulkAck` carries 16-byte `{bulkEpoch, requestID}`. Legacy 8-byte ACKs cannot clear capable repair bulks. Timeout or fabric disconnect retires the transport and re-arms repair debt.

### 1.10 ReadConfirm Persisted-Tree Bounds & #6548 Boundary (Workstreams G & F)
* **Persisted Tree Validation**: `ValidatePersistedTreeShape` enforces non-nil trees, non-nil child pointers, and `len(Keys) > 0` recursively. Called in `DB.readTreeMeta` and `DB.ReadConfirm` prior to `recoverPendingConfirmLocked`.
* **#6548 Exclusion Scope**: Workstream F restricts `LoadOverride` atomic detached tree candidate swaps to Store, REST, gRPC, and non-interrupted local loads. `readline.ErrInterrupt` and `pkg/cli` terminal interrupt handling remain strictly excluded and delegated to #6548.

---

## 2. Comprehensive Audit of Workstreams A–M

| Workstream | Issue ID | Focus Area | Design Verdict | Status & Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **A** | K003-16 | `vipWarnedIfaces` Mutex Synchronization | **Fully Specified** | Protected under `m.mu`; race-free map access guaranteed. |
| **B** | K003-07 | Empty Security Identity Pre-Normalization | **Fully Specified** | Validates non-empty keys prior to AST normalization. |
| **C** | K003-13 | SNMPv3 Security Intent Validation | **Fully Specified** | Schema-aware deep fold, redacted observations, in-memory correlation, credential-aware restart hash. |
| **D** | K003-01 | Flowless ICMP Global Admission | **Fully Specified** | Passes ICMP type byte without memory allocations on packet path. |
| **E** | K003-03 | DDNS Withdrawal & Ownership Binding | **Fully Specified** | Surface enums, matrix checks, atomic claim-only save/snapshot order, post-reconcile anchor rotation. |
| **F** | K003-09 | Atomic `LoadOverride` Format Handling | **Fully Specified** | Flat vs hierarchical classification on detached trees; #6548 interrupt boundary strictly preserved. |
| **G** | K003-04 | AST Validation & Compiler Belts | **Fully Specified** | Bounded `ValidatePersistedTreeShape` at `ReadConfirm` boundary; safe `Name()` idiom. |
| **H** | K003-08 | Route-Map Expansion Cardinality | **Fully Specified** | Centralized sequence counting and boundary guards in `pkg/config`. |
| **I** | K003-10 | RG Dataplane Align & BulkSync Engine | **Fully Specified** | Owner slots 1..15, full replacement helper map, pinned slot BPF clear, monotonic epochs/incarnations, pre-actuation HA hook, typed barriers, type-29 request ID, 16-byte BulkAck. |
| **J** | K003-06 | Global Address-Book Consolidation | **Fully Specified** | Order-preserving merge of top-level and nested global address books. |
| **K** | K003-11 | Transient Routing Ownership Retention | **Fully Specified** | Ownership retained until confirmed netlink removal or `LinkNotFound`. |
| **L** | K003-14/15 | Lifecycle Action Normalization | **Fully Specified** | `SESSION_OPEN`/`SESSION_CLOSE` normalize to `"n/a"`; forward actions strictly gated. |
| **M** | K003-05 | Nested Zone-Policy Container Rejection | **Fully Specified** | Fail-closed rejection of non-canonical nested `from-zone` containers. |

---

## 3. Categorization of Findings

### 3.1 Blockers
* **None**. Revision 9 resolves all dual-receive loop races, HA role transition hook gaps, barrier check/enqueue races, type-29 ABA ambiguities, and RG helper snapshot model misalignments identified in Round 8.

### 3.2 Optional Polish
1. **Type-29 Metrics Counter**: Add a Prometheus counter tracking type-29 repair requests coalesced during active bulk transfers.
2. **DDNS Claim Release Logging**: Log a structured trace event when a Surface-B claim-only release executes without provider I/O.

---

## 4. Final Verdict

PLAN-READY
