# Checkout Verification & Environment State
- **PWD**: `/home/ps/git/xpf-worktrees/6744-plan-r10-review`
- **HEAD SHA**: `103acbfd28115993f8f6393ed6b55d632bcfb4ee`
- **Git Status**: Clean (`git status --short` returned 0 lines)
- **Write Scope Confirmation**: Write scope is strictly **NONE**. No files, branches, issues, or PRs were modified or written.

---

PLAN-READY

---

### AGY Independent Protocol Reconstruction & Hostile Interleaving Analysis

As the AGY reviewer, I have independently re-derived the state machines, protocol boundaries, lock graphs, transition semantics, and concurrency interleavings described in `docs/research/6744-kimi-review-003/plan.md` (Revision 10) against the current production source tree. 

Revision 10 successfully closes all 16 major findings identified in Round 9. The proposed design provides watertight protection against race conditions, protocol state corruption, unauthenticated/legacy interleavings, and lock deadlocks across all Workstreams A through M.

---

### Hostile Interleaving & Boundary Verification

#### 1. Setup & Capability Negotiation (`new/new`, `new/old`, `old/new`, `keyed/unkeyed`, delayed first frame)
- **Framing Order**: `performSyncHandshake` retains exclusive ownership of pre-auth HELLO/PROOF frames (`syncMsgAuthHello=27`, `syncMsgAuthProof=28`). Handshake completion occurs under the bounded pre-auth setup window (`syncHandshakeTimeout=3s`).
- **Post-Auth Capability**: Immediately following handshake completion and socket buffer configuration, the upgraded node writes `syncMsgCapabilities=30` as its first post-auth frame and reads the peer's first post-auth frame under a setup deadline.
- **Legacy & Unkeyed Staging**: An unkeyed legacy peer sending an ordinary session frame (`syncMsgSessionV4=1`, etc.) as its first frame has that frame staged without loss. The setup phase detects the non-capability header, resolves the connection as `legacy`, registers setup completion, and dispatches the staged message only after full connection registration and authority check. A delayed/stalled first frame hits the setup deadline and closes the setup socket cleanly without tying up post-auth buffers or `conn0`/`conn1` slots.

#### 2. Dual-Fabric & Process Identity Governance (`peerProcessID`, `flags` Mismatch)
- Capability payloads carry an explicit 16-byte random `peerProcessID` generated per `SessionSync` instance (backed by a non-failing entropy check that aborts `Start` before bind if broken).
- Setup requires both fabrics in a transport to match capability class (`capable` vs `legacy`) and `peerProcessID`. If fabric 0 registers as `capable` with `peerProcessID=A` and fabric 1 attempts registration with `peerProcessID=B` (or `legacy`), fabric 1 setup is rejected, the transport is retired, and `transportEpoch` is advanced.

#### 3. Single-Fabric vs. Last-Fabric Disconnect During In-Flight Operations
- **Single-Fabric Replacement**: Admitted config callbacks and session installs are scoped by `(transportEpoch, peerProcessID, roleGeneration, configGen)`. When fabric 0 flaps but fabric 1 keeps the transport live, `transportEpoch` remains constant. An admitted config callback that mutates `configstore` completes cleanly and updates `acceptedConfigGen` because its transport lease remains valid.
- **Last-Fabric Loss**: When both fabrics disconnect, the gate atomically enters `drainingTransport=true`, closes admission, cancels in-flight receive reconciliation and send loops, and blocks new connection registration until all admitted callbacks, installs, and workers join. Only after complete drain does `transportEpoch` advance, invalidating any lingering stale completions and requiring a new config baseline.

#### 4. Callbacks Mutating Store Before Blocking Transitions
- The daemon wrapper `BeginConfigAuthorityTransition` closes gate admission and returns a monotonic `transitionSerial`, but defers advancing `roleGeneration`. 
- An admitted config callback executing against the old role generation completes its `configstore` mutation and publishes `acceptedConfigGen` under its existing lease. `CompleteConfigAuthorityTransition` waits for all admitted callbacks to join (`Wait()`) before incrementing `roleGeneration` and committing the new authority state. No callback can strand a store mutation across a role boundary.

#### 5. Protection Transitions & Unknown/Unresolved Roles
- Protection state is strictly evaluated as `ConfigSyncEnabled && RG0Role == RG0Secondary`.
- An unknown/unresolved RG0 role initializes in `transitioning=true` fail-closed posture. Enabling config-sync on a secondary clears current continuity and imposes a mandatory baseline obligation before session frames can be admitted. Disabling config-sync drains active work and clears baseline debt without purging generic session repair debt.

#### 6. Simultaneous Bidirectional Cold Requests
- Outbound bulk authorization and receive window states are completely decoupled. Outbound sending is guarded by `bulkSendMu -> producerMu`, while receive state is guarded exclusively by `gate.mu`.
- When both capable nodes concurrently issue type-29 cold bulk requests, each node independently captures its local ownership snapshot and writes its outbound bulk without acquiring the receive window mutex. Cluster-originated installs/deletes do not feed back into outbound queues, preventing lock coupling and infinite echo loops.

#### 7. Outbound Used-Connection Fencing & Vanishing Connections
- Before sending `BulkStart`, the sender enqueues a drain token under `bulkSendMu -> producerMu`, records the exact set of `(transportEpoch, connectionIncarnation)` tuples used by pre-drain frames, and issues barriers on all used and live connections.
- If any connection in the used set vanishes or fails its barrier ACK before `BulkStart`, the sender aborts the bulk, retires the transport, re-arms repair debt, and reopens session producers. Late frames from a vanished connection can never arrive after `BulkStart`.

#### 8. Request Pinning & Preferred Fabric Selection
- A repair request sent over fabric 1 captures `(transportEpoch, connectionIncarnation)` of fabric 1. 
- The sender pins the repair bulk to that exact connection incarnation. Even if fabric 0 is preferred for general traffic, the repair bulk remains pinned to fabric 1. If fabric 1 disconnects, the request attempt expires and is re-armed under a new request ID; it is never silently re-routed to fabric 0.

#### 9. Cross-Fabric Isolation During Bulk Receive
- The receive window binds exclusively to the connection incarnation that delivered `BulkStart`.
- If any session frame arrives on the other fabric while the window is in `receiving` or `reconciling` phase, the gate classifies it as a protocol violation, invalidates the receive window, suppresses ACK/readiness, and retires the transport.

#### 10. Reconcile Cancellation During Config, Role Change, Disconnect, or Stop
- `ReconcileClusterBulk` accepts a child `context.Context` and checks cancellation between iterator/delete operations.
- On config apply, role transition, fabric disconnect, or daemon `Stop`, the gate cancels the context and waits (`Wait()`) for the reconciliation goroutine to terminate. The old 5-second unjoined abandon path is completely removed; `Stop` never touches a torn-down dataplane.

#### 11. Reconcile Failure & Readiness Split
- If `ReconcileClusterBulk` fails (due to payload corruption, delete error, or cancellation), `SetSyncReady(true)` is NOT called, `bulkEverCompleted` is NOT set, and repair debt remains armed.
- Advancing `syncReadyTimeout` afterwards only sets the separate `electionTimeoutExpired` availability bit. Continuity remains `false`, manual failover stays blocked, and VRRP continuity release is suppressed.

#### 12. Helper Inventory Debt & Status-Loop Supersession
- Manager-owned `haInventoryDebt` captures `{desiredConfigGeneration, desiredOwners, stagedHelperGroups, pinnedFencedSlots}` under `haStateMu`.
- The status/reconcile loop is the sole consumer. While debt exists, status refresh is prohibited from reading `m.haGroups`, re-arming watchdog slots, or publishing ready status. A newer config generation replaces the debt snapshot atomically under lock, ensuring old retries can never overwrite a newer generation.

#### 13. Legacy Receiver ACK Disambiguation
- Capable `BulkAck` (type 15) carries an explicit 16-byte payload `{bulkEpoch uint64, requestID uint64}`.
- Upgraded senders refuse 8-byte legacy ACKs as proof of authoritative completion. An upgraded sender connected to a legacy receiver will time out on ACK, leave repair debt armed, and mark continuity unready, enforcing the required standby-first upgrade ordering.

---

### Material Blockers

**None.** Plan Revision 10 satisfies all hostile checks and architectural invariants.

---

### Optional Polish & Implementation Guidance

1. **Workstream I-a/I-c Activation Canaries**: Ensure that the build-tag or constant-gated activation check (`I-d`) has a static unit test verifying that legacy paths remain selected when the constant is disabled.
2. **Operational Log Redaction Audits**: In Workstream C, verify that `SNMPSourceObservation` path string formatters use the `RedactedClone` AST classifier in automated unit tests to prevent future secret key leakage into log targets.
