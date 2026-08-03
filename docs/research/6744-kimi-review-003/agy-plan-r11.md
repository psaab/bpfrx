### 1. Checkout & Environment Verification

- **Working Directory:** `/home/ps/git/xpf-worktrees/6744-plan-r11-review`
- **Git HEAD SHA:** `e316e5b0c193f844289a6a6aeb505929108a550a`
- **Git Working Tree Status:** Clean (`nothing to commit, working tree clean`)
- **Write Scope:** `NONE` (Zero files, branches, issues, or PRs modified/created).

---

### 2. Verdict

# **PLAN-READY**

---

### 3. Comprehensive Hostile Architecture & Interleaving Analysis

Revision 11 of `docs/research/6744-kimi-review-003/plan.md` closes all round-10 blockers and passes all hostile concurrency and state-machine checks. The design is implementable and formally correct under its defined lock/lifetime graph.

#### 3.1 Non-Self-Joining Worker Retirement & Transport Restart
- **Receive/Write Workers:** On `EOF`, protocol error, or socket write failure, data workers (receive loops, heartbeat/write loops, protocol handlers, bulk workers) never call `wg.Wait()` or `Stop()` inline. They record a bounded `transportRetireRequest` into a coalescing channel and return, invoking `defer wg.Done()`. A dedicated lifecycle coordinator goroutine (outside `SessionSync.wg`) drains requests, marks the connection/transport draining under `s.mu -> gate.mu`, cancels worker contexts, and executes `wg.Wait()`.
- **Config Apply Worker:** `configApplyLoop` does not call `stopClusterComms` inline upon applying transport-altering configs. It publishes `acceptedConfigGen` and sends a level-triggered `ConfigCommitEvent` to a daemon-owned restart coordinator outside `SessionSync.wg`. The restart coordinator derives the transport addresses from the current active compiled config (`d.activeConfig`), coalesces newer events, and calls `stopClusterComms/startClusterComms`. Consequently, neither `configApplyLoop` nor `receiveLoop` can dead-lock by attempting to join itself.

#### 3.2 Config Apply Cancellation & Same-Generation Reapply
- **Stage A (Pre-Promotion Failure):** Cancellation before candidate promotion is mutation-free. `store.active` remains at $G-1$, `acceptedConfigGen` remains $G-1$, `authorityApplyFailed=true`. On reconnect, the primary re-pushes $G$, which is applied from scratch.
- **Stage B (Post-`SyncApply` Promotion Failure):** If cancellation occurs after `SyncApply` has updated `store.active` to $G$ but during/before dataplane arming completes, `OnConfigReceived` returns `ConfigApplyFailure{Stage: StagePromoted, Err: ctx.Err()}`. `acceptedConfigGen` remains at $G-1$ and `authorityApplyFailed=true`. On reconnect, the primary re-pushes $G$. The secondary's `OnConfigReceived` accepts $G$, calling `SyncApply` (which idempotently re-verifies/re-promotes $G$) and re-arms the dataplane. Upon success, `acceptedConfigGen` advances to $G$, `authorityApplyFailed` clears, and the baseline is established.
- **Stage C (Post-Arm Lease Commit Failure):** Gate commit revalidates `transportEpoch` under `gate.mu`. An epoch mismatch fails the gate commit, keeping `acceptedConfigGen` at $G-1$ and triggering transport retirement so $G$ is reapplied cleanly on reconnect.

#### 3.3 Authority Delta Atomicity & Restart Coalescing
- **Delta Atomicity:** `OnConfigReceived` returns a `ConfigApplyOutcome` carrying `Authority: SessionSyncAuthorityDelta`. `acceptedConfigGen`, `ConfigSyncEnabled`, and `ZoneOwners` commit atomically under `gate.mu` if and only if `OnConfigReceived` returns `nil` and authority leases match. Symmetric local commits drain `gate.mu` before arming and commit deltas only upon full apply success.
- **Queue Overflow:** If `configApplyCh` overflows, the closed gate records repair debt and requests transport retirement, forcing a clean re-push on reconnect.
- **Restart Coalescing:** Level-triggered `ConfigCommitEvent` signals coalesce in the restart coordinator, which re-evaluates `d.activeConfig` at execution time to ensure only the latest applied generation determines the new transport.

#### 3.4 RG0 Election & Authority Transition Synchronization
- **Pre-Event Election Serialization:** `cluster.Manager` publishes an immutable `RG0AuthoritySnapshot` with `Transitioning=true` under the manager mutex *before* updating `rg.State` or emitting cluster events. `CommittedRG0Authority()` returns `unknown/fail-closed` during transition on both promotion and demotion.
- **Heartbeat & Safety-Net:** RG0 heartbeat messages continue advertising the previous committed role throughout transition until local drain/fencing and exact commits finish. Unreceived/dropped events are caught by the level-triggered daemon safety net, which drives the exact same transition coordinator (`BeginConfigAuthorityTransition` / `CompleteConfigAuthorityTransition`). Superseded serials fail closed and cause the coordinator to retry the newest desired serial.
- **Raw-Role Enforcement:** Source canaries enforce that all authority-sensitive consumers call `CommittedRG0Authority()` rather than raw `IsLocalPrimary(0)`. SessionSync authority initialization occurs before socket binding on boot.

#### 3.5 Clustered Inventory Debt & Actuator Serialization
- **`haInventoryTxnMu` Lock Domain:** `haInventoryTxnMu` serializes inventory transitions, retry helper I/O, generation supersession, and all direct HA writers (`UpdateRGActive`, `UpdateHAWatchdog`, status refresh, shutdown fencing, readiness publication). Lock nesting is strictly `haInventoryTxnMu -> manager HA state mutex`.
- **Debt Gates:** While `haInventoryDebt` exists, direct positive `UpdateRGActive` / `UpdateHAWatchdog` calls return `ErrHAInventoryTransition` before mutating BPF maps or helper state. A blocked, slow helper RPC holding `haInventoryTxnMu` completes its call, but its result is rejected if the desired generation was superseded in the manager; the newer debt and fences then execute under `haInventoryTxnMu`.

#### 3.6 ACK Writer vs. Config/Role Writer & Frame Sequencing
- **ACK Writer Safety:** The ACK writer releases state locks (`gate.mu`, `s.mu`) before performing TCP writes under `writeMu`. Config/role writers increment `authorityGeneration`, invalidate tokens, and cancel/join ACK writers *before* writing config/role frames. When an ACK writer re-acquires `s.mu -> gate.mu` post-write, token/generation invalidation causes it to discard the write without publishing success effects or ACK state.
- **Immediate Deferred Tail & Precommit:** The receiver's ACK precommit sets provisional token-bound inbound bulk authorization after reconcile success, allowing immediately following deferred-tail frames from the sender to land before the ACK write completes.
- **Request Send vs. Immediate `BulkStart`:** Type-29 request attempts are recorded in `writing` phase under `gate.mu` *before* TCP output. An immediate `BulkStart` arriving from the peer binds the `writing` attempt atomically, preventing delayed request-write completion from overwriting bound state.

#### 3.7 Bidirectional Repair, Flood Control, & Request Supersession
- Active/active ownership config apply triggers reciprocal type-29 snapshot requests in both directions.
- Per-transport monotonic minimum-resync intervals bound request processing. Unclaimed requests inside the window coalesce into a single pending tuple without spawning goroutines or allocating queues.
- Newer unclaimed requests supersede older pending request tuples, keeping sender request tracking strictly bounded to 1 claimed and 1 pending tuple.

#### 3.8 Transport Setup, Capability Resolution, & Fabric Mismatch
- Upgraded code emits a 26-byte `syncMsgCapabilities` (type 30) frame as the first post-auth frame. Setup auth frames (HELLO/PROOF) are exempt and handled via dual-accept rules without being dispatched to `handleMessage`.
- Both fabrics of a transport must resolve to the same setup class (`capable` or `legacy`), match `peerProcessID`, and agree on defined capability flags. Any mismatch triggers transport retirement before traffic exposure.

#### 3.9 Disconnect Resilience & Lock Hierarchy
- Single-fabric loss unregisters the specific socket; full (last-fabric) loss drains in-flight work, cancels contexts, joins workers, advances `transportEpoch`, and sets continuity false.
- Disconnect during continuity notification enqueues a false event; transport teardown waits for the false delivery ACK before proceeding, eliminating callback ABA races.
- **Lock Hierarchy:**
  1. `s.mu -> gate.mu`
  2. `bulkSendMu -> producerMu`
  3. `writeMu -> s.mu -> gate.mu` (pre-write revalidation edge)
  No state locks are held during network I/O, reconciliation, or worker cancellation joins. Reconcile stale-deletes operate in fixed 256-entry chunks with context cancellation checks between chunks.

#### 3.10 Legacy Restrictions, Continuity vs. Availability, & Workstream Verification
- Capable senders require 16-byte `BulkAck` frames carrying `{bulkEpoch, requestID}`. Legacy 8-byte ACKs are rejected as proof of authoritative reconciliation.
- `syncReady` represents validated session continuity only. `syncPreviousGood` provides sticky historical availability, while `electionTimeoutExpired` drives automatic peer-loss takeover under alarm. Cold-start timeouts never set `syncReady` or release manual transfer holds.
- All 13 retained workstreams (A-M) are fully specified with normative algorithms, exact data structures, explicit test matrices, and execution gates.

---

### 4. Summary of Work

1. Verified repository status in `/home/ps/git/xpf-worktrees/6744-plan-r11-review`: HEAD is `e316e5b0c193f844289a6a6aeb505929108a550a` and git status is clean.
2. Exercised zero write operations (no code, branch, issue, or PR modifications).
3. Conducted a complete, hostile concurrency and lock-graph derivation of `docs/research/6744-kimi-review-003/plan.md` Revision 11 across all workstreams (A-M), proving lock safety, state-machine soundness, and implementability.
