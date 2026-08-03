### Repository State Verification

* **pwd:** `/home/ps/git/xpf-worktrees/6744-plan-r12-review`
* **HEAD:** `1f1325f3348c5904e451e1e3b4dcd8cc8ec71bc6`
* **git status:**
```
Not currently on any branch.
nothing to commit, working tree clean
```
* **Diff status:** Verified 0 modified, 0 staged, 0 untracked files. Working tree is completely clean.

---

# AGY Hostile Plan Design Review for Issue #6744 (Plan Revision 12)

**Target Document:** `docs/research/6744-kimi-review-003/plan.md`  
**Base Revision:** `1f1325f3348c5904e451e1e3b4dcd8cc8ec71bc6`  
**Reviewer Identity:** Independent AGY Plan Reviewer

---

## 1. Executive Summary & Workstream Disposition Audit

Plan Revision 12 re-evaluates all 15 source claims (K003-01 through K003-16) and the unevidenced cohort (K003-C). The plan retains **13 independent live root causes** organized into Workstreams A through M:

* **Workstream A (K003-16):** Dedicated `vipWarningMu` isolating `vipWarnedIfaces` map operations from `directVIPMu`.
* **Workstream B (K003-07):** AST pre-walk validation rejecting empty security identities before scope normalization.
* **Workstream C (K003-13):** Pre-lowering SNMPv3 security intent validation with secret-redacted source observations and unified runtime evaluation (`EvaluateV3Users`).
* **Workstream D (K003-01):** Flowless ICMP global admission pass-through of parsed L4 type metadata.
* **Workstream E (K003-03):** Record-bound DDNS withdrawal matching exact same-family updater/`fpb1` anchors with classified co-owner claim release preceding delete authority.
* **Workstream F (K003-09):** Explicit, atomic classifier (`classifyOverride`) and parser for flat `set`/`deactivate` vs. hierarchical override loading.
* **Workstream G (K003-04):** Non-recursive structural AST validator (`ValidatePersistedTreeShape`) at `readTreeMeta` and `ReadConfirm` persistence boundaries plus compiler indexing guards.
* **Workstream H (K003-08):** Shared `pkg/config` prefix-list family expansion and saturating term-sequence cardinality calculator (`RouteMapTermSequenceCount`).
* **Workstream I (K003-10):** Preservation of control definition domain (0..255) while constraining explicit dataplane owner bindings (1..15) with clustered helper debt (`haInventoryDebt`), full-map ownership snapshot serials, and epoch-gated receiver-requested resync.
* **Workstream J (K003-06):** Union-merge compilation of repeated top-level and nested global `address-book` containers.
* **Workstream K (K003-11):** Transient netlink error classification (`isLinkNotFound`) preserving bond and tunnel routing ownership.
* **Workstream L (K003-14 / K003-15):** Explicit positive event allowlist (`eventHasForwardingAction`) centralizing lifecycle action applicability (`"n/a"`, `0xff`) across logging/API surfaces.
* **Workstream M (K003-05):** Rejection of unsupported nested `from-zone X { to-zone Y { ... } }` policy containers.

---

## 2. Deep-Dive Analysis of the Hostile Attack Vectors

### Attack Vector 1: Sender-Owned Config Generations vs. Canonical Cross-Peer Digest Identity

**Plan Anchors:** Plan lines 1927–2090, 2185–2191, 2336–2344, 2410–2457.

1. **Local Commits vs. Remote Epochs:**  
   The plan defines `senderConfigEpoch` as `{ generation uint64, digest [32]byte }`. Generation allocation is strictly local and sender-owned. `QueueCommittedConfig(record)` consumes `committedConfigRecord` where generation is allocated via `max(localCounter, committedConfig.epoch.generation) + 1`. Remote generations are recorded separately in `acceptedPeerConfigEpoch` upon successful peer apply and are **never** copied into the local outbound generation counter.
2. **Config-Sync-Disabled Identical Configs & Re-Sync:**  
   When `ConfigSyncEnabled` is `false`, nodes A and B commit identical canonical text locally (`digest D`), generating independent local generations ($G_A \neq G_B$). Type 29 resync messages (`{requestID, configGeneration, configDigest}`) exchange local sender epochs. The responder validates canonical digest equality against its local `committedConfigRecord` rather than comparing generations. Upon resync window completion and ACK precommit, the receiver stages the responder's peer-owned epoch ($G_B, D$) as its `acceptedPeerConfigEpoch`. Subsequent per-session install checks on Node A match $G_B$ against `acceptedPeerConfigEpoch.generation`.
3. **Same-Generation Replay & Different Generations:**  
   Replay of an already accepted exact tuple (`peerProcessID`, generation, digest) bypasses store mutation and acts as an idempotent transport baseline. Replay of an identical generation with a *different* digest is detected as protocol corruption and triggers transport retirement.
4. **SessionSync / Cluster-Comms Restarts & Counter Exhaustion:**  
   Process restart or cluster-comms restart generates a new random 16-byte `peerProcessID` and advances `transportEpoch`. Monotonic counters fail closed on `MaxUint64` and rotate the process ID rather than wrapping into ABA-susceptible values.

### Attack Vector 2: Local RG0..RG255 State Writers, Transitions, Heartbeats, & Zone Ownership

**Plan Anchors:** Plan lines 1064–1105, 1765–1926, 3239–3295.

1. **Mutation Boundary & Transition-Before-Raw Publication:**  
   All local RG state or definition changes must pass through `mutateLocalRGLocked` or `replaceLocalRGDefinitionsLocked`. Prior to mutating `rg.State` or publishing events, a complete desired ownership map is built and a new manager-wide serial is assigned with `Transitioning=true` under `Manager.mu`. Source canaries enforce zero direct `rg.State` writes or map mutations outside these boundaries.
2. **Heartbeat Advertisements:**  
   Heartbeat rows source their role from `RGAuthoritySnapshot.Committed`, **not** raw `rg.State`. During a transition, changed RGs continue advertising their *previous committed* role until local traffic fencing, gate staging, and final `PublishRGAuthority` compare-and-swap complete. Boot advertises `StateSecondaryHold`.
3. **Zone-Owner Derivation & Callback Transitions:**  
   Zone-to-RG mappings are derived via `zoneOwnersForCommittedConfig`. When a peer config callback runs `cluster.UpdateConfig` and returns an `RGMutationReceipt` for serial $S+1$, the callback records its outcome against predecessor serial $S$. `BeginOwnershipTransition` joins the callback before replacing the gate serial, staging $S+1$ with the callback's committed zone map.
4. **Dropped Event Recovery:**  
   The level-triggered safety net bypasses event stream gaps by directly reading the manager's level-triggered full snapshot (`Desired` vs. `Committed`).

### Attack Vector 3: `haInventoryTxnMu` / `Manager.mu` Ordering & Helper Status Leases

**Plan Anchors:** Plan lines 1177–1287, 3260–3280.

1. **Strict Lock Ordering:**  
   The lock hierarchy is strictly `haInventoryTxnMu -> Manager.mu`. Code never acquires `haInventoryTxnMu` while holding `Manager.mu`. Source canaries validate this edge and reject inverse lock orders.
2. **Status-Bearing Helper Requests & Leases:**  
   Helper requests returning `ProcessStatus` capture a `helperStatusLease` under `haInventoryTxnMu -> Manager.mu` before releasing state locks to perform bounded socket I/O. Response consumption re-acquires `haInventoryTxnMu -> Manager.mu` and validates that `processGeneration`, `snapshotGeneration`, `desiredInventoryGeneration`, `publishedInventoryGeneration`, and `debtGeneration` match. Stale or debt-crossing responses can update telemetry counters but are forced fail-closed and barred from executing `applyHelperControlStatusWithLeaseLocked`.
3. **Config Promotion & Actuator Serialization:**  
   Config promotion obeys `applySem -> haInventoryTxnMu -> Manager.mu`. Any older debt-mutating helper RPC must release `haInventoryTxnMu` before a new candidate can be promoted.

### Attack Vector 4: Worker Registries, Drains, Lifetime Leases, & Self-Join Prevention

**Plan Anchors:** Plan lines 1658–1764, 2110–2135.

1. **Worker Registry Handoff:**  
   Three distinct, non-reusable worker registries are established:
   * `lifetimeWorkers`: Accept loops, connect loops, config loop, notifier, lifecycle coordinator.
   * `setupWorkers[transportEpoch]`: Bounded handshakes/capability attempts.
   * `dataWorkers[transportEpoch]`: Receive/send loops, ACK workers, reconciliation, protocol callbacks.
   Setup handles atomically move from `setupWorkers` to `dataWorkers` under `s.mu` upon capability completion.
2. **Drains & Retirement:**  
   Single-fabric retirement closes connection-pinned handles while preserving transport-scoped config callbacks. Last-fabric loss marks the transport draining, closes/joins setup and data registries, advances `transportEpoch`, and clears continuity. The lifecycle coordinator is outside all worker sets, preventing self-join deadlocks.
3. **`clusterCommsEpoch` Lifecycle:**  
   Restart detaches the old epoch, closes registration, cancels contexts, and joins all handles without relying on a 5-second timeout-abandon escape hatch.

### Attack Vector 5: Fences, Barrier Membership, Tokens, & Readiness Ordering

**Plan Anchors:** Plan lines 1595–1635, 2384–2534.

1. **Write Fence (`writeMu`):**  
   Invalidations (config send/receive, disconnect, ownership change, Stop) acquire `writeMu` before invalidating tokens under `s.mu -> gate.mu`. ACK writers acquire `writeMu`, revalidate under state locks, release state locks, and execute network output.
2. **Barrier Membership & Token Fencing:**  
   Outbound bulks fence the union of used and current-live connections. Spurious, old, or cross-fabric ACKs are rejected. Capable BulkStart/BulkEnd/BulkAck carry 56-byte tokens (`{bulkEpoch, requestID, configGeneration, configDigest}`) requiring exact equality.
3. **Readiness Split & Outbox Ordering:**  
   `SetSyncReady` is split into validated session continuity vs. cold-start `electionTimeoutExpired` availability. Continuity transitions pass through `continuityPublishMu -> [writeMu ->] s.mu -> gate.mu` to reserve outbox slots before acquiring state locks, ensuring strict FIFO ordering across true/false edges via an ordered notifier worker.

### Attack Vector 6: Operational Completeness, Entrypoints, Canaries, & Tests

**Plan Anchors:** Plan lines 2725–3040, 3447–3510.

1. **Explicit Production Entrypoints:**  
   Every workstream defines exact function entrypoints and types (e.g., `validateNonEmptySecurityIdentities`, `prepareCompileView`, `updaterForOwnedWithdrawal`, `classifyOverride`, `ValidatePersistedTreeShape`, `RouteMapTermSequenceCount`, `ValidateDataplaneRGBindingID`, `mutateLocalRGLocked`, `SessionSyncAuthority`, `eventHasForwardingAction`, `validateSecurityPolicyContainerShapes`).
2. **Source Canaries & Fail-on-Revert Tests:**  
   Source canaries enforce structural invariants (forbidding raw `rg.State` assignments outside mutation helpers, un-leased callbacks, direct `vipWarnedIfaces` access, and bare `go On...` routines). Section 9.1 specifies fail-on-revert test strategies for all 13 workstreams.

---

## 3. Materiality Triage & Operational Assessment

* **Material Blockers Resolved in Revision 12:**
  * Canonical cross-peer digest identity vs. sender-owned generation scoping across config-sync-disabled, active-active, and reboot scenarios.
  * `haInventoryTxnMu` serialization preventing stale helper status responses from overwriting active inventory debt.
  * Strict two-phase ACK precommit and `writeMu` fencing preventing tail-frame drops and race conditions between invalidations and network I/O.
  * Worker registry isolation preventing self-join deadlocks and cross-epoch goroutine leakage.
* **Non-Blocker / Operational Notes:**
  * Operational rolling upgrades require manual pre-check of configuration files using `xpfd check-config -node-id 0/1` against source artifacts prior to deployment.
  * Low-severity findings K003-06 (address book) and K003-14/15 (log action formatting) remain bounded quality/observability fixes.

---

## 4. Final Verdict

Plan Revision 12 fully addresses all architectural, concurrency, protocol, operational, and security requirements without requiring the invention of missing invariants.

PLAN-READY
