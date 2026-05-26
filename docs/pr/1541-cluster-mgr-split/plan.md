# #1541 cluster manager split — plan

**Status:** DRAFT v3 — addresses Codex r2 PLAN-NEEDS-MAJOR and
Gemini r2 PLAN-NEEDS-MINOR (Gemini explicitly acknowledged the
r1 counter-example as resolved by v2).

**Round 2 outcomes:**
- Codex (task-mpmz1yi5-q7nath): PLAN-NEEDS-MAJOR. Finding:
  `handlePeerHeartbeat` still applies transfer-grace state
  (`peerTransferOutOverride`, `peerTransferCommitGraceUntil`)
  while rebuilding `newPeerGroups` (cluster.go:1516), so the
  "stale-heartbeat-content" invariant is NOT fully in failover.go.
  Fix: extract a failover.go-owned helper (e.g.
  `applyTransferCommitOverridesOnPeerStateLocked`) that
  `handlePeerHeartbeat` calls. This is the one allowed deviation
  from the "no method bodies edited" rule. Also one typo to fix
  (v2 said handlePeerHeartbeat where it meant handlePeerTimeout).
- Gemini (task-mpmz2j22-zfrgrf): PLAN-NEEDS-MINOR with explicit
  acknowledgment that round-1 PLAN-KILL counter-example is
  resolved. Two new findings: (a) `triggerGARP` is wrongly placed
  in `heartbeat_manager.go`; the L2 VIP-takeover invariant belongs
  in `garp.go` (where the burst sender already lives) or
  `election.go`; (b) `failover_batch.go` should merge into
  `failover.go` so that the entire manual-failover locking domain
  (single-RG + batch) is one file with shared `*Locked` helpers.

**v3 response:**
1. **Codex finding (transfer-grace-on-heartbeat smear).** Extract
   `applyTransferCommitOverridesOnPeerStateLocked(newPeerGroups,
   now)` as a new helper owned by `failover.go`.
   `handlePeerHeartbeat` calls it instead of inlining the override
   logic. This is the ONLY behavior-preserving extraction
   permitted by v3 — the helper body contains the exact same
   statements that lived inline in handlePeerHeartbeat, just
   relocated. No control-flow change, no field rename, no new
   allocation. The plan's "no method bodies edited" rule gains an
   explicit exception for "lift-then-call extractions when both
   reviewers identify the same locking-invariant smear" — this
   is the only one needed.
2. **Codex typo.** Fixed below — the cross-file call from
   heartbeat_manager.go to failover.go is `handlePeerTimeout` →
   `suppressPeerTimeoutForTransferCommitLocked`, not
   `handlePeerHeartbeat`.
3. **Gemini GARP finding.** `triggerGARP` moves to `garp.go`, not
   `heartbeat_manager.go`. It's a one-line `go sendGARP()` wrapper
   already adjacent to the burst sender code; co-locating it with
   `sendGARP` is the obvious home.
4. **Gemini failover-merge finding.** `failover_batch.go` merges
   into `failover.go`. The result is ~1000 LOC but the entire
   manual-failover and transfer-commit locking domain — single-RG
   AND batch — lives in one file with shared `*Locked` helpers.
   No more cross-file references to `applyPeerTransferOutOverrideLocked`
   / `clearPeerTransferOutOverrideLocked` /
   `restorePeerTransferOutOverrideLocked` /
   `transferCommitGracePeriodLocked` from a separate batch file.

**v1 → v2 round 1 outcomes (preserved for audit):**
- Codex r1 (task-mpmyrii6-pl9f0f): PLAN-NEEDS-MINOR (3 findings,
  all addressed in v2 or v3).
- Gemini r1 (task-mpmys3n8-wcaa7b): PLAN-KILL on transfer-commit
  smear; resolved in v2.

**Round 1 outcomes:**
- Codex (task-mpmyrii6-pl9f0f): PLAN-NEEDS-MINOR. Three findings:
  (1) transfer-out override + grace helpers are assigned to the
  wrong homes; they belong in `failover.go`, not split between
  `peer_state.go` and `heartbeat_manager.go`; (2) method count is
  64 across the package, not 61 (3 batch methods in
  `failover_batch.go` were not counted in v1); (3) `pkg/cluster/
  README.md` currently names `cluster.go` as the home for several
  types and needs a touch.
- Gemini (task-mpmys3n8-wcaa7b): PLAN-KILL with a concrete
  counter-example: the "committed-failover-suppresses-stale-
  heartbeat" invariant under v1 forces a reviewer to walk
  `failover.go` → `peer_state.go` → `heartbeat_manager.go` while
  carrying `m.mu` write-lock context. Gemini argues this
  *increases* cognitive load.

**v2 response:** Codex's finding #1 and Gemini's PLAN-KILL
counter-example are the same problem. Fix: put the entire
transfer-commit state machine in `failover.go`. After v2,
`handlePeerHeartbeat` (in `heartbeat_manager.go`) just *calls*
`suppressPeerTimeoutForTransferCommitLocked` (defined in
`failover.go`); it doesn't own any transfer-commit state. The
"how does a committed failover suppress a stale heartbeat"
invariant is now answerable by reading `failover.go` end-to-end —
exactly one file, exactly one locking domain. Method count
corrected to 64. README to be updated as part of the PR.

## 1. Issue framing

`pkg/cluster/cluster.go` is 2429 LOC and owns many independent HA
concerns in one `Manager` file:

- redundancy-group state and readiness gates
- election and peer-loss handling (`electSingleNode`, `recalcWeight`,
  `SetMonitorWeight`)
- heartbeat send/receive lifecycle (`StartHeartbeat`, `StopHeartbeat`,
  `RestartHeartbeat`, `buildHeartbeat`, `handlePeerHeartbeat`,
  `handlePeerTimeout`, `handlePeerNeverSeen`, `HeartbeatStats`)
- manual failover and transfer commit protocol (`ManualFailover`,
  `RequestPeerFailover`, `commitRequestedPeerFailover`,
  `abortRequestedPeerFailover`, `FinalizePeerTransferOut`,
  `ForceSecondary`, `ResetFailover`, transfer-out override helpers)
- peer fencing hooks and event history
- sync stats projection (`SetSyncStats`, `GetSyncStats`,
  `IsSyncConnected`)
- CLI/status renderers (`FormatStatus`, `FormatInformation`,
  `FormatStatistics`, `FormatControlPlaneStatistics`,
  `FormatDataPlaneStatistics`, `FormatDataPlaneInterfaces`,
  `FormatIPMonitoringStatus`, `FormatInterfaces`)
- interface monitor status formatting

The issue (#1541) asks to split this into domain-cohesive modules
while keeping the public API stable.

## 2. Honest scope/value framing

This is a **pure code-motion refactor** — no behaviour changes, no
API changes, no new types. Every public method on `*Manager` stays
exported with the same signature, semantics, locking shape, and
goroutine ownership.

The win is **maintainability and review surface**: cluster.go is
correctness-critical HA code where a missing transition or split-
brain edge case causes outages. Reviewers currently have to navigate
2429 lines and 77 methods spanning eight concerns to evaluate any
one HA invariant. Splitting along the natural domain seams — already
established in-repo by `election.go`, `heartbeat.go`,
`failover_batch.go`, `events.go`, `sync*.go`, `monitor.go`, `reth.go`
— makes the locking scope and state-transition responsibility of
each method obvious at a glance.

There is **no runtime perf claim**. The heartbeat tick and VRRP
advertisement allocation rules are preserved trivially because the
move does not add any new allocations on those paths.

If reviewers conclude the maintainability gain is too small to
justify the churn, PLAN-KILL is an acceptable verdict.

## 3. What's already shipped / partially batched

The package already has substantial domain-split files:

- `election.go` (279 LOC) — `EffectivePriority`, `electRG`,
  `runElection`. Tests in `election_test.go` (917 LOC).
- `heartbeat.go` (474 LOC) — `HeartbeatPacket`,
  `MarshalHeartbeat`/`UnmarshalHeartbeat`, `heartbeatSender`,
  `heartbeatReceiver` goroutines, `normalizeHAProtocolVersion`.
  Tests in `heartbeat_test.go` (544 LOC).
- `failover_batch.go` (369 LOC) — multi-RG failover variants of the
  manual/transfer/commit protocol. *Folded into the new `failover.go`
  in v3 per Gemini r2 (shared `*Locked` state with single-RG).*
- `events.go` (101 LOC) — `EventCategory`, `HistoryEvent`,
  `EventHistory`, drop counters.
- `monitor.go` (491 LOC) — `Monitor` netlink-driven monitor.
- `reth.go` (178 LOC) — RETH MAC/VIP helpers.
- `garp.go` (571 LOC) — gratuitous ARP burst sender.
- `runtime.go` (33 LOC) — currently a small `dataplane` interface and
  one helper.

What's NOT yet split (the residual 2429 LOC in `cluster.go`):

- Manager struct definition + types (`NodeState`,
  `RedundancyGroupState`, `ClusterEvent`,
  `RetryablePreFailoverError`, `monitorKey`, `peerGroupSnapshot`).
- `NewManager` + lifecycle (`Start`, `Stop`, `sendEvent`,
  `SetOnEventDrop`, `Events`, `Monitor`, `NodeID`, `ClusterID`).
- Manager-level heartbeat orchestration that owns the goroutines
  (`StartHeartbeat`, `StopHeartbeat`, `RestartHeartbeat`,
  `buildHeartbeat`, `handlePeerHeartbeat`, `handlePeerTimeout`,
  `handlePeerNeverSeen`, `vrfListenConfig`, `HeartbeatStats`,
  `triggerGARP`).
- Manual failover protocol entry points
  (`ManualFailover`, `ForceSecondary`, `ResetFailover`,
  `RequestPeerFailover`, `commitRequestedPeerFailover`,
  `abortRequestedPeerFailover`, `notePeerTransferCommitted`,
  `FinalizePeerTransferOut`, `FenceStatus`,
  `applyPeerTransferOutOverrideLocked`,
  `clearPeerTransferOutOverrideLocked`,
  `restorePeerTransferOutOverrideLocked`,
  `transferCommitGracePeriodLocked`,
  `suppressPeerTimeoutForTransferCommitLocked`).
- Readiness gate (`SetRGReady`, `IsReadyForTakeover` method on
  `RedundancyGroupState`).
- Election helpers that talk to Manager state (`electSingleNode`,
  `SetMonitorWeight`, `recalcWeight`, `LocalPriorities`).
- RG state accessors (`GroupStates`, `DataGroupIDs`, `GroupState`,
  `IsLocalPrimary`, `IsLocalPrimaryAny`, `UpdateConfig`).
- Hooks (`SetPreManualFailoverHook`, `SetTransferReadinessFunc`,
  `SetLocalTransferCommitReadyHook`, `SetPeerFailoverFunc`,
  `SetPeerFailoverCommitFunc`, `SetPeerFailoverBatchFunc`,
  `SetPeerFailoverCommitBatchFunc`, `SetPeerFenceFunc`,
  `SetPeerTimeoutGuard`).
- Peer state accessors (`PeerAlive`, `PeerNodeID`, `PeerGroupStates`,
  `SetSoftwareVersion`, `SoftwareVersions`, `SetHAProtocolVersion`,
  `HAProtocolVersions`, `HAProtocolVersionMismatch`,
  `PeerMonitorStatuses`).
- Sync stats projection (`SetSyncReady`, `IsSyncReady`,
  `SetSyncTransport`, `SyncTransport`, `SetSyncStats`,
  `GetSyncStats`, `IsSyncConnected`).
- Event recording (`RecordEvent`, `EventHistoryFor`).
- All status formatting (`FormatStatus`, `FormatInformation`,
  `FormatStatistics`, `FormatControlPlaneStatistics`,
  `FormatDataPlaneStatistics`, `FormatDataPlaneInterfaces`,
  `FormatIPMonitoringStatus`, `FormatInterfaces`).

The split builds on the existing pattern (sibling files in
`package cluster`) rather than introducing sub-packages. Sub-packages
would require either exporting a great deal of currently-private
Manager state or creating shim accessors, which is gratuitous churn
for a refactor whose only goal is review-surface reduction.

## 4. Concrete design

Wave-2 rules require: sibling `.go` files in `pkg/cluster/`, NOT
`cluster_election.go` prefix; one slim entry file.

### 4.1 File layout after split

```
pkg/cluster/
  manager.go              # Manager struct, NewManager, types
                          #  (NodeState, RedundancyGroupState,
                          #   ClusterEvent, RetryablePreFailoverError,
                          #   monitorKey, peerGroupSnapshot), lifecycle
                          #  (Start, Stop, sendEvent, SetOnEventDrop,
                          #   Events, Monitor, NodeID, ClusterID,
                          #   constants).
  hooks.go                # Set*Hook / Set*Func methods.
  peer_state.go           # PeerAlive, PeerNodeID, PeerGroupStates,
                          #   software/protocol version accessors,
                          #   PeerMonitorStatuses. (NO transfer-out
                          #   override helpers — those live in
                          #   failover.go alongside the protocol they
                          #   serve. v2 fix for r1 Codex finding #1 +
                          #   Gemini PLAN-KILL counter-example.)
  group_state.go          # RedundancyGroupState accessors:
                          #   GroupStates, DataGroupIDs, GroupState,
                          #   IsLocalPrimary, IsLocalPrimaryAny,
                          #   UpdateConfig, LocalPriorities.
  readiness.go            # SetRGReady, IsReadyForTakeover method.
  sync_state.go           # SetSyncReady, IsSyncReady,
                          #   SetSyncTransport, SyncTransport,
                          #   SetSyncStats, GetSyncStats,
                          #   IsSyncConnected.
  election.go             # (existing) + electSingleNode,
                          #   SetMonitorWeight, recalcWeight moved in.
  heartbeat.go            # (existing) — wire format / sender / receiver
                          #   stays. Manager-orchestration methods move
                          #   to a new file (see below).
  heartbeat_manager.go    # NEW — Manager methods that own heartbeat
                          #   goroutines: StartHeartbeat, StopHeartbeat,
                          #   RestartHeartbeat, buildHeartbeat,
                          #   handlePeerHeartbeat, handlePeerTimeout,
                          #   handlePeerNeverSeen, vrfListenConfig,
                          #   HeartbeatStats.
                          #   (Transfer-commit state machine is NOT
                          #   here — see failover.go. handlePeerTimeout
                          #   calls suppressPeerTimeoutForTransferCommitLocked
                          #   from failover.go; handlePeerHeartbeat calls
                          #   applyTransferCommitOverridesOnPeerStateLocked
                          #   from failover.go to apply transfer-out
                          #   overrides while rebuilding newPeerGroups.
                          #   Both are package-private cross-file calls.
                          #   triggerGARP is NOT here — see garp.go.
                          #   v3 fixes for Codex r2 PLAN-NEEDS-MAJOR
                          #   and Gemini r2 GARP misplacement.)
  failover.go             # NEW — single-RG and multi-RG (batch)
                          #   manual failover protocol AND the
                          #   transfer-commit state machine. v3 folds
                          #   failover_batch.go into this file per
                          #   Gemini r2: the entire manual-failover
                          #   locking domain (single-RG + batch +
                          #   transfer-commit *Locked helpers) lives
                          #   in one file. Methods:
                          #   - Manual failover (single-RG):
                          #     ManualFailover, ForceSecondary,
                          #     ResetFailover.
                          #   - Manual failover (batch, from former
                          #     failover_batch.go): ManualFailoverBatch,
                          #     IsSupportedClusterNodeID,
                          #     normalizeFailoverRGIDs,
                          #     failoverBatchKey.
                          #   - Transfer protocol (single-RG):
                          #     RequestPeerFailover,
                          #     commitRequestedPeerFailover,
                          #     abortRequestedPeerFailover,
                          #     notePeerTransferCommitted,
                          #     FinalizePeerTransferOut, FenceStatus.
                          #   - Transfer protocol (batch, from former
                          #     failover_batch.go):
                          #     RequestPeerFailoverBatch,
                          #     commitRequestedPeerFailoverBatch,
                          #     abortRequestedPeerFailoverBatch,
                          #     notePeerTransferCommittedBatch,
                          #     FinalizePeerTransferOutBatch.
                          #   - Transfer state *Locked helpers:
                          #     applyPeerTransferOutOverrideLocked,
                          #     clearPeerTransferOutOverrideLocked,
                          #     restorePeerTransferOutOverrideLocked,
                          #     transferCommitGracePeriodLocked,
                          #     suppressPeerTimeoutForTransferCommitLocked.
                          #   - NEW v3 extraction (Codex r2 fix):
                          #     applyTransferCommitOverridesOnPeerStateLocked(
                          #       newPeerGroups map[int]PeerGroupState,
                          #       now time.Time)
                          #     called from heartbeat_manager.go::handlePeerHeartbeat.
                          #     Body lifted verbatim from the inline override
                          #     application loop in handlePeerHeartbeat
                          #     (current cluster.go:1505-1520 region). The
                          #     lift is a single behavior-preserving
                          #     extraction; no control-flow or field-access
                          #     changes.
  garp.go                 # (existing 571 LOC, unchanged body) — now
                          #   also gets triggerGARP method moved in from
                          #   cluster.go. triggerGARP is the
                          #   `go sendGARP(...)` wrapper that
                          #   election.go and failover.go fire to
                          #   broadcast L2 takeover, so co-locating it
                          #   with sendGARP (the burst sender it wraps)
                          #   keeps the L2 takeover invariant in one
                          #   file. v3 fix for Gemini r2 GARP misplacement.
  events_log.go           # RecordEvent, EventHistoryFor.
                          #   (events.go holds types + EventHistory
                          #   struct; these are Manager methods.)
  status.go               # ALL Format* methods.
  ... (existing reth.go, garp.go, sync*.go, monitor.go,
       failover_batch.go, events.go, runtime.go unchanged)
```

### 4.2 Mechanical move discipline

This is **pure code motion**. The rules:

1. Every function moves verbatim — same body, same signature, same
   receiver, same doc comment.
2. No method bodies are edited during the move. If a method needs
   fixing, it is fixed in a follow-up PR.
   **Exception (v3, Codex r2):** ONE lift-extraction is permitted:
   the inline transfer-out-override application loop in
   `handlePeerHeartbeat` (cluster.go:1505-1520 region) is hoisted
   to a new method
   `applyTransferCommitOverridesOnPeerStateLocked(newPeerGroups
   map[int]PeerGroupState, now time.Time)` owned by `failover.go`.
   The hoisted statements are byte-for-byte the same; only the
   enclosing function changes. This is the minimum behavior-
   preserving extraction that closes Codex's r2 finding (and
   Gemini's r1 counter-example fully). No other method bodies
   are touched.
3. No new types are introduced. No fields are added or removed on
   `Manager`. No locking is changed.
4. Imports are pruned per-file to satisfy `goimports`, but no new
   third-party imports are introduced.
5. The `package cluster` declaration stays. External callers
   (`cluster.NewManager`, `*cluster.Manager`, `cluster.NodeState`,
   `cluster.RedundancyGroupState`, etc.) see no change.
6. Tests stay in their current files. No test file is moved or
   renamed in this PR.

### 4.3 Why not sub-packages

The issue prose mentions `pkg/cluster/election/` and friends as a
"preferred shape." Wave-2 explicitly overrides this — *"NO
`cluster_election.go` prefix anti-pattern. Keep one slim entry file
`pkg/cluster/cluster.go` or `pkg/cluster/manager.go` with the
lifecycle glue. Split into sibling `.go` files."* Sub-packages would
require:

- Exporting `Manager` private fields (peerAlive, peerEverSeen,
  peerGroups, peerTransferOutOverride, peerTransferCommitGraceUntil,
  localTransferOutHoldUntil, groups, monitorWeights, mu, etc.) so
  sub-package code can reach them, OR
- Building shim accessors on `Manager` for every reachable field,
  which is exactly the kind of churn the issue is trying to avoid.

Either approach defeats the purpose of an internal refactor. The
sibling-file layout gets the review-surface win without touching the
package boundary or the external API.

## 5. Public API preservation

Every public symbol stays in `package cluster` with the same name,
type, signature, and semantics. Concretely, all of these continue
to resolve identically:

- Types: `Manager`, `NodeState`, `RedundancyGroupState`,
  `ClusterEvent`, `RetryablePreFailoverError`, `HeartbeatPacket`,
  `HeartbeatStats`, `Monitor`, `InterfaceMonitorInfo`,
  `PeerGroupState`, `SyncStatsProvider`, `SyncStatsSnapshot`,
  `HistoryEvent`, `EventCategory`, `EventHistory`,
  `InterfacesInput`.
- Constants: `StateSecondary`, `StatePrimary`, `StateSecondaryHold`,
  `StateLost`, `StateDisabled`, `DefaultTakeoverHoldTime`,
  `DefaultPreManualFailoverRetryTimeout`,
  `DefaultPreManualFailoverRetryInterval`.
- Constructor: `NewManager(nodeID, clusterID int) *Manager`.
- Free functions: `IsRetryablePreFailoverError`,
  `IsSupportedClusterNodeID`, `MarshalHeartbeat`,
  `UnmarshalHeartbeat`, `EffectivePriority`.
- All 64 exported `*Manager` methods in `pkg/cluster/` keep their
  current signatures: 61 currently defined in `cluster.go` plus
  3 currently in `failover_batch.go`
  (`ManualFailoverBatch`, `RequestPeerFailoverBatch`,
  `FinalizePeerTransferOutBatch`). After v3, all 64 are still
  exported with identical signatures, just from new file homes.
  The v3-introduced helper
  `applyTransferCommitOverridesOnPeerStateLocked` is **private**
  (lowercase) and so does not touch the public API surface.

`go test ./pkg/...` will reveal any accidental signature drift
immediately.

## 6. Hidden invariants the change must preserve

1. **Locking shape.** `m.mu` is the single `sync.RWMutex` guarding
   `groups`, `monitorWeights`, peer-state fields, and timer state.
   Every `*Locked` helper assumes the caller already holds `m.mu`
   write-locked. Moving these helpers to another file does not
   change the calling protocol; reviewers should verify each moved
   `*Locked` helper still has the same set of callers, all of which
   still hold the lock.
2. **Goroutine ownership.** `hbSender`, `hbReceiver`, the
   per-RG `holdTimer`, and the GARP burst goroutine are all
   started/stopped from specific Manager methods. After the move,
   `StartHeartbeat`/`StopHeartbeat`/`RestartHeartbeat` still own
   `hbSender`/`hbReceiver` lifecycle; `triggerGARP` still spawns
   the burst goroutine. No method changes who owns what.
3. **Event channel ordering.** `sendEvent` is the single writer to
   `eventCh`. Reviewers should verify all callers of `sendEvent`
   continue to call the same function (move does not change the
   call sites, only the file containing the function body).
4. **`RetryablePreFailoverError` semantics.** `IsRetryablePreFailoverError`
   is a free function in cluster.go. It must stay exported and behave
   identically. Moving its definition to manager.go preserves
   semantics; moving the body unchanged means `errors.As` continues
   to resolve correctly.
5. **HA wire protocol stability.** The heartbeat wire format
   (`MarshalHeartbeat`/`UnmarshalHeartbeat`) and the transfer-commit
   grace constants stay byte-for-byte identical. No new fields, no
   reordering. Mixed-version clusters where one node has the split
   and the other does not must remain wire-compatible (and they
   are — wire code lives in `heartbeat.go` and is untouched).
6. **No new allocation on the 200ms heartbeat tick.** `buildHeartbeat`
   constructs a `HeartbeatPacket` per tick (already true today). The
   move keeps the same allocation profile.
7. **No new allocation on the 30ms VRRP advertisement tick.** VRRP
   lives in `pkg/vrrp/`, not `pkg/cluster/`. Cluster code does not
   touch the VRRP send path on this PR.
8. **`mu` write-lock holders never call format/render code.** The
   `Format*` family currently takes `m.mu.RLock()` internally.
   Moving them to status.go does not change this. Reviewers should
   verify no other moved method now reaches into a `Format*` while
   already holding `mu`.

## 7. Risk assessment

| Class                              | Level | Notes                                                              |
| ---------------------------------- | ----- | ------------------------------------------------------------------ |
| Behavioral regression risk         | LOW   | Pure code motion. `go test ./pkg/cluster/...` is the canary.       |
| Lifetime / borrow-checker risk     | N/A   | Go, not Rust. No lifetime concerns.                                |
| Performance regression risk        | LOW   | No path-of-execution change. No allocations added.                 |
| Architectural mismatch risk        | LOW   | Sibling-file split is the established in-repo pattern (eight       |
|                                    |       | existing sibling files in pkg/cluster/ already). Not a #946        |
|                                    |       | Phase-2-style architectural pitch.                                 |
| Locking-invariant drift            | LOW   | No method bodies edited; lock acquisition lines unchanged.         |
| Test coverage drift                | LOW   | Tests stay where they are; no test file renamed.                   |
| Build-tag / compile-time invariant | LOW   | Move stays inside `package cluster`; no new build tags.            |
| Merge conflict risk vs other PRs   | MED   | #1518 (session-sync interface migration) touches sync*.go files we |
|                                    |       | are NOT moving. As long as we don't touch sync_failover.go, sync_  |
|                                    |       | bulk.go, sync_protocol.go, sync_conn.go, or sync.go, there should  |
|                                    |       | be no overlap. Plan explicitly excludes them.                      |

## 8. Test plan

1. **Pre-move baseline.** `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go
   test ./pkg/cluster/... -count=1` already passes on master
   (verified above).
2. **Per-file move.** After each file extraction, run
   `go build ./...` and `go vet ./pkg/cluster/...`. Resolve any
   compile error immediately. Do not batch broken intermediate
   states.
3. **Full Go suite.** `go test ./... -count=1` after all moves
   complete. 30+ packages must pass.
4. **`pkg/cluster` 5x flake check** on the largest test files:
   `cluster_test.go`, `sync_test.go`, `election_test.go`,
   `heartbeat_test.go`, `monitor_test.go`. Run each 5x to confirm
   no timing-sensitive regression introduced by file reordering.
5. **HA-sensitive smoke** — per Wave-2 §2 + [[feedback_smoke_every_10_batch]],
   HA-touching PRs run the full `make test-failover` cluster gate
   in addition to the iperf3 smoke matrix. PR-smoke marker is
   `<!-- AWAITING-SMOKE -->\nScope: smoke-plus-test-failover`.
6. **iperf3 smoke matrix** on `loss:xpf-userspace-fw0/fw1`:
   - Pass A (CoS disabled): v4+v6 × push+reverse single-stream
     + 12-stream reverse reproducer v4 and v6.
   - Pass B (CoS enabled): per-class ports 5201-5206 × v4+v6 ×
     push+reverse.
7. **HA failover** — `make test-failover` (manual failover during
   iperf3, verify zero-drop and ~60ms cutover).

## 9. Out of scope (explicitly)

- No sub-package introduction. `pkg/cluster/election/`,
  `pkg/cluster/failover/`, etc. are explicitly NOT done in this PR
  per Wave-2 sibling-file rule.
- No method body edits, no signature changes, no field
  additions/removals.
- No test file moves or renames.
- Documentation: this plan, `_Log.md`, and a minimal touch to
  `pkg/cluster/README.md` to update the "Files" section so it
  no longer claims `cluster.go` is the home for `Manager` /
  `NodeState` / `ClusterEvent`. No other doc churn.
- No `pkg/cluster/sync*.go` touches — those are #1518's territory.
- No `pkg/vrrp/` changes.

## 10. Open questions for adversarial review

1. **Is the sibling-file layout actually the right shape, or should
   we accept the issue's preferred sub-package layout?** Wave-2 says
   sibling files; the issue says sub-packages. The plan picks Wave-2.
   PLAN-KILL is appropriate if reviewers think the issue's intent
   (sub-packages with documented locking boundaries) is being
   subverted.

2. **`heartbeat_manager.go` vs extending `heartbeat.go`.** The
   existing `heartbeat.go` (474 LOC) holds wire format + goroutine
   types. The Manager-orchestration methods (~250 LOC of
   `StartHeartbeat`/`StopHeartbeat`/`buildHeartbeat`/handlers) could
   either go in a new `heartbeat_manager.go` or be appended to
   `heartbeat.go`. Plan chooses the new file to keep wire-format
   code clearly separate from Manager-coupled orchestration. Is
   this the right call?

3. **`failover.go` vs renaming `failover_batch.go`.** Single-RG
   manual failover and multi-RG batch failover share state
   (`failoverInProgress`, `peerTransferOutOverride`,
   `peerTransferCommitGraceUntil`). Plan keeps them in two files
   on the principle that the batch protocol is functionally an
   independent algorithm (multi-RG ordering, batch-key, partial
   commit/abort) that just happens to share state. Should they be
   merged into one larger `failover.go` instead?

4. **`group_state.go` vs `manager.go`.** Several
   small accessors (`NodeID`, `ClusterID`, `IsLocalPrimary`,
   `IsLocalPrimaryAny`, `GroupState`, `GroupStates`,
   `DataGroupIDs`, `UpdateConfig`, `LocalPriorities`) are
   all about reading/updating RG state. Plan puts them in
   `group_state.go` because `UpdateConfig` alone is ~90 LOC of
   non-trivial logic. Alternative: collapse into manager.go.

5. **Could this trigger a #946-Phase-2-style architectural mismatch?**
   The risk is: if HA invariants tie multiple "domains" together
   (e.g., heartbeat handler must touch failover state must touch
   election must touch status), then the split is cosmetic at best
   and obscures the dependency. Reviewers should walk the most
   complex method (probably `handlePeerHeartbeat` or
   `RequestPeerFailover`) and confirm the cross-file references
   in the post-split layout don't make the code harder to follow,
   not easier.

6. **Does pure code-motion actually deliver the maintainability
   claim?** Or does the residual cross-file coupling (`m.mu`
   write-locked across method calls in different files) defeat
   the win?

7. **Is "no new allocation on heartbeat tick" verifiable by
   inspection of the moved code, or does it require a benchmark?**
   Plan position: by inspection, because `buildHeartbeat` is
   moved verbatim. PLAN-NEEDS-MAJOR if a reviewer thinks a
   measurement is required.

8. **What about the merge-conflict risk vs #1518?** The plan
   explicitly does not touch sync*.go. Is that sufficient, or
   should we coordinate the merge order?
