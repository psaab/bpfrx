# HA Failover Implementation Plan

Date: 2026-04-02

Related docs:

- [ha-failover-simplification-audit.md](./ha-failover-simplification-audit.md)
- [ha-simple-failover-design.md](./ha-simple-failover-design.md)
- [session-sync-architecture.md](./session-sync-architecture.md)
- [flow-cache-simplification.md](./flow-cache-simplification.md)
- [userspace-forwarding-and-failover-gap-audit.md](./userspace-forwarding-and-failover-gap-audit.md)

Related issues:

- #314
- #315
- #316
- #317
- #319
- #321
- #323
- #338
- #339
- #340
- #341
- #342
- #344
- #345
- #347
- #348
- #349
- #358
- #359
- #360
- #389
- #390
- #391

## Goal

Reduce userspace HA failover to this:

1. session state is already present on both nodes
2. the standby is already forwarding-ready
3. cutover is one explicit ownership transfer
4. after cutover:
   - move MAC ownership
   - send GARP / gratuitous NA
   - keep forwarding

## Why Current Failover Is Still Hard

Current `master` still spreads failover correctness across multiple state
machines:

- cluster election and `ManualFailover`
- session-sync bulk / barrier / ack state
- helper `update_ha_state`
- helper activation / demotion apply work
- activation-time reverse/session refresh
- ctrl / XSK liveness and fallback logic
- neighbor / fabric warm-up side effects

The core problem is not that sessions are unsynced. The core problem is that
"session synced" is not the same thing as "new owner can forward now".

## Required End-State Invariants

These invariants must be true before failover can become simple:

1. there is one portable canonical session record replicated across nodes
2. each node continuously derives local forwarding-ready runtime state from it
3. flow cache is disposable and never part of cutover correctness
4. standby RX/TX readiness is established before takeover-ready becomes true
5. cutover is acknowledged as one applied generation, not inferred from idle
   queues, barriers, and side effects
6. manual failover is an explicit transfer protocol, not an election hack

## Current Root Causes

### 1. Manual failover is expressed indirectly

Current manual failover still works by mutating election state:

- [cluster.go](../pkg/cluster/cluster.go) `ManualFailover()`
- [election.go](../pkg/cluster/election.go)

It sets `ManualFailover=true`, drives local weight to `0`, and relies on peer
election to make ownership move. That forces time guards and cleanup logic to
avoid dual-secondary and self-repromotion behavior.

Issue:

- #389 Replace weight-zero manual failover with an explicit RG transfer protocol

### 2. Activation still starts dataplane work

Current RG activation still triggers:

- helper HA state update
- FIB generation bump
- NAPI bootstrap
- proactive neighbor resolution

Files:

- [manager_ha.go](../pkg/dataplane/userspace/manager_ha.go)
- [manager.go](../pkg/dataplane/userspace/manager.go)

That means the standby is not assumed RX-ready and forwarding-ready before
cutover.

Issues:

- #344
- #347
- #391

### 3. Helper HA apply still repairs state at cutover

The helper still performs activation or demotion work that depends on session
table walks or alias rebuilds:

- [ha.rs](../userspace-dp/src/afxdp/ha.rs)
- [session_glue.rs](../userspace-dp/src/afxdp/session_glue.rs)

That means cutover is still a "repair then forward" model.

Issues:

- #358
- #359
- #390

### 4. Session sync is continuous, but forwarding readiness is not

Current sync still leaves gaps that must be repaired or reconstructed:

- `local_delivery` is still special
- reverse companion handling is still special
- local egress resolution is still local-only
- fabric and neighbor state still arrive asynchronously

Issues:

- #315
- #316
- #317
- #319
- #345
- #348

### 5. Cutover still depends on transport choreography

Graceful demotion still depends on:

- bulk sync priming
- barrier ack state
- event-stream producer behavior
- helper apply timing

Files:

- [sync.go](../pkg/cluster/sync.go)
- [daemon.go](../pkg/daemon/daemon.go)

Issues:

- #323
- #338
- #339
- #340
- #341
- #342

## Simpler Architecture

The simpler model has four layers.

### Layer 1: Explicit RG Ownership Transfer

There should be one transfer protocol:

1. source proposes transfer of RG `N` to target node
2. target proves readiness for generation `G`
3. both sides apply generation `G`
4. ownership changes
5. MAC movement and GARP / GNA happen

Election remains for health arbitration and peer loss only.

### Layer 2: Canonical Session Replication

Cross-node sync should carry only portable session intent:

- flow identity
- NAT state
- owner RG
- direction and reverse identity
- logical egress identity
- timeout / TCP state

It should not carry peer-local resolved forwarding artifacts.

### Layer 3: Continuous Local Materialization

Both nodes should continuously derive:

- local rewrite descriptor
- local egress decision
- reverse companion
- translated aliases
- owner-RG-local indexes

The standby should already have all of this before cutover.

### Layer 4: Disposable Cache

Flow cache should only store:

- local decision identity
- rewrite descriptor
- validation epochs

On mismatch, it misses and rebuilds from already-materialized local runtime
state. It must never require failover-time scans or explicit repair.

## Implementation Phases

### Phase 0: Define The Cutover Contract

Goal:

- make "failover succeeded" mean one thing

Deliverables:

- define one HA apply generation acknowledged by helper workers
- define readiness conditions for takeover that include dataplane readiness,
  not just sync transport
- stop treating transport barrier state and helper apply state as independent
  notions of readiness

Primary issues:

- #323
- #338
- #339
- #340
- #341
- #342

Dependency:

- none; this is the prerequisite for all later phases

Exit criteria:

- one documented generation fence for cutover
- one status surface that says whether generation `G` is applied

### Phase 1: Remove Election Tricks From Manual Failover

Goal:

- make manual failover an explicit transfer, not a weight mutation

Deliverables:

- replace `ManualFailover -> Weight=0` logic with target-owner transfer
- remove time-based dual-resign escape logic from normal manual cutover
- keep election-based promotion only for peer loss / health arbitration

Primary issue:

- #389

Dependencies:

- Phase 0

Exit criteria:

- manual failover does not rely on election side effects to move ownership

### Phase 2: Make Standby Continuously Forwarding-Ready

Goal:

- eliminate activation-time session repair as the normal path

Deliverables:

- continuous local materialization of reverse companions and aliases
- continuous local egress re-resolution from canonical session state
- include all forwarding-relevant classes in continuous sync, including
  `local_delivery` if it is required for cutover correctness

Primary issues:

- #315
- #316
- #317
- #319
- #345

Dependencies:

- Phase 0

Exit criteria:

- new owner does not need RG-wide session refresh scans to become forwarding-ready

### Phase 3: Index HA State By Owner RG

Goal:

- remove full-table scans from the failover path

Deliverables:

- derived helper indexes keyed by owner RG
- demotion and activation operate on affected RG indexes only
- alias stores and reverse companion stores participate in those indexes

Primary issue:

- #390

Secondary issue:

- #321

Dependencies:

- Phase 2

Exit criteria:

- failover work scales with changed RGs, not total session count

### Phase 4: Remove Startup/Warm-Up Work From Cutover

Goal:

- cutover must not start dataplane startup procedures

Deliverables:

- remove NAPI bootstrap from `UpdateRGActive()`
- make queue RX-liveness part of readiness before takeover
- make neighbor and fabric readiness continuous background state, not post-cutover repair

Primary issues:

- #344
- #347
- #348
- #349
- #391

Dependencies:

- Phase 2

Exit criteria:

- activation no longer calls startup-style dataplane warm-up helpers

### Phase 5: Simplify Helper HA Runtime To One Lease/Generation Model

Goal:

- packet-time HA behavior should consult one runtime model

Deliverables:

- one lease / generation validity model
- no separate reasoning across active bit, watchdog freshness, and transition flags
- packet path gates on one helper truth: "this RG is forwarding-active for generation G"

Primary issues:

- #358
- #359
- #360

Dependencies:

- Phase 0
- Phase 2

Exit criteria:

- helper packet-time HA checks are driven by one runtime concept

## Dependency Graph

Recommended execution order:

1. Phase 0
2. Phase 1 and Phase 5
3. Phase 2
4. Phase 3
5. Phase 4

Rationale:

- Phase 0 defines the cutover contract the rest of the system must obey
- Phase 1 removes election-induced ambiguity from ownership transfer
- Phase 5 removes duplicate helper HA state models
- Phase 2 makes the standby actually ready before transfer
- Phase 3 removes failover-time scans once the runtime state is continuous
- Phase 4 removes remaining warm-up side effects from cutover

## What We Should Not Do

Do not simplify by:

- syncing raw peer-local ifindex / MAC results and pretending they are portable
- making flow cache more authoritative
- adding more failover-time repair scans
- relying on post-cutover neighbor warm-up to make first packet succeed
- using election heuristics to express normal manual transfer intent

Those approaches preserve the current fragility.

## Acceptance Criteria

The end-state should satisfy all of these:

1. manual RG failover under `iperf3 -P 8` does not require activation-time
   session repair scans to keep traffic flowing
2. hard-crash takeover works without separate "recovery mode" behavior in the
   helper
3. split-RG active/active failover works without RG-wide session rescans
4. first packet after cutover does not depend on ad hoc neighbor warm-up
5. the helper status can prove:
   - current applied HA generation
   - forwarding-ready status per RG
   - no activation-time repair backlog

## Immediate Next Steps

The next implementation slice should be:

1. Phase 0 cutover contract
2. Phase 1 explicit RG transfer
3. Phase 4 removal of NAPI bootstrap from `UpdateRGActive()`

That combination gives the highest reliability return first:

- one ownership protocol
- one cutover fence
- no startup work triggered during failover
