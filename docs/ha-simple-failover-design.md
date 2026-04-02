# HA Session Sync And Flow Cache Simplification

Date: 2026-04-01

Related issues:
- #314
- #315
- #316
- #318
- #319
- #320
- #321
- #322
- #323

## Goal

Make HA failover behave like this:

1. the standby continuously receives the authoritative session state
2. the standby continuously derives the local forwarding-ready runtime state
3. failover is reduced to:
   - ownership flip
   - MAC move
   - GARP / gratuitous NA
   - continued forwarding

The current code does not meet that bar. The session stream is not the full
forwarding-ready state, and the helper still performs activation-time repair
work.

This document describes a simpler target model and a phased implementation plan.

## Problem Statement

The current HA design works, but it is carrying too much transition-time logic.
That logic is expensive, hard to reason about, and directly connected to why
failover remains fragile.

The main structural problem is this:

- the replicated state is not the same thing as the forwarding-ready state

That forces failover to do more than MAC movement.

## Current Complexity Drivers

### 1. The sync payload is not portable

Current session sync still serializes node-local forwarding details such as:

- egress ifindex
- tx ifindex
- neighbor MAC
- source MAC
- VLAN choice

But the receiver immediately discards the peer's local FIB-resolved fields on
install because they are not portable to the new node.

That means the stream is carrying a mix of:

- canonical session state
- non-portable local resolution state

Those are different layers and should not be conflated.

### 2. Standby state is not continuously forwarding-ready

On RG activation, the helper still does repair work:

- reverse-session prewarm
- forward session re-resolution
- reverse session refresh
- flow cache flush / invalidation

That means the standby is not continuously keeping its local runtime form ready.
It is partially hydrated and then repaired when ownership changes.

### 3. Helper HA state is spread across overlapping stores

The helper currently reasons across:

- `shared_sessions`
- `shared_nat_sessions`
- `shared_forward_wire_sessions`
- worker-local `SessionTable`
- multiple alias indexes

This creates transition-time complexity because demotion, activation, delete,
and refresh have to walk and reconcile multiple representations of the same flow.

### 4. Flow cache participates in HA correctness

The flow cache should be a disposable acceleration layer.

Right now failover correctness still depends on:

- per-RG cache invalidation scans
- global `FlushFlowCaches`
- special handling for stale ownership

That is a sign that the cache is too entangled with HA state transitions.

### 5. Demotion is compensating for missing cutover semantics

Graceful demotion currently needs:

- queue-idle detection
- ordered barriers
- pause/resume of incremental sync
- event-stream drain or RPC drain/export fallback
- journal flush

That choreography exists because there is no simple proof of:

- "the peer has fully imported and materialized all forwarding-relevant state
  through sequence N"

### 6. The producer model is still too broad

The system still uses a mix of:

- helper event stream
- helper polling fallback
- kernel sweep / reconciliation
- transition-time exports and drains

That makes correctness depend on multiple producer paths being kept aligned.

## Simplification Principles

### 1. One canonical replicated state model

Cross-node HA sync should carry only canonical session state.

It should not carry remote-node resolution artifacts.

### 2. One continuously maintained local runtime model

Each node should derive its own forwarding-ready runtime state from:

- canonical synced session state
- local forwarding snapshot
- local HA state
- local neighbor state

That derivation should happen continuously, not as an activation repair pass.

### 3. Flow cache must be disposable

The flow cache should never be a state transition participant.

If ownership or resolution changes, cache entries should self-miss through epoch
checks, not require imperative scans and flushes.

### 4. Failover must fence applied state, not background activity

The cutover contract should be:

- the new owner has applied and materialized all canonical session updates
  through sequence N

Not:

- the queue appears idle
- the drainer is empty
- no unrelated sync traffic arrived during the last window

### 5. Local-only state is acceptable if misses are bounded

Some state will remain local by design:

- neighbor table contents
- queue binding details
- per-worker flow cache entries
- watchdog freshness

That is fine, as long as those misses:

- do not require activation-time table scans
- do not invalidate failover readiness
- degrade into a bounded first-hit slow path

## Target State Model

The target design has three layers.

### Layer 1: Canonical Session Record

This is the only cross-node replicated session state.

It should contain:

- flow key
- NAT rewrite state
- ingress / egress zone identity
- owner RG
- reverse / fabric-ingress / tunnel flags
- any logical egress identity needed to derive local forwarding

It should not contain:

- peer ifindex
- peer MAC addresses
- peer FIB cache generation
- peer queue or worker identity

This record is authoritative and portable.

### Layer 2: Local Session Runtime

Each node derives a local runtime object from the canonical session record.

This runtime object contains:

- locally resolved rewrite descriptor
- reverse companion identity
- translated alias identity
- local HA gating state
- local resolution epoch
- local owner-RG epoch

This object is continuously maintained on both primary and standby.

Inactive ownership does not prevent the runtime from existing. It only prevents
it from being used for forwarding.

### Layer 3: Flow Cache

The flow cache stores only:

- session identity
- precomputed rewrite descriptor
- validation epochs

It should validate against:

- config epoch
- resolution epoch
- owner-RG epoch

On mismatch, it misses and repopulates from the local runtime object.

The flow cache should not require transition-time scans.

## What Failover Should Become

### New owner steady state before failover

Before any MAC movement:

1. canonical session records are already synced
2. local runtime entries are already materialized on the standby
3. reverse companions and aliases already exist locally
4. flow cache may be cold, but cold cache is acceptable

### Cutover sequence

At failover:

1. stop admitting new updates from the old owner past sequence N
2. wait until the new owner has applied and materialized through N
3. flip owner-RG active state and increment owner-RG epoch
4. move MAC ownership
5. send GARP / gratuitous NA

That is the whole cutover.

No activation-time table scan should be required.

No reverse prewarm should be required.

No forward-session re-resolution scan should be required.

### Why this is simpler

Because the new owner is already forwarding-ready before MAC ownership moves.

The only runtime difference at cutover is:

- ownership allowed vs. ownership disallowed

## What Remains Local-Only

The following should remain local-only:

- neighbor resolution cache
- worker / queue assignment
- per-worker flow cache entries
- watchdog freshness timers

Those should not participate in HA correctness.

If they are missing:

- first packet may go slow path
- cache may repopulate
- neighbor may resolve on demand

But failover should still fundamentally work.

## Implementation Phases

### Phase 1: Portable canonical session schema

Issue:
- #318

Change:
- redesign cross-node session sync and helper sync payloads around portable
  session records
- stop treating resolved ifindex / MAC state as part of the replicated contract

Deliverables:
- canonical session record schema
- conversion layer from current BPF / helper session structs
- explicit list of fields that remain local-only

Acceptance:
- no activation code depends on peer ifindex / MAC fields existing in the sync
  payload

### Phase 2: Continuous standby materialization

Issues:
- #315
- #316
- #319

Change:
- on sync import, always materialize the standby's local runtime form
- build reverse companions and translated aliases continuously
- either carry `local_delivery`-relevant state explicitly or replace it with a
  deterministic derived model

Deliverables:
- no reverse prewarm requirement at RG activation
- no "cluster-synced reverse session is present in kernel but absent in helper"
  split
- explicit treatment of `local_delivery` in the HA model

Acceptance:
- synced sessions are locally usable on the standby before activation

### Phase 3: Canonical helper store plus derived indexes

Issue:
- #320

Change:
- collapse shared session clones into one canonical helper store
- keep alias maps as indexes to canonical session identity rather than cloned
  `SyncedSessionEntry` objects

Deliverables:
- one authoritative synced session store
- derived indexes for reverse / translated / forward-wire lookup
- simplified delete / demote / activation paths

Acceptance:
- demotion and delete no longer need to walk parallel shared stores

### Phase 4: Epoch-based flow cache validation

Issue:
- #321

Change:
- add:
  - owner-RG epoch
  - local resolution epoch
  - config epoch
- validate flow-cache entries against epochs instead of transition-time scans

Deliverables:
- no `FlushFlowCaches` requirement in the HA transition path
- no per-RG cache walk for correctness

Acceptance:
- RG transition correctness does not depend on explicit cache flushing

### Phase 5: Applied-sequence cutover fence

Issues:
- #314
- #322

Change:
- assign a monotonically increasing sequence to canonical session updates
- standby acks the highest fully materialized sequence
- graceful demotion fences on that applied sequence instead of queue-idle
  heuristics and side drains

Deliverables:
- peer-applied sequence tracking
- worker-completion acknowledgment for local materialization
- cutover-ready condition expressed as `applied_seq >= target_seq`

Acceptance:
- no `WaitForIdle`-style heuristic is needed in the common demotion path

### Phase 6: Event-first producers, reconciliation-only sweep

Issue:
- #323

Change:
- helper event stream becomes the steady-state userspace producer
- kernel session producer becomes event-first
- sweeps remain only for reconciliation, reconnect recovery, and correctness
  audits

Deliverables:
- reduced steady-state polling
- reduced transition-time queue churn
- simpler sequence accounting for cutover fencing

Acceptance:
- sweeps are no longer the primary semantic source of sync freshness

## Expected Result

When the above phases are complete:

1. session sync carries only canonical, portable state
2. standby continuously maintains local forwarding-ready runtime state
3. reverse and alias state already exists before failover
4. flow cache is a disposable accelerator with epoch validation
5. cutover is fenced by applied sequence, not by drain choreography
6. failover becomes much closer to:
   - flip ownership
   - move MACs
   - GARP / gratuitous NA
   - continue forwarding

That is the simplest HA model that still preserves performance.

## Non-Goals

This design does not try to:

- eliminate all local-only state
- prewarm every possible neighbor on the standby
- make cold-cache first-packet latency zero

Those are separate goals.

The point here is narrower:

- make HA correctness depend on a small, explicit state model
- stop depending on transition-time repair passes
- keep the flow cache fast without making it part of the failover state machine
