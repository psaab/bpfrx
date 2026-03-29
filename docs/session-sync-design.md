# Session Sync Design

## Goal

Improve HA session sync so that it is:

- fast enough to preserve established traffic during failover
- explicit enough to gate failover admission correctly
- simple enough to reason about ownership and replay semantics
- efficient enough to avoid treating a 1-second map sweep as the primary steady-state producer

This document is a forward-looking design note. It complements the current-state
writeup in [session-sync-architecture.md](./session-sync-architecture.md).

## Current State

Today the architecture is split across:

- [pkg/cluster/sync.go](../pkg/cluster/sync.go)
  - sync wire protocol
  - bulk sync
  - delete journal
  - incremental sweep
  - barriers
- [pkg/daemon/daemon.go](../pkg/daemon/daemon.go)
  - readiness gating
  - ownership filtering
  - bulk-prime retry
  - userspace delta drain/export
  - graceful demotion prep
- [pkg/dataplane/userspace/manager.go](../pkg/dataplane/userspace/manager.go)
  - helper RPCs for delta drain/export and cluster-synced install
- [userspace-dp/src/afxdp/session_glue.rs](../userspace-dp/src/afxdp/session_glue.rs)
  - userspace session lifecycle inside the Rust helper

That split is not accidental. It reflects two different responsibilities:

1. cluster control-plane ownership and failover gating
2. dataplane-local session production and install

The problem is not that the current split is conceptually wrong. The problem is
that the steady-state producer model is still too sweep-heavy, and the userspace
helper is still integrated through polling instead of an ordered stream.

## What Is Wrong With The Current Model

### 1. The kernel sweep is still treated as a primary producer

The sweep in [pkg/cluster/sync.go](../pkg/cluster/sync.go) is still doing the
bulk of steady-state kernel session discovery by scanning `sessions_v4` /
`sessions_v6` on a timer and comparing `Created` / `LastSeen` against the prior
window.

That has three problems:

- it is too coarse for failover-sensitive traffic
- it creates unnecessary work when nothing materially changed
- it couples sync freshness to sweep cadence instead of actual session events

### 2. Userspace helper sync is still polled

The Rust helper currently exports steady-state session changes through
`DrainSessionDeltas(...)`, which the daemon polls periodically.

That means the lowest-latency session producer in the system is still forced
through a polling boundary. This adds delay, complexity, and another place where
quiescence has to fight background work.

### 3. Ownership and filtering live in the right place, but too late in the path

The daemon is currently the right owner for HA filtering decisions such as:

- `ShouldSyncZone(...)`
- `IsPrimaryForRGFn(...)`
- stale-owner `FabricRedirect` exceptions
- `local_delivery` suppression

But we are paying for those decisions after collecting data through broad sweeps
or polling loops rather than from narrower event sources.

### 4. Readiness and replication are now more sophisticated than the producer model

Current failover admission already depends on:

- inbound bulk receipt
- outbound `BulkAck`
- quiescence
- barriers
- explicit userspace export/drain during demotion prep

That is a stronger control-plane model than the producer side deserves. The
producer side still behaves like a periodic best-effort replication loop.

## Options Considered

## Option A: Keep Everything In `bpfrxd`

That means:

- keep the sync transport in Go
- keep kernel sweeps as the main producer
- keep helper polling through RPC
- improve tuning around the edges

### Pros

- minimal architectural change
- no new cross-language streaming interface
- easiest short-term implementation path

### Cons

- preserves the wrong steady-state producer model
- keeps helper-originated events behind polling latency
- keeps sweeping as the main answer to missing kernel session events

This is not the right end state.

## Option B: Move Session Sync Into Rust

That means:

- Rust helper owns peer TCP sync transport
- Rust helper owns bulk sync, barriers, replay, and readiness
- Go daemon becomes mostly a consumer of Rust sync state

### Pros

- one runtime owns all userspace session production and transport
- avoids helper-to-daemon polling for userspace sessions

### Cons

- pushes HA/control-plane logic into the dataplane runtime
- duplicates or fragments ownership logic that already lives in Go
- complicates VRRP / RG admission / config / fence / failover sequencing
- creates an awkward split for kernel/BPF-originated sessions, which still do
  not originate in Rust

This is the wrong tradeoff. The session-sync transport is part of the HA
control plane, not just the userspace dataplane.

## Option C: Hybrid Event-First Design (Recommended)

Keep the HA/session-sync control plane in Go, but replace broad polling with
narrower event producers.

### Core idea

- `bpfrxd` remains the owner of:
  - peer transport
  - bulk sync
  - readiness
  - barriers
  - demotion handoff
  - ownership filtering
- the Rust helper becomes a streaming producer for userspace session events
- kernel/BPF session sync becomes event-first, with sweep reduced to
  reconciliation

This preserves architectural ownership while fixing the main inefficiencies.

## Recommendation

Use Option C.

In concrete terms:

1. keep `pkg/cluster/sync.go` as the sync protocol owner
2. keep failover admission and demotion sequencing in `pkg/daemon/daemon.go`
3. replace helper delta polling with a long-lived ordered local stream
4. make kernel sync event-first
5. demote the timer sweep to reconciliation / backstop duty

## Target Architecture

## 1. `bpfrxd` remains the authoritative sync coordinator

The daemon should continue to own:

- sync transport connection management
- bulk sync / `BulkAck`
- ownership filtering by zone / RG
- failover readiness
- graceful demotion barriers and quiescence
- install into kernel dataplane and userspace manager

Reason:

- HA ownership is already expressed here
- cluster readiness already gates promotion here
- other cluster control-plane messages already live on the same transport here

Moving this into Rust would not simplify the system. It would shift the wrong
kind of responsibility into the dataplane helper.

## 2. Replace helper polling with helper-to-daemon streaming

Instead of periodic `DrainSessionDeltas(...)`, use a long-lived local stream
between the helper and `bpfrxd`.

### Properties

- ordered delivery
- monotonically increasing sequence number
- bounded local backlog
- daemon ack of last applied sequence
- reconnect/resume semantics
- explicit snapshot/export remains available for reconnect recovery and
  demotion prep

### Why this is better

- lower latency than polling
- no need to wake a drain loop to discover nothing changed
- simpler quiescence during demotion because the stream can be paused or
  checkpointed explicitly

## 3. Make kernel sync event-first

Kernel/BPF sessions should not depend primarily on a 1-second or 15-second map
scan.

The design target should be:

- immediate event for session create
- immediate event for delete
- event for material state transitions
- event for ownership-relevant changes
- sweep only to recover missed events or reconnect gaps

The ring-buffer callback already points in this direction. It should become a
first-class producer instead of a small optimization in front of the sweep.

## 4. Sweep becomes reconciliation, not primary replication

The sweep should still exist, but with a different job:

- catch missed events
- recover after disconnect or queue overflow
- verify convergence
- repair journal or event loss

It should run less frequently and carry less semantic weight.

A reconciliation sweep is still valuable. A reconciliation sweep as the main
steady-state sync producer is not.

## 5. Sync only material changes

The current sweep logic keys off `Created` / `LastSeen` movement. That is too
coarse.

The better model is to sync when one of these changes:

- session create
- session delete
- TCP state change
- NAT allocation / NAT tuple change
- disposition / ownership change
- timeout bucket change that matters for failover survivability

For long-lived established flows, frequent `LastSeen` movement is usually not a
reason to send another sync update.

## Detailed Proposal

## Local producer model

### Kernel producer

A kernel-side producer emits:

- `SessionCreate`
- `SessionUpdate`
- `SessionDelete`

Updates are emitted only for material state changes.

The event contains:

- key
- address family
- reason / update class

The daemon can fetch the full session value by key if needed before queueing it
onto peer sync.

### Userspace producer

The Rust helper emits:

- `SessionOpen`
- `SessionUpdate`
- `SessionClose`
- optional `SessionAliasOpen/Close` for translated forward-wire aliases

These events flow over a local ordered stream rather than RPC polling.

### Reconciliation producer

A slower reconciliation pass periodically verifies:

- local producer health
- peer convergence
- no unacked backlog explosion
- no missed deletes / stale peer-owned sessions

## Sync coordinator behavior

The coordinator in `bpfrxd` should:

- accept events from kernel and helper producers
- apply ownership filtering once
- queue peer sync once
- keep bulk sync as reconnect/bootstrap only
- keep explicit demotion export as a targeted handoff tool

That gives one control-plane authority, not two.

## Why Not Put Kernel Session Sync In Rust

Because the kernel session tables are not Rust-owned.

The helper can own userspace-originated sessions because it created them. It is
not the right owner for:

- kernel conntrack lifetime
- cluster readiness
- RG ownership filtering
- config / failover / fence sequencing

Trying to centralize all sync in Rust would make userspace sessions simpler, but
kernel sessions and HA control-plane behavior more complicated.

That is a net loss.

## Phased Plan

## Phase 1: Replace helper polling with a local stream

Implement:

- helper -> daemon ordered event stream
- sequence / ack model
- reconnect / replay for the local stream
- demotion-prep integration so the daemon can explicitly pause or drain the
  stream

Keep:

- existing peer TCP session-sync protocol
- existing bulk sync and barriers
- existing userspace export path as fallback

This is the highest-value near-term change.

## Phase 2: Promote kernel event sync to primary path

Implement:

- structured session-open / delete events from the kernel-side producer path
- on-demand full-session fetch by key for sync encoding
- minimal update classes for material state changes

Reduce dependence on:

- full map scans every active interval

## Phase 3: Convert sweep into reconciliation

After Phase 2 is stable:

- lengthen sweep intervals
- stop using sweep as the main fresh-session discovery mechanism
- run sweep mainly for convergence repair and missed-event detection

## Phase 4: Reduce update churn

Add more selective update rules:

- timeout bucket changes instead of raw `LastSeen`
- TCP state transitions
- NAT tuple changes
- ownership / disposition changes

That should reduce peer sync traffic substantially without making failover
worse.

## Operational Improvements This Enables

If the design above is implemented, we should get:

- lower steady-state sync CPU
- lower sync latency for userspace-originated sessions
- less demotion-prep fighting with background polling loops
- clearer readiness semantics
- less dependence on arbitrary 1-second scan cadence
- simpler debugging because event provenance is explicit

## Acceptance Criteria

The redesign should not be considered complete unless all of these are true:

1. helper-originated sessions are streamed, not polled, in steady state
2. kernel session create/delete are event-first, not sweep-first
3. periodic sweep can be slowed substantially without failover regression
4. graceful failover does not require broad background drain loops to settle
5. crash/rejoin still converges correctly with reconnect bulk sync
6. ownership filtering remains centralized in `bpfrxd`
7. the peer sync transport and readiness model stay single-owner and coherent

## Non-Goals

This design does **not** propose:

- rewriting HA/session-sync transport in Rust
- deleting bulk sync
- deleting reconciliation sweep entirely
- making the helper the owner of RG/VRRP/failover admission

## Bottom Line

The problem is not that session sync lives in Go.

The problem is that the producer side is still too polling-oriented.

The right redesign is:

- keep the HA/session-sync control plane in `bpfrxd`
- move userspace session production to a local stream
- move kernel session sync to an event-first model
- keep sweep as reconciliation, not as the primary steady-state source
