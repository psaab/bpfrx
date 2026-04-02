# HA Failover Simplification Audit

## Scope

This audit is against `origin/master` at `493daeb0`.

Files reviewed:

- [pkg/daemon/daemon.go](../pkg/daemon/daemon.go)
- [pkg/cluster/sync.go](../pkg/cluster/sync.go)
- [pkg/dataplane/userspace/manager.go](../pkg/dataplane/userspace/manager.go)
- [userspace-dp/src/afxdp.rs](../userspace-dp/src/afxdp.rs)
- [userspace-dp/src/afxdp/session_glue.rs](../userspace-dp/src/afxdp/session_glue.rs)
- [userspace-dp/src/event_stream.rs](../userspace-dp/src/event_stream.rs)

Related prior design and audit docs:

- [ha-simple-failover-design.md](ha-simple-failover-design.md)
- [session-sync-architecture.md](session-sync-architecture.md)
- [userspace-forwarding-and-failover-gap-audit.md](userspace-forwarding-and-failover-gap-audit.md)
- [flow-cache-simplification.md](flow-cache-simplification.md)

## Short Answer

Failover is not currently “move MACs, send GARP/GNA, keep forwarding” because the system does not continuously maintain one portable, forwarding-ready state on both nodes.

Instead, failover still depends on:

- continuously replicated canonical session state
- helper-local activation and demotion work
- helper-local liveness state
- activation-time re-resolution and cache invalidation
- asynchronous neighbor and fabric refresh side effects

That split is the core source of HA complexity.

## Current Failover Path

The code path still spans multiple layers that each believe they own part of failover correctness.

### 1. Session transport and peer readiness

`SessionSync` in [pkg/cluster/sync.go](../pkg/cluster/sync.go) still models failover readiness through:

- incremental session deltas
- bulk sync epochs in [`BulkSync()`](../pkg/cluster/sync.go#L1025)
- barrier messages and pending barrier drain
- separate bulk-primed state

That means “peer is ready” is not one thing. It is a combination of:

- transport connected
- bulk state acknowledged
- barrier ack observed
- local producers not outrunning the fence

Relevant issues:

- `#323` Replace HA demotion drain choreography with an applied-sequence cutover fence
- `#338` Graceful demotion barrier no longer fences helper and kernel session producers
- `#339` Graceful demotion can proceed without confirmed peer bulk readiness
- `#340` Daemon acks helper event-stream deltas even when sync-disconnect drops them

### 2. Graceful demotion still has a transport phase and a helper phase

Graceful demotion in [`prepareUserspaceRGDemotionWithTimeout()`](../pkg/daemon/daemon.go#L4120) still does:

1. acquire demotion prep state in Go
2. wait for peer barriers / barrier drain
3. call helper `PrepareRGDemotion`

The helper then still has its own staged demotion path:

- [`prepare_ha_demotion()`](../userspace-dp/src/afxdp.rs#L1340)
- worker `PrepareDemoteOwnerRGs`
- later worker `DemoteOwnerRG`

The handoff-safe point is therefore not one acknowledged transition.

Relevant issues:

- `#359` Collapse helper demotion from prepare-plus-demote into one acknowledged transition
- `#323`
- `#338`
- `#339`

### 3. Ownership activation is still modeled twice

Go activates ownership in [`UpdateRGActive()`](../pkg/dataplane/userspace/manager.go#L2789):

- updates BPF `rg_active`
- bumps FIB generation
- pushes helper `update_ha_state`
- then applies helper status

The helper still has a second activation step in [`refresh_owner_rgs()`](../userspace-dp/src/afxdp.rs#L1261), which:

- prewarms reverse synced sessions
- bumps RG epochs
- queues `RefreshOwnerRGs` to workers
- waits for worker acks with a separate timeout

Workers then still run RG-wide refresh logic in [`RefreshOwnerRGs`](../userspace-dp/src/afxdp/session_glue.rs#L333).

This is the central duplication: ownership moved, but forwarding readiness is still a later helper repair step.

Relevant issues:

- `#358` Collapse userspace RG activation into one helper-applied HA generation
- `#314` HA cutover still lacks a helper worker-completion acknowledgment
- `#341` UpdateRGActive hides helper `refresh_owner_rgs` timeout and failure
- `#342` RG activation duplicates helper refresh work through `update_ha_state` and explicit refresh
- `#344` HA activation is decoupled from actual userspace dataplane enablement
- `#345` HA activation still does RG-wide helper refresh scans despite on-receipt standby materialization

### 4. Helper liveness is still modeled separately from helper ownership

Helper HA runtime state in [`update_ha_state()`](../userspace-dp/src/afxdp.rs#L1074) still carries:

- `active`
- `watchdog_timestamp`
- `demoting`
- `demoting_until_secs`

That means helper packet-time HA behavior is driven by more than one notion of “this RG is usable here”.

This directly contributes to transient `HAInactive` behavior and to duplicated reasoning in both Go and Rust.

Relevant issues:

- `#360` Replace split active-plus-watchdog HA state with a single applied lease model
- `#349` HA watchdog refresh cadence is slower than the helper’s stale threshold
- `#344`

### 5. The standby is not fully forwarding-ready from continuous sync alone

The code is closer than it used to be, but it still is not true that continuous sync alone leaves the standby ready to forward immediately.

Examples:

- `local_delivery` is still excluded from continuous userspace sync
- reverse sessions are still special-cased
- synced sessions still undergo local re-resolution on receipt or activation
- activation still performs RG-wide session refresh scans

Relevant issues:

- `#315` Continuous userspace HA sync still omits local-delivery session state
- `#316` Cluster-synced reverse sessions are still not mirrored into the userspace helper
- `#317` Userspace session sync still depends on activation-time local egress re-resolution
- `#319` Continuously materialize standby helper state instead of repairing sessions on RG activation
- `#345`

### 6. Cutover still depends on async warm-up side effects

Failover is still not just a control-plane ownership change because data-plane correctness depends on background work that happens after the transition:

- neighbor warm-up
- `fabric_fwd` refresh
- helper-local cache and alias cleanup

Relevant issues:

- `#347` Failover still depends on post-transition neighbor warm-up sweeps
- `#348` HA transition still depends on asynchronous `fabric_fwd` refresh
- `#321` Make HA flow-cache scans and flushes rely on epoch-based cache validation

## Simpler Model

The simpler failover model is:

1. both nodes continuously receive the same portable canonical session record
2. both nodes continuously materialize their own local forwarding-ready runtime state from that record
3. helper caches are disposable and validated by epochs / leases
4. cutover is one applied generation fence
5. once the new owner reports the new generation applied, failover reduces to MAC movement and GARP/GNA

That is the only model that actually makes “sessions are continuously synced, so failover should be simple” true.

## What To Simplify

### A. One canonical session record, no peer-local resolution in sync

The replicated object should carry portable session intent only:

- 5-tuple / direction
- NAT state that is semantically part of the session
- policy / zone / service identity
- ownership identity
- timeout / TCP state

It should not carry peer-local resolved forwarding state such as:

- peer ifindex
- peer MAC
- peer-local next-hop artifacts

Related issues:

- `#318` Redesign HA session sync around a portable canonical session record
- `#317`

### B. One helper state machine for HA cutover

The helper should not separately expose:

- `update_ha_state`
- `refresh_owner_rgs`
- `prepare_ha_demotion`
- `PrepareDemoteOwnerRGs`
- `DemoteOwnerRG`

It should expose one HA transition interface built around an applied generation:

- `apply_generation`
- `cutover_to_generation`
- `ack generation N fully applied`

Related issues:

- `#358`
- `#359`
- `#341`
- `#342`

### C. One lease model, not active plus watchdog plus demoting

Helper packet-time HA checks should validate one model:

- current owner generation
- current lease or epoch validity

The helper should not need to combine:

- active bit
- watchdog timestamp
- demoting bool
- demoting deadline

Related issues:

- `#360`
- `#349`

### D. Standby must be continuously forwarding-ready

The standby should already have:

- reverse companions
- translated aliases
- local egress resolution
- forwarding-ready helper indexes

If that is true, activation should not need RG-wide scans.

Related issues:

- `#319`
- `#315`
- `#316`
- `#345`

### E. Flow cache should be disposable

The flow cache is still needed for performance, but it should not be part of HA choreography.

The cache should be:

- local-only
- derived-only
- invalidated by simple epochs / generations
- rebuilt by misses

That is the direction already described in [flow-cache-simplification.md](flow-cache-simplification.md).

Related issues:

- `#321`
- `#322`

### F. Session producers should be event-first, not mixed-primary

The current system still mixes:

- bulk sync
- incremental deltas
- helper event stream
- reconciliation sweeps / polling

Those are all useful, but they should not all behave like primary truth sources during failover.

The simpler model is:

- event-first producers for normal steady state
- reconciliation sweeps only as backstop
- one applied-sequence fence at cutover

Related issues:

- `#320`
- `#323`

### G. Cutover should use one applied-sequence fence

The right handoff primitive is:

- all replicated state through sequence `S` has been received
- both helper and kernel-facing consumers have applied through `S`
- the new owner has applied HA generation `G`

At that point failover can move MACs and emit GARP/GNA.

This is simpler than the current mix of:

- bulk-primed state
- peer barriers
- helper prepare acks
- helper refresh acks
- asynchronous status convergence

Related issues:

- `#323`
- `#338`
- `#339`
- `#340`
- `#314`

## Implementation Phases

### Phase 0: Guardrails and observability

Before deeper simplification, the current path still needs accurate failure reporting.

Primary items:

- `#341`
- `#346`
- `#349`

Goal:

- stop reporting HA transition success while helper-side work is still hidden, timed out, or stale

### Phase 1: Canonical record and standby materialization

Primary items:

- `#318`
- `#320`
- `#315`
- `#316`
- `#317`
- `#319`

Goal:

- every continuously replicated session record is portable
- both nodes continuously build their own forwarding-ready local representation from it

### Phase 2: Collapse helper session state and cache dependencies

Primary items:

- `#321`
- `#322`
- `#345`

Goal:

- helper session state becomes one canonical store with derived indexes
- cache invalidation becomes epoch-based, not scan-based
- activation does not need RG-wide repair work

### Phase 3: Replace staged handoff with one cutover fence

Primary items:

- `#323`
- `#338`
- `#339`
- `#340`
- `#358`
- `#359`

Goal:

- one acknowledged cutover sequence instead of prepare, barrier, refresh, and demote sub-phases

### Phase 4: Unify runtime lease and dataplane enablement

Primary items:

- `#360`
- `#344`
- `#349`

Goal:

- helper ownership, helper liveness, and dataplane enablement are all driven by the same applied HA state

### Phase 5: Remove post-cutover warm-up dependencies

Primary items:

- `#347`
- `#348`
- `#308`

Goal:

- after cutover ack, the new owner forwards immediately
- failover is reduced to ownership move plus MAC/GARP/GNA work

## What Success Looks Like

The design is simpler only if these statements become true:

1. Session sync carries one portable canonical record.
2. The standby is already forwarding-ready before failover.
3. Helper flow cache contents never need explicit HA choreography.
4. Activation is one acknowledged helper-applied generation.
5. Demotion is one acknowledged handoff fence.
6. MAC move plus GARP/GNA is the only externally visible failover step.

Until those are true, HA will continue to need special-case repair logic at cutover.
