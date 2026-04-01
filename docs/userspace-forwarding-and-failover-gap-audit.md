# Userspace Forwarding And Failover Gap Audit

Date: 2026-03-31

This document answers two design questions against the current codebase:

1. Is the eBPF dataplane ever still in use when the userspace dataplane is
   considered "running"?
2. Why does HA failover currently need more than MAC movement plus GARP/NA if
   sessions are being synchronized continuously?

The short answers are:

- **No, we do not currently enforce a pure userspace-forwarding invariant.**
  The code still allows `xdp_main_prog`, `XDP_PASS`, and kernel/BPF state to
  participate while the userspace dataplane is active or partially active.
- **No, current failover is not reducible to "move MACs and keep forwarding".**
  Session sync is continuous, but it is not the full forwarding state. Several
  forwarding-critical inputs are local, derived, filtered, or ordered
  separately from the session stream.

This is an audit of the current implementation, not a statement of the desired
end state.

## 1. Desired Invariants

If we want a strict userspace dataplane model, the runtime invariants should be:

1. When userspace forwarding is declared active for a data interface, transit
   packets are never forwarded by `xdp_main_prog`.
2. When userspace forwarding is declared active, transit packets are never
   forwarded by accidental `XDP_PASS` into the kernel routing path.
3. Any exception path is explicit and narrow:
   - ARP / NDP control plane
   - maybe ESP / GRE until userspace owns them completely
4. The system must expose when it has fallen back out of strict userspace mode.

If we want failover to be "just move MACs and keep forwarding", the runtime
invariants should be:

1. The peer already has all forwarding-relevant state before the RG move.
2. Old-owner and new-owner dataplanes agree on ownership at the cutover edge.
3. No local cache, alias, neighbor, or reverse-session rebuild is needed after
   the move.
4. Session sync is sufficient to reconstruct the exact forwarding decision on
   the new owner without an ordered handoff.

The current code does not meet either invariant set.

## 2. Audit Result: eBPF Dataplane Is Still In Use In Userspace Mode

### 2.1 The userspace backend still compiles and carries the full eBPF pipeline

`pkg/dataplane/userspace/manager.go` embeds the normal eBPF
`dataplane.Manager` as `inner`. The userspace backend is not replacing the eBPF
dataplane; it is layering a userspace helper and an XDP shim on top of it.

Relevant code:

- `pkg/dataplane/userspace/manager.go`
- `pkg/dataplane/loader.go`

Implication:

- `xdp_main_prog`, TC programs, BPF maps, and conntrack maps still exist in
  the userspace backend.

### 2.2 The entry program is still explicitly swappable between userspace and eBPF

The userspace manager still chooses between `xdp_userspace_prog` and
`xdp_main_prog`:

- `pkg/dataplane/userspace/manager.go:Compile()`
- `pkg/dataplane/loader.go:SwapXDPEntryProg()`

Current behavior:

- if userspace forwarding is supported and XSK liveness has not failed, the
  manager prefers `xdp_userspace_prog`
- if XSK liveness has failed, the manager explicitly selects `xdp_main_prog`
- link-cycle preparation also explicitly swaps back to `xdp_main_prog`

This means:

- "userspace configured" is not equal to "userspace exclusively forwarding"
- the runtime can silently move back to eBPF transit

### 2.3 XSK liveness failure intentionally falls back to eBPF

`pkg/dataplane/userspace/manager.go` contains a deliberate XSK liveness probe.
If bindings are ready but RX liveness is not proven, it marks
`xskLivenessFailed` and swaps the entry program to `xdp_main_prog`.

Relevant code:

- `pkg/dataplane/userspace/manager.go:applyHelperStatusLocked()`

That is a designed compatibility mechanism, not a strict userspace invariant.

### 2.4 Link-cycle handling intentionally swaps traffic back to eBPF

Before link DOWN/UP or AF_XDP rebind-sensitive operations, the manager
explicitly:

1. disables userspace control
2. swaps to `xdp_main_prog`
3. stops helper workers

Relevant code:

- `pkg/dataplane/userspace/manager.go:DisableAndStopHelper()`
- `pkg/dataplane/userspace/manager.go:PrepareLinkCycle()`

This is required today for safety around UMEM / XSK rebinds, but it means the
strict invariant is false during those transitions.

### 2.5 The userspace XDP shim still falls back to eBPF or kernel paths

`userspace-xdp/src/lib.rs` is not a "userspace only" entry path. It has
multiple explicit fallback behaviors.

#### 2.5.1 `fallback_to_main()` exists and is used

`userspace-xdp/src/lib.rs:fallback_to_main()` attempts a tail call to the main
eBPF pipeline. If that fails, it returns `XDP_PASS`.

This is used for cases such as:

- ctrl disabled
- parse failures
- heartbeat missing / stale
- early filter fallback
- adjust-meta failure
- redirect errors

Relevant code:

- `userspace-xdp/src/lib.rs:try_xdp_userspace()`
- `userspace-xdp/src/lib.rs:fallback_to_main()`

Implication:

- even with the userspace shim attached, transit can still be processed by the
  eBPF pipeline or by the kernel stack

#### 2.5.2 `XDP_PASS` is still used for multiple classes of traffic

The userspace shim intentionally passes several packet classes to the kernel:

- non-IP packets
- ARP / L2 control behavior
- ICMPv6 NDP
- local-destination traffic
- `PASS_TO_KERNEL` session actions
- ESP
- non-native GRE
- interface-NAT-local cases

Relevant code:

- `userspace-xdp/src/lib.rs:try_xdp_userspace()`
- `userspace-xdp/src/lib.rs:cpumap_or_pass()`
- `userspace-xdp/src/lib.rs:is_local_destination()`
- `userspace-xdp/src/lib.rs:is_interface_nat_destination()`

This means the current userspace dataplane is a hybrid:

- userspace helper for some transit/session-owned flows
- kernel or eBPF pipeline for others

### 2.6 The userspace session map still contains `PASS_TO_KERNEL` actions

The XDP shim reads `userspace_sessions` and honors two actions:

- `REDIRECT`
- `PASS_TO_KERNEL`

Relevant code:

- `userspace-xdp/src/lib.rs`
- `userspace_sessions` map definition and `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL`

So even the "userspace session steering" map is not a strict redirect-only map.

### 2.7 BPF conntrack state still matters when userspace re-enables

`pkg/dataplane/userspace/manager.go` explicitly flushes:

- `userspace_sessions`
- BPF conntrack maps `sessions` / `sessions_v6`

on ctrl re-enable, because stale BPF state interferes with the userspace path.

Relevant code:

- `pkg/dataplane/userspace/manager.go:applyHelperStatusLocked()`

This is an important proof point:

- the eBPF dataplane is not merely "loaded but irrelevant"
- residual BPF state can still change the forwarding behavior of the userspace
  system

### 2.8 Current conclusion for question 1

The current code does **not** validate the claim:

> "if the userspace dataplane is running, the eBPF dataplane is never in use"

What the current code actually supports is:

> "the userspace dataplane is preferred when healthy, but the runtime may still
> use eBPF or kernel forwarding for fallback, bootstrap, control-plane, and
> failure-handling paths"

## 3. Gaps To Eliminate For A Strict Userspace-Only Invariant

To make the invariant true, the repo needs explicit architectural changes.

### 3.1 Define runtime modes explicitly

The code needs a first-class mode distinction, not an implied one:

- `userspace_strict`
- `userspace_compat`
- `ebpf_only`

Right now "userspace running" can still mean:

- `xdp_userspace_prog` attached with kernel/eBPF fallback live
- `xdp_main_prog` swapped in after XSK liveness failure

That is too ambiguous.

### 3.2 Remove transit fallback from `xdp_userspace_prog` in strict mode

In strict mode:

- `fallback_to_main()` must not be used for transit traffic
- `PASS_TO_KERNEL` must not be used for transit traffic
- transit exceptions should drop and count loudly, not silently forward through
  another dataplane

Control-plane exceptions can remain narrow and explicit.

### 3.3 Stop silently swapping to `xdp_main_prog` when userspace is declared healthy

If the runtime wants strict userspace semantics, XSK liveness failure should:

- fail the dataplane health signal
- block takeover/readiness
- or fail closed

It should not silently preserve transit by moving to the eBPF dataplane while
still looking like "userspace mode".

### 3.4 Expose the actual forwarding boundary in status and validation

Status must report:

- attached XDP entry program per interface
- whether strict userspace-only invariants are currently satisfied
- whether any transit fallback counters have incremented

Validation should fail if:

- a data interface is on `xdp_main_prog` while userspace strict mode is claimed
- transit fallback counters rise

## 4. Audit Result: Failover Is Not Just MAC Movement Today

The assumption behind the question is:

> sessions are synced continuously, so the new owner should already be able to
> forward; therefore failover should only need MAC movement plus GARP/NA

That assumption does not match the current implementation.

### 4.1 Session sync is continuous, but it is not the full forwarding state

The session sync path lives in Go:

- `pkg/cluster/sync.go`
- `pkg/daemon/daemon.go`

It installs synced sessions back into the dataplane through:

- `pkg/dataplane/userspace/manager.go:SetClusterSyncedSessionV4()`
- `pkg/dataplane/userspace/manager.go:SetClusterSyncedSessionV6()`

But those installs explicitly zero local FIB-resolved fields:

- `FibIfindex`
- `FibVlanID`
- `FibDmac`
- `FibSmac`
- `FibGen`

That is a direct proof that session sync is not carrying complete resolved
forwarding state. The new owner must still re-resolve forwarding locally.

### 4.2 HA ownership state is separate from session sync

Forwarding depends on local HA runtime, not just the session contents.

Relevant code:

- `pkg/dataplane/userspace/manager.go:UpdateRGActive()`
- `userspace-dp/src/main.rs:update_ha_state`
- `userspace-dp/src/afxdp.rs:update_ha_state()`

What happens on RG change:

- BPF `rg_active` is updated
- helper `ha_state` is updated
- flow caches are invalidated
- demoted owner-RG sessions are demoted or purged
- reverse synced sessions are prewarmed / refreshed for activated RGs

If failover were only MAC movement, this entire HA state update path would not
be necessary. It is necessary because session entries alone do not encode the
current local ownership truth.

### 4.3 Reverse companions are not continuously mirrored 1:1

The helper has explicit logic to:

- synthesize reverse synced entries
- prewarm reverse synced sessions on RG activation
- refresh live reverse sessions on owner-RG changes

Relevant code:

- `userspace-dp/src/afxdp/session_glue.rs:prewarm_reverse_synced_sessions_for_owner_rgs()`
- `userspace-dp/src/afxdp/session_glue.rs:refresh_live_reverse_sessions_for_owner_rgs()`
- `pkg/dataplane/userspace/manager.go:SetClusterSyncedSessionV4()`
- `pkg/dataplane/userspace/manager.go:SetClusterSyncedSessionV6()`

This exists because the reverse side is partly derived from:

- current HA state
- current resolution
- current owner RG after re-resolution

The install path also only mirrors forward sessions directly into the helper:
`shouldMirrorUserspaceSession(val.IsReverse)` returns false for reverse entries.

That is not equivalent to "session sync already made both sides ready".

### 4.4 Continuous sync intentionally filters some session classes

The daemon explicitly declines to sync some userspace deltas:

- `local_delivery` is filtered out
- ownership filtering applies by RG / zone
- special handling exists for fabric redirect aliases

Relevant code:

- `pkg/daemon/daemon.go:shouldSyncUserspaceDelta()`

So "all sessions are synced continuously" is already false in the strict sense.

The current model is:

- sync only the subset needed for failover continuity
- derive or rebuild the rest locally

### 4.5 Neighbor state and fabric-link state are separate control channels

Failover forwarding depends on more than the conntrack/session table.

Separate control paths exist for:

- fabric state
  - `pkg/dataplane/userspace/manager.go:SyncFabricState()`
- neighbor state
  - `userspace-dp/src/main.rs:update_neighbors`
- local address / interface-NAT / helper snapshot state
  - userspace snapshot publication in the userspace manager

If session sync were sufficient, these would not have to be independent HA
inputs.

### 4.6 Flow-cache state is local and must be invalidated

`UpdateRGActive()` explicitly bumps FIB generation, and helper workers flush or
invalidate flow caches during RG changes.

Relevant code:

- `pkg/dataplane/userspace/manager.go:UpdateRGActive()`
- `userspace-dp/src/afxdp.rs:update_ha_state()`
- `userspace-dp/src/afxdp/session_glue.rs`

This is another proof that forwarding decisions are cached locally and are not
fully represented by the synced session table.

### 4.7 Ordered demotion exists because "continuous sync" is not enough at the cutover edge

The daemon does substantial work before allowing a graceful demotion:

- verify peer bulk sync acknowledgement
- wait for prior barriers to drain
- wait for sync quiescence
- pause incremental sync
- drain event stream or fallback RPC deltas
- export owner-RG sessions
- flush kernel session journal
- wait for peer barrier
- call helper `PrepareRGDemotion`

Relevant code:

- `pkg/daemon/daemon.go:prepareUserspaceRGDemotionWithTimeout()`

If the continuous stream alone were sufficient, this staged handoff would not
exist. It exists because failover correctness depends on:

- knowing what the peer has already installed
- fencing background producers
- aligning old-owner demotion with new-owner readiness

### 4.8 Demotion and activation still mutate helper-local state

On RG change, the helper does more than "keep forwarding":

- deletes live session keys from `USERSPACE_SESSIONS` for demoted RGs
- demotes shared owner-RG sessions
- flushes flow caches
- sends worker `DemoteOwnerRG`
- prewarms reverse synced sessions for activated RGs
- refreshes owner-RG state on workers

Relevant code:

- `userspace-dp/src/afxdp.rs:update_ha_state()`
- `userspace-dp/src/afxdp.rs:prepare_ha_demotion()`

This is the current code-level answer to the user’s question:

> failover needs more than GARP/NA because the new owner does not yet hold a
> complete, cache-free, locally re-resolved forwarding graph at the exact
> cutover point

### 4.9 Standby readiness is not implied by session sync

The userspace system still has to ensure:

- helper process exists
- workers are bound
- ctrl is enabled
- XSK liveness is proven
- standby helper is armed enough to receive stale-owner traffic or take over

Those are separate from session sync.

## 5. Current Answer To "Why Not Just Keep Forwarding?"

Because the current "session" is not the whole forwarding decision.

The forwarding decision on the new owner depends on:

1. synced forward session state
2. locally recomputed reverse companion state
3. current HA runtime (`active`, `demoting`)
4. current local neighbor state
5. current fabric-link state
6. current interface-NAT / local-address classification
7. current flow-cache invalidation epoch
8. proof that the peer has actually installed the relevant state before cutover

Today, those are updated through multiple channels with explicit ordering.

That is why current failover needs:

- HA state updates
- reverse-session refresh / prewarm
- demotion prep
- barriers / bulk ack
- neighbor / fabric sync
- cache invalidation

## 6. What Must Change To Reach MAC-Move-Only Failover

If the desired end state is:

> "failover only moves virtual MACs and sends GARP/NA; forwarding continues"

then the architecture needs to become much stricter than it is now.

### 6.1 Userspace-only forwarding must become real

Transit must not silently escape to:

- `xdp_main_prog`
- `XDP_PASS` kernel forwarding

for data-plane flows.

### 6.2 Forwarding-relevant state must be either fully replicated or cleanly re-derived

At minimum, the system must guarantee that the new owner already has:

- forward session state
- reverse companion state
- owner-RG truth
- fabric-ingress truth
- any alias state required for translated forward/reverse lookups
- local neighbor/fabric inputs needed to emit the packet

and that the old owner no longer has stale cached permission to keep forwarding
locally.

### 6.3 Cutover must be defined by an install fence, not by hope

Continuous sync alone is not a proof of readiness.

The system needs a cutover fence that means:

- peer has installed all relevant state through sequence N
- old owner has invalidated stale local decisions
- new owner can answer the next packet with the correct disposition

### 6.4 The repo should state the truth explicitly

The current code is a hybrid userspace/eBPF HA system with staged failover
hardeners.

It is not yet:

- strict userspace-only forwarding
- or pure MAC-move-only failover

That should be documented as an explicit architectural truth instead of being
left implicit.

## 7. Recommended Follow-Up Work

### 7.1 For strict userspace-only forwarding

1. Add a first-class runtime mode for strict userspace forwarding.
2. Ban transit fallback to `xdp_main_prog` and `XDP_PASS` in that mode.
3. Expose per-interface entry-program state and fallback counters in status.
4. Make validation fail if transit fallback occurs.

### 7.2 For minimal failover

1. Enumerate every forwarding-relevant state input that is not currently in the
   sync stream.
2. Decide whether each input should be:
   - replicated
   - derived deterministically
   - or fenced by cutover ordering
3. Reduce worker-local / cache-local state that needs activation-time repair.
4. Keep demotion barriers until the above is true; do not remove them based on
   the assumption that session sync alone is already sufficient.
