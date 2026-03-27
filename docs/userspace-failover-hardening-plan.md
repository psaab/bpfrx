# Userspace Failover Hardening Plan

## Problem statement

The userspace HA failover path is still flaky in two distinct ways:

1. Manual redundancy-group moves under established load can blackhole long-lived flows.
2. Crash/rejoin recovery can succeed briefly, then destabilize again when the rebooted node returns.

These are not the same bug. They need separate fixes and separate validation.

There is a third control-plane issue underneath both of them:

3. Session-sync readiness is still treated as "a fresh bulk sync completed on
   this connection" instead of "this standby has a valid sync baseline."

There is now a fourth dataplane-specific issue that shows up after the earlier
cache and sync-readiness fixes:

4. The new owner can still miss post-failover forward-wire sessions for flows
   first observed on the old owner after the RG move.

## What we reproduced

### 1. Manual RG move under load

Repro:

- Start `iperf3 -c 172.16.80.200 -P 4` from `cluster-userspace-host`.
- Move `RG1` from `node0` to `node1` with:
  - `request chassis cluster failover redundancy-group 1 node 1`

Observed:

- The TCP connection dies with `Broken pipe` and does not recover.
- On the old owner (`node0`), helper counters continue to climb by millions of packets after `rg1 active=false`.
- On the new owner (`node1`), helper counters barely move for the same flow.
- `flow_cache_hits` explodes on the old owner during the bad interval.
- `session_hits` stays low.

Interpretation:

- The old owner does continue forwarding locally for part of the bad window.
- But that is not the whole bug.
- When we forced earlier cache invalidation, the new owner immediately started
  seeing the redirected flow and then failed with large `session_miss`
  growth instead.
- So the remaining failure is a handoff-ordering problem between:
  - stale-owner local forwarding
  - stale-owner forward-session republish
  - new-owner forward-wire materialization

Updated live finding after the flow-cache invalidation work:

- The old owner no longer keeps `rg1 active=true`.
- Instead, the new owner receives SNATed forward-wire packets like:
  - `172.16.80.8:58340 -> 172.16.80.200:5201`
- On the new owner those packets miss userspace session lookup and fall into:
  - `session_miss -> missing_neighbor -> slow_path`
- The old owner continues to process and redirect the flow over fabric, but the
  new owner never materializes the matching forward session alias.

### 2. Crash/rejoin of the active node

Repro:

- Keep all RGs on `node0`.
- Start traffic from `cluster-userspace-host`.
- Crash `node0` with:
  - `echo b > /proc/sysrq-trigger`

Observed on surviving `node1`:

- `node1` becomes primary for `RG0/1/2` and starts forwarding traffic.
- After the rebooted node returns, `session sync ready` drops back to `false`.
- Sync-link state flaps:
  - peer connected
  - peer disconnected
  - peer connected
  - peer disconnected

Observed on rebooted `node0` during startup:

- DHCP lease arrives on `fxp0`.
- Daemon logs:
  - `DHCP address changed, recompiling dataplane`
- The daemon then tears down and recreates VRFs, tunnel anchors, XDP, TC, and cluster heartbeat state.
- During that rebind storm it can hit transient failures such as:
  - `failed to compile dataplane ... attach tcx link: no such device`
- The node restarts cluster heartbeat after VRF rebind.

Interpretation:

- The rebooted node is not returning quietly.
- A management-only DHCP lease refresh is triggering a full dataplane recompile.
- That recompile restarts cluster transport and destabilizes sync/fabric readiness while the survivor is already primary.

### 3. Warm standby is treated like a cold standby

Repro:

- Let a standby complete at least one successful bulk sync.
- Drop and restore the fabric/session-sync connection by rebooting the peer or
  restarting cluster comms.
- Attempt manual failover or failback before a brand new bulk transfer completes.

Observed:

- `cluster: sync peer disconnected` resets `syncReady=false`.
- The standby remains in:
  - `Takeover ready: no (session sync not ready)`
- Promotion then waits on:
  - bulk sync completion
  - plus the normal takeover hold timer

Interpretation:

- This is too strict once the standby already has a valid local session table.
- The code is treating every reconnect like a fresh boot.
- That unnecessarily stretches the outage window on manual failover and on
  crash/rejoin failback.

## Root causes

### Root cause A: stale fast path survives HA ownership changes

Current flow-cache validation checks only:

- 5-tuple
- ingress ifindex
- config generation
- FIB generation

It does not revalidate HA ownership on cache hits.

That is insufficient because an RG move changes forwarding ownership without necessarily changing:

- config generation
- userspace FIB generation

So a cached `ForwardCandidate` remains usable on the old owner even though the RG is no longer locally active.

Updated finding:

- This is only a partial root cause.
- Bulk TCP data packets in the failing `iperf3` repro are mostly `PSH|ACK`, not
  pure `ACK`, so they bypass the flow-cache fast path entirely.
- A cache-only fix improves the first stale-owner window but does not solve the
  failover collapse on its own.

### Root cause B: management DHCP events are treated as full dataplane events

In this lab, DHCP runs on `fxp0`, which is management-only.

A lease refresh on `fxp0` should only require:

- address/route refresh on the management VRF
- possibly DNS update

It should not require:

- full `applyConfig`
- VRF teardown/recreate for dataplane objects
- XDP/TC detach/reattach
- cluster heartbeat restart
- userspace helper startup/rebind churn

The current callback does a full recompile for any DHCP address change.

### Root cause C: sync readiness is reset on reconnect even after a valid bulk sync

Current behavior:

- `OnBulkSyncReceived` sets `syncReady=true`
- `OnPeerDisconnected` always sets `syncReady=false`
- only initial daemon startup arms the timeout fallback that can release the hold

That means:

- a standby that already completed bulk sync is treated as cold again on every
  disconnect/reconnect
- reconnect failover waits for a brand new bulk sync even though the standby
  still has a valid baseline session table
- freshly booted standbys can also deadlock behind `session sync not ready`
  after reconnect because the timeout fallback is not re-armed

### Root cause D: stale-owner fabric-redirect sessions are filtered out of userspace session sync

Current daemon logic only syncs userspace session deltas when:

- the local node is primary for `delta.OwnerRGID`, or
- the local node is primary for the ingress zone's RG

That is wrong for stale-owner failover traffic:

- the old owner is no longer primary for the ingress zone
- but it is still the node that first observes the packet and creates the
  userspace forward session that the new owner needs
- if that forward session is a fabric redirect, the delta is still dropped by
  the primary-only filter

Result:

- the new owner never receives the forward session open
- no shared forward-wire alias is published for the already-SNATed wire packet
- established traffic goes to zero and does not recover

### Root cause E: demotion is not staged; the old owner can redirect before the new owner is primed

What the tighter failover captures show:

- If we leave the current behavior alone, the old owner can keep forwarding
  locally for a short interval after demotion.
- If we force earlier invalidation on the old owner, the new owner starts
  seeing the stale-owner traffic immediately, but it then shows:
  - large `session_miss`
  - `missing_neighbor` on the already-SNATed forward-wire flow
  - very little sustained WAN transmit

Interpretation:

- The new owner is still not guaranteed to have the stale-owner forward session
  alias before redirected data arrives.
- Demotion currently does too many things asynchronously and independently:
  - invalidate caches
  - republish forward sessions
  - refresh reverse sessions
  - delete old live-session pins
  - start redirecting on the old owner
- Those actions need a defined ordering, not just "same control update, best
  effort by workers."

## Plan

### Phase 1: stage demotion before redirect

1. Add an explicit demotion-prep worker command for the old owner RG.
2. In that prep phase, refresh and republish all local forward sessions for the
   demoted RG with peer-usable WAN resolution and forward-wire aliases.
3. Refresh reverse companions against the post-demotion HA view.
4. Track worker acks for demotion prep.
5. Only after all workers ack:
   - mark the RG demoted for live forwarding
   - delete old live-session pins from `USERSPACE_SESSIONS`
   - cancel queued stale-owner TX work

Expected result:

- the new owner already has the forward-wire session materialized before
  redirected data arrives
- the old owner stops forwarding locally without creating a new-owner
  `session_miss` storm

### Phase 2: tighten stale-owner fast-path invalidation

1. Keep HA revalidation on every flow-cache hit.
2. Invalidate stale-owner cached decisions after the staged demotion-prep
   handshake, not before it.
3. Record the correct owner RG in flow-cache metadata for targeted
   invalidation/debugging.

Expected result:

- cache hits stop extending the stale-owner local-forward window
- but they no longer race ahead of forward-session republish

### Phase 3: stop management-only DHCP from destabilizing rejoin

1. Distinguish management-only DHCP lease changes from dataplane-relevant DHCP changes.
2. For management-only lease changes:
   - refresh management VRF routes only
   - do not call full `applyConfig`
3. Keep full recompile only for DHCP changes that actually affect dataplane forwarding.

Expected result:

- rebooted node returns without tearing down dataplane state a second time
- cluster sync/heartbeat remains stable when the node rejoins

### Phase 4: preserve warm-standby sync readiness across reconnects

1. Track whether the standby has ever completed a real bulk sync since local
   startup/dataplane reset.
2. On peer disconnect:
   - preserve `syncReady` if a valid bulk baseline already exists
   - otherwise clear it and re-arm the timeout fallback
3. On peer reconnect:
   - immediately restore `syncReady` for a warm standby
   - re-arm the timeout fallback for a cold standby
4. Keep `OnBulkSyncReceived` as the authoritative transition that marks the
   standby as fully primed.

Expected result:

- crash/rejoin no longer makes a previously-synced standby ineligible again
- manual failback does not wait for a brand new bulk transfer when a warm
  standby already has usable session state
- cold standbys still have a bounded timeout instead of an indefinite block

### Phase 5: harden validation

Add explicit validation for both failure classes:

1. Manual RG move under sustained `iperf3`
   - require traffic to recover
   - require old-owner flow-cache behavior to stop pinning the flow locally
2. Crash/rejoin under sustained traffic
   - require surviving node to take over
   - require traffic to continue after the rebooted node reconnects
   - require sync readiness to recover and remain stable after rejoin

### Phase 6: sync stale-owner fabric redirects to the new owner

1. Mark userspace session deltas explicitly when the forward decision is a
   `FabricRedirect`.
2. Allow those deltas through daemon-side session sync even when the local node
   is no longer primary for the ingress zone.
3. Keep fabric-ingress packets excluded so the new owner does not re-sync the
   same flow back to the old owner.

Expected result:

- the new owner receives the canonical forward session open for stale-owner
  fabric-redirected flows
- the helper publishes the shared forward-wire alias on the new owner
- established `iperf3` flows survive manual RG moves instead of falling into
  `session_miss -> slow_path`

## Execution order

1. Implement staged demotion-prep and worker acking for RG handoff.
2. Re-test manual RG move with tight 1s/2s post-failover snapshots.
3. Re-introduce cache-side HA invalidation only after the staged handoff is in place.
4. Implement management-only DHCP no-recompile path.
5. Preserve warm-standby sync readiness across reconnects.
6. Re-test crash/rejoin and manual failback.
7. Extend failover validation to cover crash/rejoin.
8. Keep the stale-owner fabric-redirect sync exemption and retest manual RG move.

## Acceptance criteria

### Manual RG move

- `iperf3` no longer dies permanently on `request chassis cluster failover redundancy-group 1 node 1`
- old owner no longer shows a sustained local WAN forward window after demotion
- new owner actually carries the flow
- new owner shows forward-wire session hits instead of large `session_miss`
  growth for the already-SNATed wire flow after the move

### Crash/rejoin

- `echo b > /proc/sysrq-trigger` on the active node causes takeover on the survivor
- when the rebooted node returns, traffic does not drop to zero again
- `session sync ready` recovers and stays stable
- no management-DHCP-triggered full dataplane recompile occurs for `fxp0`
- a previously-synced standby does not become ineligible again just because the
  sync connection bounced
