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

Updated live finding after staged demotion-prep and peer barrier ack:

- The staged handoff now completes successfully for manual `RG1 node0 -> node1`
  moves.
- The old owner logs:
  - `cluster sync: barrier ack received`
  - `userspace: prepared rg demotion`
  - `cluster: manual failover`
- The new owner logs:
  - `cluster sync: barrier received`
  - `cluster sync: barrier ack sent`
  - `cluster: primary transition`
- After that, the established `iperf3 -P 4` flow stays healthy for roughly
  5-6 seconds on the stale-owner fabric path, then collapses without a
  `session_miss` storm.

High-resolution monitor captures from
`./failover-debug/continuous-monitors-long-20260327-085209` show:

- old owner LAN ingress (`ge-0/0/1`) continues strongly through
  `15:52:17` and then goes flat around `15:52:18`
- old owner fabric TX (`ge-0/0/0`) continues strongly through
  `15:52:17` and then goes flat around `15:52:18`
- new owner fabric RX/TX (`ge-7/0/0`) continues strongly through
  `15:52:17` and then goes flat around `15:52:18`
- new owner WAN TX (`ge-7/0/2`) continues strongly through
  `15:52:17` and then goes flat around `15:52:18`
- no corresponding spike in userspace `Session misses`

Interpretation:

- The barrier/handoff stage is no longer the primary blocker.
- The established redirected flow now survives the ownership move.
- The remaining failure is a post-transition stale-owner fabric dataplane
  collapse under sustained load, not a pre-transition demotion-prep miss.

Latest gated failover result after pre-failover sync-idle checks and
transition-window sampling:

- The run now gets through:
  - pre-failover sync-idle
  - demotion prepare
  - barrier ack
  - RG1 move to `node1`
- Immediate failover checks pass:
  - target reachability
  - external IPv4/IPv6 reachability
  - zero transition-window `Kernel RX dropped`
  - zero transition-window `Direct TX no-frame`
- But the flow still is not healthy under sustained load:
  - all four `iperf3` streams can hit `0.00 bits/sec` in the failover phase
  - the new owner shows small but real `Policy denied packets` growth
  - the remote `iperf3` client can stall at zero throughput and remain hung
    until explicitly terminated

Interpretation:

- the remaining failure is not a simple barrier timeout anymore
- it is a sustained post-transition transport failure on the redirected path
- the failover harness must treat a hung remote `iperf3` client as a hard
  failover failure rather than letting the run hang indefinitely

Latest gated failover result after repeated direct-mode post-failover
re-announcement bursts:

- One-cycle harness run now passes end-to-end:
  - sender throughput `20.685 Gbps`
  - sender retransmits `4047`
  - `0` zero-throughput intervals
  - target + external IPv4/IPv6 reachability all pass
- Transition-window path counters from
  `./userspace-ha-failover-rg1-20260327-100223` show:
  - old-owner LAN RX delta `11`
  - old-owner fabric TX delta `11`
  - new-owner fabric RX delta `14`
  - new-owner WAN TX delta `11`

Interpretation:

- The repeated GARP/NA schedule materially improves the LAN-side ownership move.
- In the passing gated run, traffic does not remain pinned to the old owner:
  the stale-owner window is tiny and redirected packets are observed on the
  new owner immediately.
- The remaining manual-failover issue is no longer "traffic always collapses
  after the move"; it is "manual failover is still blocked unless the session
  sync path is quiescent enough to admit the move."

Manual failover behavior after the runtime quiescence gate work:

- early manual failover under active load now fails closed instead of
  blackholing traffic:
  - the CLI returns a demotion-prep quiescence error
  - the daemon logs repeated preflight barrier attempts
- later manual failover, after the sync stream has settled, is admitted and the
  RG move completes
- but even in that admitted case the redirected `iperf3` flow still degrades to
  zero throughput and hangs until terminated

Interpretation:

- the quiescence gate is a keep: it stops unsafe failover attempts from
  proceeding blindly
- it does not solve the remaining dataplane problem
- once failover is admitted, the surviving bug is still sustained
  post-transition fabric transport collapse

Latest manual failover admission result after bounded retry:

- The exact operator command now blocks and succeeds instead of failing closed:
  - `request chassis cluster failover redundancy-group 1 node 1`
  - `rc=0`
  - `elapsed_ms=6531`
- Artifact:
  - `./manual-failover-retry2-20260327-102950`
- The data-plane result is still bad after admission:
  - flow reaches `~20.4 Gbps` peak before failover
  - then drops to `12.7 Gbps`
  - then goes to sustained `0.0 Gbps`
  - `52` zero intervals after peak

Interpretation:

- Manual failover admission is no longer the blocker.
- The remaining manual-failover bug is now clearly post-admission dataplane
  continuity, not control-plane quiescence gating.

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

Latest crash/rejoin result on the re-announce build:

- Artifact:
  - `./sysrqb-rejoin-20260327-103142`
- Repro:
  - long `iperf3 -c 172.16.80.200 -P 4`
  - `echo b > /proc/sysrq-trigger` on active `node0`
- Observed:
  - short disruption during crash takeover:
    - one interval `2.79 Gbps`
    - then two `0.0 Gbps` intervals
    - then one `9.57 Gbps` interval
  - after that, traffic recovers to `~15-16 Gbps` and stays there
  - no late collapse after the rebooted node returns
  - end-of-run tail throughput stays healthy:
    - tail median `15.79 Gbps`
    - tail/peak ratio `0.95`
  - external `1.1.1.1` ping log shows replies at the end of the observation
  - final cluster state is stable:
    - `node1` primary
    - `node0` secondary
    - both takeover-ready

Interpretation:

- The repeated re-announce + current failover gating materially improve the
  crash/rejoin case.
- The survivor takeover and returning-node rejoin no longer reproduce the old
  “comes back and kills traffic again” behavior in this run.
- The remaining high-value failure is the manual failover dataplane collapse
  after an admitted RG move.

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

Status after the staged demotion-prep work:

- This root cause is now largely addressed for manual failover.
- The peer barrier is delivered and acked.
- Duplicate demotion-prep is suppressed across the barrier wait.
- Manual `RG1` failover now succeeds without the earlier immediate
  blackhole-or-timeout failure.

That means the remaining long-lived flow collapse is no longer explained by
the original unstaged handoff itself.

### Root cause F: stale-owner fabric transit cannot sustain the inherited established-flow rate after failover

What the latest long-window capture shows:

- immediately after the new owner becomes primary, the stale-owner path carries
  the already-established flow at tens of Gbps for several seconds
- the new owner fabric interface records an immediate input-drop jump when the
  redirected burst arrives
- the stale-owner fabric path and new-owner WAN path then flatten together
  around 5-6 seconds after primary transition
- userspace miss counters stay essentially flat during the collapse

Interpretation:

- The connection is no longer dying because the new owner missed the session
  alias before the first redirected packets arrived.
- It is now dying because the post-transition fabric path is too lossy under
  the inherited established-flow rate, and TCP eventually collapses.
- This matches the earlier stale-owner fabric performance ceiling work:
  the path is functionally correct, but materially weaker than the direct WAN
  path.

The failover problem is therefore split into two layers:

1. control correctness: barrier, session handoff, peer install ordering
2. post-handoff transport quality: stale-owner fabric throughput/drop behavior

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

Status:

- No longer the top blocker for the current manual failover repro.
- The latest capture shows the established flow surviving the ownership move
  and then collapsing later without miss growth.

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

Status:

- The staged handoff work plus barrier delivery now appear to have solved the
  original forward-wire install race for the manual failover case.
- The next failure is no longer `session_miss -> slow_path`; it is
  post-transition throughput collapse on the fabric path.

### Phase 7: instrument and mitigate post-transition fabric collapse

1. Keep the staged demotion-prep/barrier logic as-is for manual failover.
2. Treat the remaining problem as stale-owner fabric transport quality, not
   as another pre-transition sync bug.
3. Add explicit failover metrics for the full post-transition collapse window,
   not only the first 10 seconds after primary transition:
   - old owner LAN RX
   - old owner fabric TX
   - new owner fabric RX/TX
   - new owner WAN TX
   - fabric interface drops
   - retransmits / zero-throughput intervals
4. Confirm whether the collapse is:
   - immediate fabric drop saturation on the new owner
   - old-owner fabric TX starvation/backpressure
   - return-path loss causing client TCP to back off to zero
5. Only after that choose the mitigation:
   - temporary failover pacing / dampening on stale-owner fabric redirect
   - higher-capacity / lower-loss fabric dataplane path
   - queueing / wake / batching changes specific to the fabric bindings

Expected result:

- we stop conflating control-plane handoff correctness with fabric throughput
  collapse
- the next code changes target the actual remaining bottleneck instead of
  reopening the now-working barrier path

## Execution order

1. Implement staged demotion-prep and worker acking for RG handoff.
2. Re-test manual RG move with tight 1s/2s post-failover snapshots.
3. Re-introduce cache-side HA invalidation only after the staged handoff is in place.
4. Implement management-only DHCP no-recompile path.
5. Preserve warm-standby sync readiness across reconnects.
6. Re-test crash/rejoin and manual failback.
7. Extend failover validation to cover crash/rejoin.
8. Keep the stale-owner fabric-redirect sync exemption and retest manual RG move.
9. After the handoff is proven correct, instrument the first 10 seconds of
   stale-owner fabric forwarding and address the remaining throughput collapse
   as a transport-quality problem.

## Acceptance criteria

### Manual RG move

- `iperf3` no longer dies permanently on `request chassis cluster failover redundancy-group 1 node 1`
- old owner no longer shows a sustained local WAN forward window after demotion
- new owner actually carries the flow
- the post-transition stale-owner fabric path stays alive instead of collapsing
  a few seconds after primary transition
- retransmits and fabric input drops stay within the failover budget

### Crash/rejoin

- `echo b > /proc/sysrq-trigger` on the active node causes takeover on the survivor
- when the rebooted node returns, traffic does not drop to zero again
- `session sync ready` recovers and stays stable
- no management-DHCP-triggered full dataplane recompile occurs for `fxp0`
- a previously-synced standby does not become ineligible again just because the
  sync connection bounced
