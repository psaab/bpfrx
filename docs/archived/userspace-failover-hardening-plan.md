# Userspace Failover Hardening Plan

## Problem statement

The userspace HA failover path is still flaky in two distinct ways:

1. Manual redundancy-group moves under established load can blackhole long-lived flows.
2. Crash/rejoin recovery can succeed briefly, then destabilize again when the rebooted node returns.

These are not the same bug. They need separate fixes and separate validation.

There is now a third validation/environment constraint:

3. The lab WAN50/public path was independently broken on March 28, 2026.
   External internet checks must be isolated from userspace failover checks
   during that outage.

There is a fourth control-plane issue underneath both of them:

4. Session-sync readiness is still treated as "a fresh bulk sync completed on
   this connection" instead of "this standby has a valid sync baseline."

There is now a fifth dataplane-specific issue that shows up after the earlier
cache and sync-readiness fixes:

5. The new owner can still miss post-failover forward-wire sessions for flows
   first observed on the old owner after the RG move.

There is now a sixth narrowing result from the traced `2026-03-28` artifact:

6. The remaining bad `fw1` sessions are being materialized through
   `shared_promote` on translated public-side tuples after failover.

There is now a seventh confirmed dataplane result from the latest `2026-03-28`
artifact:

7. Established redirected packets that hit the flow-cache fast path were still
   selecting the fabric egress binding by ingress queue instead of by per-flow
   fabric hash, collapsing inherited failover traffic onto one worker.

There is now an eighth post-merge finding from the March 28 reruns:

8. After the queue-selection and sync-disconnect fixes, admitted failover
   traffic can stay healthy through the ownership move, but the new owner VM
   can reboot under load, causing the old owner to reclaim `RG1`.

There is now a ninth checkpoint from the March 30 reruns on top of the
`#295` + `#296` baseline:

9. Fixing the XDP attach-mode / AF_XDP bind-mode mismatch restored steady-state
   forwarding, but it did not fix the HA dataplane failures:
   - manual `RG1` failover under `iperf3 -P 8` still collapses with a large
     new-owner `session_miss` burst
   - all-RGs-on-primary crash/rejoin is materially better
   - split-RG crash still fails badly, and split ownership can leave
     `session sync not ready` stuck on the survivor

There is now a tenth checkpoint from the later March 30 reverse-prewarm pass:

10. The latest reverse-session activation fix removes the large new-owner
    `session_miss` burst on first failover, but the manual `RG1` failover still
    collapses immediately after the move with stable ownership and low miss
    counters.

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

Latest March 30, 2026 rerun on the corrected XDP-mode baseline:

- artifact:
  - `/tmp/userspace-ha-failover-rg1-20260330-092213`
- configuration:
  - `#295` + `#296`
  - `iperf3 -P 8`
  - `3` failover cycles
- result:
  - `1539` zero-throughput intervals
  - `1368` per-stream zero-throughput intervals
  - sender throughput `4.280 Gbps`
  - sender retransmits `115`

Most important first-failover counters:

- old-owner LAN RX delta `5865927`
- old-owner fabric TX delta `38353`
- new-owner fabric RX delta `28494`
- new-owner WAN TX delta `7`
- new-owner session miss delta `28489`

Interpretation:

- restoring correct AF_XDP bind mode fixed the unrelated steady-state
  forwarding break
- the surviving manual failover bug is still the inherited-flow ownership move
- the first real failover still explodes `session_miss` on the new owner under
  `-P 8`

Latest March 30, 2026 rerun after reverse-session activation prewarm:

- code checkpoint:
  - `c84c35c7` `userspace: prewarm reverse sessions for activated RGs`
- artifacts:
  - `/tmp/userspace-ha-failover-rg1-20260330-174231`
  - `/tmp/manual-oneway-rg1-20260330-174744`

Observed result:

- the first failover no longer shows the earlier large new-owner
  `session_miss` burst
- in the one-way failover run:
  - `fw0 Session misses` stays flat at `29`
  - `fw1 Session misses` stays flat at `27-28`
  - `fw1 Sessions installed` starts at `151` and later reaches `216`
  - cluster ownership remains stable with `node1` primary for `RG1`
- despite that, `iperf3 -P 8` still collapses:
  - pre-failover steady state holds near `20 Gbps`
  - the first bad interval drops to `3.17 Gbps`
  - the next interval is `0.00 bits/sec`
  - tail median remains `0.000 Gbps`

Interpretation:

- the reverse-session activation fix is a keep; it materially narrowed the
  problem
- the remaining bug is no longer “new owner cannot install inherited state”
- the next work needs to target stale-owner demotion / redirected transport
  continuity after ownership moves

Rejected follow-up experiment on March 30, 2026:

- `b319046b` attempted to make demotion cleanup delete the full shared
  session-map alias set immediately
- that change regressed the failover signature back to a large new-owner
  `session_miss` storm
- artifact:
  - `/tmp/manual-oneway-rg1-20260330-175924`
- measured result:
  - `fw1 Session misses: 28077 -> 28086`
  - `fw1 Sessions installed: 140 -> 203`
  - `fw1 TX packets: 0 -> 57`

Interpretation:

- the demotion alias set cannot be purged naïvely at the first ownership edge
- some alias continuity is still required during the handoff window
- the surviving bug remains in the demotion / redirected transport transition,
  but the fix must be more selective than full immediate alias deletion

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

Latest traced failover result after session-origin instrumentation:

- artifact:
  - `/tmp/userspace-ha-failover-rg1-20260328-064556`
- the bad `fw1` recent session deltas are:
  - `origin=shared_promote`
  - `172.16.80.8:37612 -> 172.16.80.200:5201`
  - `172.16.80.8:37624 -> 172.16.80.200:5201`
  - `172.16.80.8:37638 -> 172.16.80.200:5201`
  - `172.16.80.8:37644 -> 172.16.80.200:5201`
- the same artifact still shows:
  - `Session misses: 13`
  - `Neighbor misses: 0`
  - `Route misses: 0`
  - `Policy denied packets: 0`
  - `Slow path local-delivery: 4196`

Interpretation:

- the remaining poison is no longer best explained by:
  - ACK-miss local-delivery caching
  - worker-local alias leakage
  - daemon-side `local_delivery` sync
- the next narrowing target is the translated-hit promotion path in
  `userspace-dp/src/afxdp/session_glue.rs`
- the next fix to test is keeping translated public-side shared hits transient
  on fabric ingress instead of promoting and republishing them

Latest failover result after keeping translated shared hits transient and fixing
cached fabric queue selection:

- artifact:
  - `/tmp/userspace-ha-failover-rg1-20260328-072043`
- one-cycle hardened failover gate result:
  - `0` zero-throughput intervals
  - `0` per-stream zero-throughput intervals
  - sender throughput `8.673 Gbps`
  - sender retransmits `12771`
  - no interval collapse

What changed materially:

- the failover no longer reproduces the old `~7 Gbps then 0` collapse
- old-owner redirected fabric TX is spread across multiple queues instead of
  concentrating on a single queue
- new-owner fabric RX and WAN TX are also spread across multiple queues

Queue evidence from the passing artifact:

- old owner `ge-0-0-0` TX:
  - queue `0`: `1.14M`
  - queue `1`: `1.18M`
  - queue `2`: `2.67M`
- new owner `ge-7-0-0` RX:
  - queue `0`: `201k`
  - queue `1`: `1.13M`
  - queue `2`: `1.03M`
  - queue `3`: `1.49M`
  - queue `5`: `1.15M`
- new owner `ge-7-0-2` TX:
  - queue `1`: `7.16M`
  - queue `3`: `12.08M`
  - queue `4`: `10.23M`
  - queue `5`: `7.18M`

Interpretation:

- the failing single-queue redirected-flow concentration was real
- the flow-cache fabric-queue selection bug was a real contributor to the
  manual failover collapse
- the next work should move away from session-origin tracing and toward:
  - repeated failover-cycle validation
  - crash/rejoin on the new build
  - retransmit reduction inside the now-passing failover window

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

Latest crash/rejoin result on top of the fabric queue-selection fix:

- Artifact:
  - `/tmp/sysrqb-rejoin-20260328-072503`
- Repro:
  - long `iperf3 -c 172.16.80.200 -P 4`
  - `echo b > /proc/sysrq-trigger` on active `node0`
- Observed:
  - takeover: `ok`
  - rejoin: `ok`
  - short disruption during crash takeover:
    - one interval `7.45 Gbps`
    - then two `0.0 Gbps` intervals
    - then one `1.33 Gbps` interval
  - after that, traffic recovers to `~13-14 Gbps` and stays there
  - no late collapse after the rebooted node returns
  - end-of-run tail throughput stays healthy:
    - tail median `13.51 Gbps`
    - tail/peak ratio `0.96`
  - final cluster state is stable:
    - `node1` primary
    - `node0` secondary
    - both takeover-ready

Interpretation:

- the fabric queue-selection fix did not regress crash/rejoin
- the survivor takeover and returning-node rejoin remain stable on the new build
- the remaining open work stays concentrated in the manual RG-move path, not
  hard-crash recovery

Latest multi-cycle note:

- the first attempted two-cycle rerun after the crash/rejoin pass stopped in
  steady-state preflight because external IPv6 was unreachable in the lab:
  - `/tmp/userspace-ha-failover-rg1-20260328-072932`
- that artifact is a lab preflight failure, not a dataplane failover verdict

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

### Root cause C: failover admission was using the wrong sync-direction signal

Earlier behavior:

- `OnBulkSyncReceived` set the coarse inbound `syncReady` signal
- reconnect/disconnect churn could clear readiness without distinguishing:
  - "I have received peer bulk"
  - "the peer has ingested my bulk"
- manual failover admission was therefore using the wrong proof for the
  demoting node's safety check

Updated status:

- current code now distinguishes:
  - `syncBulkPrimed`: inbound peer bulk received
  - `syncPeerBulkPrimed`: peer explicitly acknowledged my bulk via `BulkAck`
- manual failover admission now correctly waits on sender-side peer ack
- cluster election still uses the coarser timeout-backed readiness path

What is still broken:

- the sender-side admission model is now correct
- current-generation `node0 -> node1` bulk completion is now observed
- but the retry loop can still send later bulk epochs before the first one is
  acknowledged

So the remaining bug is no longer "reconnect readiness is too coarse." It is:

- later retry bulks occupy the same ordered stream as demotion barriers
- the peer eventually receives and acknowledges the barriers
- but not within the manual-failover quiescence window

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

### Root cause G: transient WAN TCP ACK misses were being cached as helper-local sessions on the new owner

What the direction-specific repros showed:

- `node1 -> node0` failover was healthy
- `node0 -> node1` failover collapsed
- the failing direction did not show a large `session_miss` storm
- instead, the new owner WAN binding showed:
  - very small `session_miss` growth
  - rapidly increasing `Slow path packets`
  - almost all of that growth in `local`

Interpretation:

- transient post-failover reply misses to the interface-NAT external IP were
  being resolved as `LocalDelivery`
- the helper was then caching those TCP ACK misses as local sessions
- once cached, later packets no longer showed up as repeated session misses;
  they kept hitting the poisoned local session and returning to slow path as
  helper-local delivery

Status:

- This root cause was real, but it was not sufficient.
- TCP ACK misses for interface-NAT-derived `LocalDelivery` are no longer cached
  as helper-local sessions.
- The simplified artifact
  `/tmp/manual-rg1-forward-simple7-20260327-230430` stayed healthy at about
  `20.7 Gbps` with `0` retransmits and no collapse.
- But the stronger harness still failed later on:
  - `/tmp/userspace-ha-failover-rg1-20260327-232956`
  - `/tmp/userspace-ha-failover-rg1-20260327-234049`
  - `/tmp/userspace-ha-failover-rg1-20260327-235148`

### Root cause H: public-side `LocalDelivery` state is still being materialized on the new owner from a path other than ACK-miss caching

What the later narrowing fixes tried:

- helper-local `LocalDelivery` sessions were kept out of shared worker alias maps
- daemon session-sync deltas were extended with explicit `disposition`
- daemon-side HA session sync was changed to skip `local_delivery` deltas

What the later artifacts showed anyway:

- the new owner still accumulates large `Slow path local-delivery` counts in the
  failover window:
  - `/tmp/userspace-ha-failover-rg1-20260327-232956`
    - `2 -> 1598 -> 4800`
  - `/tmp/userspace-ha-failover-rg1-20260327-234049`
    - `14 -> 1298 -> 3240`
  - `/tmp/userspace-ha-failover-rg1-20260327-235148`
    - `2 -> 4488 -> 6632`
- the new owner still shows public-side sessions such as:
  - `172.16.80.8:<port> -> 172.16.80.200:5201`
  - `Out: 172.16.80.200/5201 -> 172.16.80.8:<port>; If: reth0.50`
- session/neighbor/route miss growth stays low during the same runs

Interpretation:

- the remaining poison is not explained only by:
  - transient TCP ACK miss caching
  - shared worker alias publication
  - daemon-side session-sync replication
- the new owner is still materializing public-side `LocalDelivery` state from
  some other path, most likely:
  - helper import/replay of a session object
  - shared-hit promotion that preserves `LocalDelivery`
  - another helper-local install path that is not miss-driven

Current status:

- this is now the primary unresolved failover bug class
- the next work should identify exactly which creation/import path is producing
  the bad public-side sessions on `fw1`

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

### Phase 4: keep current-generation sender-side priming from backlogging the stream

1. Keep the split readiness model:
   - election/readiness may use timeout-backed inbound sync state
   - manual demotion must use sender-side peer acknowledgement
2. Allow only one outbound bulk epoch to be outstanding at a time.
3. Defer retry while the previous bulk is still awaiting `BulkAck` inside a
   grace window.
4. Keep the existing instrumentation so future regressions can still prove:
   - bulk start
   - bulk end
   - bulk ack send
   - bulk ack receive

Expected result:

- the demoting node observes `syncPeerBulkPrimed=true` on the current
  connection generation
- demotion barriers are not queued behind stale retry bulks
- manual failover admission stops failing with barrier/quiescence timeout
- only after that should the work return to post-admission dataplane continuity

Current status:

- the one-outstanding-bulk change achieved this control-plane goal in the
  latest manual repro
- manual `RG1 node0 -> node1` failover was admitted
- the original admitted-collapse repro was then traced to poisoned WAN local
  session caching on transient ACK misses
- that forward-direction collapse is now fixed on the current branch

### Phase 5: trace and block remaining public-side `LocalDelivery` materialization

1. Add origin tagging for helper-local session creation/import paths so status
   and delta artifacts can distinguish:
   - miss-created helper-local sessions
   - replayed/imported helper-local sessions
   - promoted shared hits
2. Reproduce the exact hardened RG1 failover and capture the first bad
   `172.16.80.8:<port> -> 172.16.80.200:5201` session on `fw1`.
3. Cut off that exact path narrowly:
   - either refuse the install
   - or rewrite the resolution so public-side translated forward traffic cannot
     become helper-local `LocalDelivery` on the new owner

Expected result:

- `fw1` no longer accumulates public-side `LocalDelivery` sessions during the
  failover window
- `Slow path local-delivery` stops dominating the bad interval
- the next remaining failure, if any, is a pure redirected transport problem

### Phase 6: harden validation

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

### Phase 8: harden sync-disconnect behavior and investigate new-owner reboot

What changed on March 28, 2026:

- `onSessionSyncPeerDisconnected()` was changed to stop clearing readiness via a
  timeout fallback
- this removed the earlier "peer disconnected, then both sides auto-release
  hold and re-enter election" split-brain failure
- the failover harness also gained `CHECK_EXTERNAL_REACHABILITY=0` so WAN-path
  outages can be isolated instead of being misreported as dataplane failures

What the rerun proved:

- external preflight failure was real but environmental:
  - `1.1.1.1` and `2606:4700:4700::1111` were unreachable
  - local `.200` IPv4/IPv6 still worked
  - active `fw0` could not reach `172.16.50.1` or `2001:559:8585:50::1`
- with external checks disabled, the two-cycle gate reached the failover path
  and the traffic itself stayed healthy through the move
- the move still did not stick:
  - `node1` later logged `clearing manual failover (peer lost)`
  - `RG1` returned to `node1`
  - `fw0` crossed a journal boot boundary around `2026-03-28 14:58:10 UTC`
  - that proves the new owner VM rebooted after becoming primary

Next actions:

1. determine why `xpf-userspace-fw0` rebooted under admitted failover load
2. separate:
   - kernel panic / watchdog reset
   - host-side VM reset
   - explicit automation reboot
3. rerun the same two-cycle gate only after that reboot cause is understood

Expected result:

- the failover result becomes stable enough to validate multi-cycle behavior
- the remaining blocker is no longer hidden behind an uncontrolled VM reboot

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
10. Preserve the WAN local-session caching fix and rerun the full hardened
    failover gate on the repaired branch.
11. Reconfirm reverse-direction manual failover and crash/rejoin on the same
    build before declaring the failover path stable.
12. Investigate and eliminate the new-owner reboot observed after the admitted
    March 28 failover rerun.

## Acceptance criteria

### Manual RG move

- `iperf3` no longer dies permanently on `request chassis cluster failover redundancy-group 1 node 1`
- old owner no longer shows a sustained local WAN forward window after demotion
- new owner actually carries the flow
- the post-transition stale-owner fabric path stays alive instead of collapsing
  a few seconds after primary transition
- the new owner stays up after primary transition; no unexpected VM reboot or
  daemon restart occurs
- retransmits and fabric input drops stay within the failover budget
- transient WAN reply misses do not poison the new owner into helper-local
  session caching

### Crash/rejoin

- `echo b > /proc/sysrq-trigger` on the active node causes takeover on the survivor
- when the rebooted node returns, traffic does not drop to zero again
- `session sync ready` recovers and stays stable
- no management-DHCP-triggered full dataplane recompile occurs for `fxp0`
- a previously-synced standby does not become ineligible again just because the
  sync connection bounced
- the returning node does not cause a second collapse after rejoin
