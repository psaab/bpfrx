# Userspace Failover Next Steps

## Goal

Get userspace HA failover to a state where both of these are true:

- manual redundancy-group moves preserve long-lived traffic without collapsing to sustained zero throughput
- crash/rejoin of the active node fails over and the returning node rejoins without destabilizing the survivor

The current work is now split into two validation buckets:

1. manual `RG1` moves must remain healthy in both directions under established `iperf3`
2. crash/rejoin must fail over and stay stable after the rebooted node returns

## What is already improved

The recent failover work materially improved safety and observability.

Working or materially better now:

- manual failover no longer proceeds blindly on the first transient sync-admission failure
- crash/rejoin is materially better on the current build than it was before the re-announce and gating work
- direct-mode failover uses repeated post-transition GARP/NA re-announcements
- the failover validator now treats hung remote `iperf3` as a hard failure
- the monitor and failover tooling expose stale-owner LAN/fabric/WAN counters well enough to separate control-plane admission failures from dataplane continuity failures
- cached redirected failover traffic no longer pins itself to the ingress queue on the fabric fast path

Validated artifacts from the earlier work:

- crash/rejoin: `/tmp/sysrqb-rejoin-20260327-105330`
- admitted manual failover collapse: `/tmp/manual-rg1-jsonstream-20260327-105647`
- deep interface-window capture: `/tmp/manual-rg1-deep-20260327-105921`

## What changed in the latest passes

The earlier session-sync admission work is now in place and no longer the
active blocker for the manual repro.

What landed:

- manual failover admission now waits on sender-side acknowledgement of the current-generation bulk sync
- stacked retry bulks are suppressed while a previous bulk is still awaiting `BulkAck`
- demotion barriers are no longer delayed behind stale retry bulk epochs
- the helper-side failover handoff stays instrumented enough to separate:
  - admission failures
  - post-admission dataplane failures

The later dataplane work narrowed, but did not eliminate, the post-failover
poisoning path.

What landed after that:

- transient TCP ACK misses to WAN `LocalDelivery` targets are no longer cached as helper-local sessions
- helper-local `LocalDelivery` sessions are no longer published into shared worker alias maps
- userspace session-sync deltas now carry `disposition`
- daemon-side HA session sync now refuses to mirror `local_delivery` deltas to the peer
- cached `FabricRedirect` flow-cache hits now use the same per-flow fabric queue hash as the slow path instead of inheriting ingress queue affinity

What those fixes proved:

- the original ACK-miss caching bug was real
- shared helper alias pollution was real
- but neither of those changes removed the core hardened-harness collapse
- the new owner still accumulates public-side `LocalDelivery` state during failover from some other path
- the traced `2026-03-28` artifact narrows that remaining path to
  `shared_promote` on the new owner, not `local_miss`, `sync_import`, or
  `missing_neighbor_seed`

What the newest queue-selection fix proved:

- the remaining failover collapse was not just session poisoning
- established redirected traffic was still hitting the flow-cache fast path and selecting the fabric egress binding by ingress queue
- under the failing artifact that pinned almost all redirected traffic to a single fabric worker
- after switching cached `FabricRedirect` hits to the flow-hash queue selector, the same hardened one-cycle failover gate passed without collapse

## What is still broken

The original `node0 -> node1` hardened one-cycle manual failover collapse is no
longer reproducing on the latest branch build.

What is still broken:

- crash/rejoin still needs to be rerun on top of the latest fabric queue-selection fix
- the strengthened failover gate still needs repeated multi-cycle validation, not just one passing cycle
- retransmits are still higher than ideal during the passing failover window

What is still improved:

- sync admission and bulk priming are no longer the blocker
- target and external reachability stay up during the bad run
- crash/rejoin is still materially better than the old baseline

## Latest evidence

The simplified manual repro improved, but the stronger failover gate still
fails after each of the latest narrowing fixes.

Validated forward-direction artifact:

- `/tmp/manual-rg1-forward-simple7-20260327-230430`

Measured result:

- `avg_gbps`: `20.74487928558069`
- `peak_gbps`: `21.113331112475258`
- `tail_median_gbps`: `20.6870205970763`
- `tail_peak_ratio`: `0.979808467307792`
- `retransmits`: `0`
- `collapse_detected`: `false`
- `zero_intervals_total`: `0`

The matching new-owner WAN monitor in that run showed that the earlier failure
signature was gone:

- `Slow path packets` stayed flat
- there was no renewed `local` slow-path explosion on `ge-7/0/2`

That simplified pass was not sufficient.

The hardened failover validator still failed repeatedly on later checkpoints:

- `/tmp/userspace-ha-failover-rg1-20260327-232956`
  - `4.530 Gbps`
  - `25410` retransmits
  - `fw1 Slow path local-delivery: 2 -> 1598 -> 4800`
- `/tmp/userspace-ha-failover-rg1-20260327-234049`
  - `4.959 Gbps`
  - `14819` retransmits
  - `fw1 Slow path local-delivery: 14 -> 1298 -> 3240`
- `/tmp/userspace-ha-failover-rg1-20260327-235148`
  - `4.119 Gbps`
  - `12568` retransmits
  - `fw1 Slow path local-delivery: 2 -> 4488 -> 6632`

Interpretation:

- the worker-local alias fix helped somewhat
- the daemon-side `local_delivery` sync filter did not fix the collapse
- the newest artifact still shows public-side sessions on `fw1` during the bad window
- therefore the remaining poison is not explained only by:
  - ACK-miss caching
  - shared worker alias publication
  - daemon-side session-sync replication

Latest traced artifact:

- `/tmp/userspace-ha-failover-rg1-20260328-064556`

What it proves:

- the bad `fw1` TCP sessions are created with:
  - `origin=shared_promote`
- the matching failing examples are:
  - `172.16.80.8:37612 -> 172.16.80.200:5201`
  - `172.16.80.8:37624 -> 172.16.80.200:5201`
  - `172.16.80.8:37638 -> 172.16.80.200:5201`
  - `172.16.80.8:37644 -> 172.16.80.200:5201`
- those are the translated public-side tuples, not the canonical client-side
  tuples
- the same artifact still shows:
  - `Session misses: 13`
  - `Neighbor misses: 0`
  - `Route misses: 0`
  - `Policy denied packets: 0`
  - `Slow path local-delivery: 4196`

Interpretation:

- sync admission is no longer the active blocker
- the remaining poison is not being created by the old
  `local_delivery` sync path
- the next narrowing target is the `shared_promote` path in
  `userspace-dp/src/afxdp/session_glue.rs`
- the likely keep is to stop translated public-side shared hits on fabric
  ingress from becoming durable local/shared session state

Latest passing artifact after fixing cached fabric queue selection:

- `/tmp/userspace-ha-failover-rg1-20260328-072043`

Measured result:

- `0` zero-throughput intervals
- `0` per-stream zero-throughput intervals
- sender throughput `8.673 Gbps`
- sender retransmits `12771`
- interval collapse detected: `false`

What it proves:

- the hardened RG1 failover gate now passes end-to-end on the current branch
- the old redirected-flow single-queue concentration was real
- after the fix, redirected traffic fans out across multiple fabric queues on the old owner and multiple fabric/WAN queues on the new owner
- the failover no longer degrades into the earlier `7 Gbps then 0` shape

Key queue-spread evidence from the artifact:

- old owner `ge-0-0-0` TX is spread across:
  - queue `0`: `1.14M`
  - queue `1`: `1.18M`
  - queue `2`: `2.67M`
- new owner `ge-7-0-0` RX is spread across:
  - queue `0`: `201k`
  - queue `1`: `1.13M`
  - queue `2`: `1.03M`
  - queue `3`: `1.49M`
  - queue `5`: `1.15M`
- new owner `ge-7-0-2` TX is spread across:
  - queue `1`: `7.16M`
  - queue `3`: `12.08M`
  - queue `4`: `10.23M`
  - queue `5`: `7.18M`

Crash/rejoin is also materially improved on the same branch.

Validated crash/rejoin artifact:

- `/tmp/sysrqb-rejoin8-20260327-230527`

Measured result:

- `avg_gbps`: `16.000761979104734`
- `peak_gbps`: `18.00647341194518`
- `tail_median_gbps`: `17.208910818226855`
- `tail_peak_ratio`: `0.955706896321562`
- `collapse_detected`: `false`
- `retransmits`: `4388`

Interpretation:

- crash takeover still has a short disruption window
- but the flow recovers and stays up after the rebooted node rejoins
- the old "returning node destabilizes the survivor again" failure did not reproduce in that run

## Current working hypothesis

The current branch is past the original sync-admission and bulk-priming bugs,
and it is also past the worst redirected-flow single-queue collapse.

The next question is now:

- whether crash/rejoin remains stable on top of the new fabric queue-selection fix
- whether the one-cycle manual pass holds up under repeated cycles and longer runs
- whether retransmit levels during the passing failover window can be reduced further

## Next code steps

### 1. Re-run crash/rejoin on the current queue-spread build

Use the exact same crash/rejoin gate that previously improved but was not yet
validated on top of the queue-selection fix.

Acceptance:

- active-node crash fails over cleanly
- the returning node does not destabilize the survivor
- no post-rejoin throughput collapse

### 2. Run repeated multi-cycle RG1 moves on the current build

The single-cycle pass is necessary but not sufficient.

Acceptance:

- repeated `RG1 node0 -> node1 -> node0` cycles stay green
- no hung remote `iperf3`
- no zero-throughput intervals
- no interval collapse

### 3. Reduce retransmits inside the now-passing failover window

The current one-cycle run passes functionally, but retransmits are still high.

Focus:

- old-owner fabric TX queue balance
- new-owner WAN queue balance
- whether a smaller number of queues is still doing disproportionate work
- promoted shared hits that retain `LocalDelivery`

Goal:

- make the next failing artifact say where the bad session came from

### 2. Trace the new-owner public-side session creation path directly

Target the exact `fw1` sessions seen in the failing artifacts:

- `172.16.80.8:<port> -> 172.16.80.200:5201`

Instrument the creation/import path so the artifact answers:

- which code path installed it
- with which disposition
- from which source object:
  - local miss
  - shared session
  - shared forward-wire alias
  - daemon session sync
  - replay/export

Status:

- done for the current failing artifact
- the remaining bad sessions are now known to come from `shared_promote`

### 3. Block public-side `LocalDelivery` materialization once the source is confirmed

Once the remaining source is proven, cut it off narrowly.

The next keep to test is:

- keep translated public-side shared hits transient on fabric ingress
- do not promote them into durable local session state
- do not republish them back into shared worker/session maps

Do not reopen the already-fixed paths unless the next artifact proves they
regressed.

## Recommended implementation order

1. Add origin tagging for helper-local session creation/import.
2. Reproduce the same hardened RG1 failover and capture the first bad public-side session on `fw1`.
3. Cut off that exact creation/import path.
4. Rerun the same hardened validator before touching any unrelated failover logic.

## Acceptance criteria

The current branch should not be considered done until all of these are true:

- manual `RG1 node0 -> node1` stays up under long-lived `iperf3`
- manual `RG1 node1 -> node0` stays up under long-lived `iperf3`
- the hardened failover validator stays green on this build
- crash/rejoin still recovers and remains stable after the rebooted node returns
- the new owner no longer accumulates public-side `LocalDelivery` sessions during the failover window
- `fw1 Slow path local-delivery` stays flat enough that it is no longer the dominant counter in the bad interval

## What not to do next

Do not spend the next cycle re-opening the now-fixed blockers unless the next
artifact proves they have regressed:

- removing the stricter sync admission gate
- backing out the WAN local-session caching fix
- backing out the worker-local alias suppression
- backing out the daemon-side `local_delivery` sync filter
- rewriting the barrier path again
- speculating about fabric throughput without first rerunning the current gate

Those are not the current default blocker anymore.
