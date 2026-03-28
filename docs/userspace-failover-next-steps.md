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

What those fixes proved:

- the original ACK-miss caching bug was real
- shared helper alias pollution was real
- but neither of those changes removed the core hardened-harness collapse
- the new owner still accumulates public-side `LocalDelivery` state during failover from some other path
- the traced `2026-03-28` artifact narrows that remaining path to
  `shared_promote` on the new owner, not `local_miss`, `sync_import`, or
  `missing_neighbor_seed`

## What is still broken

The specific `node0 -> node1` manual failover collapse is still present under
the hardened failover validator.

What is still broken:

- the exact strengthened RG1 failover harness still collapses after the move to `node1`
- all four `iperf3` streams still hit `0.00 bits/sec`
- the remote client still hangs until the harness kills it
- the new owner still shows exploding `Slow path local-delivery` during the bad window
- the new owner still ends up with public-side sessions like:
  - `172.16.80.8:<port> -> 172.16.80.200:5201`

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

The current branch is past the original sync-admission and bulk-priming bugs.

The remaining question is narrower:

- what path is still creating public-side `LocalDelivery` state on the new owner
- and why does that state survive even after:
  - ACK-miss caching suppression
  - worker-local shared-alias suppression
  - daemon-side `local_delivery` sync filtering

The likely remaining class is:

- session materialization on the new owner from a hit/import/replay path that
  still carries `LocalDelivery` semantics for public-side translated traffic

## Next code steps

### 1. Tag the origin of helper-local sessions in status and delta logs

The current artifacts prove that bad public-side sessions still appear on the
new owner, but not where they were created.

Add enough visibility to distinguish:

- miss-created helper-local sessions
- synced/imported helper-local sessions
- replayed helper-local sessions
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
