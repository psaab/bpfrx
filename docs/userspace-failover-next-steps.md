# Userspace Failover Next Steps

## Goal

Get userspace HA failover to a state where both of these are true:

- manual redundancy-group moves preserve long-lived traffic without collapsing to sustained zero throughput
- crash/rejoin of the active node fails over and the returning node rejoins without destabilizing the survivor

The near-term work is now split into two gates:

1. failover admission must only proceed once the standby has a real current-generation session-sync baseline
2. once admitted, the dataplane handoff must keep established traffic alive through the ownership move

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

## What changed in the latest pass

The newest work still did not fix the dataplane, but it did move the
admission logic onto the correct signal.

New behavior now:

- manual failover no longer keys off the old inbound-bulk signal
- reconnect/disconnect clears both:
  - `syncBulkPrimed`
  - `syncPeerBulkPrimed`
- session-sync readiness for cluster election still uses the existing timeout path
- manual failover admission now waits on sender-side peer acknowledgement of the current-generation bulk sync
- the daemon retries sender-side bulk priming after peer connection instead of sending one burst and assuming success
- the cluster transport now emits explicit bulk-complete acknowledgements:
  - sender writes `BulkEnd`
  - receiver responds with `BulkAck`
  - originator marks the peer as actually primed only after that ack arrives

This is the right safety model:

- cluster bring-up can still elect with timeout-based readiness
- manual demotion cannot proceed unless the current connection has actually completed peer bulk priming in the correct direction

## What is still broken

The original one-directional bulk-completion bug is no longer the blocker.

What is still broken now:

- manual failover is correctly failing closed because the demotion barrier does not clear inside the quiescence window
- the barrier is not being lost
- it is being delayed behind previously-sent retry bulk traffic on the same stream

That means the remaining problem is no longer just "manual failover is flaky." It is:

- current-generation bulk completion is now observed in both directions
- but the retry loop can still send epoch `2` and `3` before epoch `1` is acked
- those extra bulks inflate stream backlog
- the demotion barrier then arrives far too late to satisfy the manual-failover admission timeout

This is still progress. The unsafe move is blocked for the right reason, but the
transport is too backlogged to admit the move in time.

## Latest evidence

Manual failover now fails with:

- `pre-failover prepare for redundancy group 1: session sync peer not quiescent before demotion: timed out waiting for session sync barrier ack ...`

Artifacts:

- `/tmp/failover-debug/manual-rg1-node0-to-node1-20260327-212324`
- `/tmp/failover-debug/manual-rg1-node0-to-node1-20260327-212719`
- `/tmp/failover-debug/manual-rg1-node0-to-node1-20260327-212958`
- `/tmp/manual-rg1-deep-20260327-213949`

Important logs on `fw0`:

- `cluster: session sync bulk ack received`
- `cluster sync: barrier sent seq=...`
- retry bulk epochs `2` and `3` were already written before the first ack arrived

Important logs on `fw1`:

- `cluster sync: bulk ack sent epoch=...`
- later:
  - `cluster sync: barrier received seq=...`
  - `cluster sync: barrier ack sent seq=...`
- but the barrier receive time is tens of seconds after send time

What this proves:

- current-generation sender-side bulk priming is now real
- barrier delivery works
- barrier acknowledgement works
- the remaining issue is transport latency caused by extra retry bulks already in front of the barrier

Newest result:

- with one-outstanding-bulk retry suppression in place, manual failover is admitted
- the same long-lived `iperf3` flow still collapses after the ownership move
- so the next bug is post-admission dataplane continuity, not session-sync priming

## Current working hypothesis

There are now two separate failover gates:

1. admission safety
2. post-admission dataplane continuity

The current branch is still blocked on gate `1` for manual failover, but for a
different reason now.

The likely failure point is the outbound retry policy:

- `BulkSync()` on reconnect sends epoch `1`
- the retry loop later sends epoch `2` and `3` before epoch `1` is acked
- those extra bulks are valid, but they occupy the same ordered stream
- demotion barriers are injected behind stale bulk replay traffic

Until that is fixed, further dataplane work is still premature because manual
failover is being blocked before the handoff runs.

## Next code steps

### 1. Keep only one outbound bulk outstanding at a time

The retry loop must not send epoch `2` or `3` while epoch `1` is still waiting
for peer acknowledgement.

Concrete change:

- track the latest outbound bulk epoch awaiting `BulkAck`
- defer retry while that ack is still pending inside a grace window

Goal:

- prevent later bulk replay traffic from sitting in front of the demotion barrier

### 2. Keep the stricter admission gate

Do not relax the new manual-failover safety check.

The current behavior is correct:

- a manual failover without current-generation peer bulk priming is unsafe
- the correct response is to block the move, not to revert to the old blackhole behavior

### 3. Only return to dataplane handoff work after retry suppression is in place

Once manual failover is admitted with:

- current-generation peer bulk ack observed
- no extra retry bulk epochs queued ahead of the barrier

- rerun the exact manual `RG1 node0 -> node1` `iperf3` repro
- compare it against:
  - `/tmp/manual-rg1-jsonstream-20260327-105647`
  - `/tmp/manual-rg1-deep-20260327-105921`

Then decide whether the next remaining bug is:

- demotion drain behavior
- stale-owner redirect continuity
- post-transition fabric transport quality

## Recommended implementation order

1. Keep one outbound bulk outstanding at a time.
2. Re-run manual `RG1` failover under load.
3. Confirm that demotion barriers are now acknowledged inside the quiescence window.
4. Only then continue the dataplane continuity work.

## Acceptance criteria

Before continuing dataplane handoff work, manual failover admission should satisfy all of these:

- no `peer bulk sync incomplete` admission failure once the peer connection is settled
- `syncPeerBulkPrimed=true` on the demoting node for the current connection generation
- the originator logs `cluster: session sync bulk ack received` for the current connection generation
- no extra retry bulk epochs are sent while the previous epoch is still awaiting ack
- demotion barriers are acknowledged within the manual-failover quiescence window

After that, the dataplane continuity goal remains:

- no sustained zero-throughput tail under manual `RG1 node0 -> node1`
- first disruption is bounded and self-recovers
- no permanent hang of the remote `iperf3` client
- crash/rejoin remains stable

## What not to do next

Do not spend the next cycle on these before fixing retry-induced stream backlog:

- more re-announcement tuning
- more barrier retry logic
- more fabric transport micro-optimizations
- relaxing manual failover admission checks

Those are not the current blocker.
