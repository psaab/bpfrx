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

The next blocker is now narrower and more concrete than before:

- manual failover is correctly failing closed because current-generation peer bulk priming is incomplete
- there is still asymmetric bulk-sync completion across the two peers on the current connection generation

That means the remaining problem is no longer just "manual failover is flaky." It is:

- `node1 -> node0` bulk completion is observed
- `node0 -> node1` bulk completion is still not being observed reliably enough to admit failover
- so the demoting node never gets a valid current-generation sync baseline and correctly refuses to proceed

This is progress, not regression. The old path blackholed traffic. The current path blocks the unsafe move.

## Latest evidence

Manual failover now fails with:

- `pre-failover prepare for redundancy group 1: session sync not ready before demotion: peer bulk sync incomplete`

Artifacts:

- `/tmp/failover-debug/manual-rg1-20260327-133956`
- `/tmp/failover-debug/manual-rg1-20260327-134724`
- `/tmp/failover-debug/manual-rg1-20260327-135300`

Important logs on `fw0`:

- `cluster: waiting to admit manual failover ... err="session sync not ready before demotion: peer bulk sync incomplete"`
- `cluster sync: bulk ack sent epoch=2`
- `cluster: session sync bulk received`
- no corresponding:
  - `cluster: session sync bulk ack received`

Important logs on `fw1`:

- later prime retries occur
- but the expected receive-side completion for `node0`'s current-generation bulk is still missing in the failing repro window

What this proves:

- `node1 -> node0` is good enough for `fw0` to send a bulk ack
- the sender-side ack path itself is alive
- the remaining missing edge is `node0 -> node1` completion on the current connection
- the originator is now observing the right signal and refusing to proceed because it is absent

So the next bug is one of:

- the accepting peer is not reliably starting its own sender-side `BulkSync()` in the `node0 -> node1` direction
- or it starts it and stalls before completion
- or `node1` receives the bulk but never reaches `BulkEnd`
- or `node1` sends the ack but `node0` never observes it on the current connection generation

## Current working hypothesis

There are now two separate failover gates:

1. admission safety
2. post-admission dataplane continuity

The current branch is still blocked on gate `1` for manual failover.

The likely failure points are in the reverse-direction session-sync prime path:

- `SessionSync.handleNewConnection()`
- the accept-side decision to invoke `BulkSync()`
- `BulkSync()` itself on the accepting peer
- `IterateSessions` / `IterateSessionsV6` on the secondary while generating the bulk transfer
- the `BulkEnd -> BulkAck -> syncPeerBulkPrimed=true` observation path on the current connection generation

Until that is fixed, further dataplane work is premature because manual failover is still being blocked before the handoff runs.

## Next code steps

### 1. Focus on the `node0 -> node1` bulk-completion direction

The general sync instrumentation is already in place. The next debugging pass
should narrow to the one direction that is still missing.

Goal:

- prove exactly where `node0 -> node1` stops on the current connection generation

### 2. Instrument accept-side sender `BulkSync()` on `node1`

Keep and extend the sender-side logs in `pkg/cluster/sync.go` so the
accepting peer proves all of these edges:

- `handleNewConnection()` schedules `BulkSync()`
- `BulkSync()` starts
- IPv4 iteration starts and completes
- IPv6 iteration starts and completes
- `BulkEnd` is written
- `BulkAck` is sent back

Goal:

- prove whether `node1` is starting `BulkSync()` for `node0`'s current-generation connection
- if it does, prove exactly where it stops

### 3. If `BulkSync()` starts but does not complete, instrument session iteration

If the sender-side logs show entry into `BulkSync()` but no completion, instrument:

- `dp.IterateSessions`
- `dp.IterateSessionsV6`

Goal:

- determine whether the stall is in session enumeration, v4/v6 split, or bulk-end write/flush

### 4. If `BulkEnd` is written but no ack arrives, instrument the receive edge

If `node1` proves it wrote `BulkEnd` for `node0`'s bulk:

- instrument `syncMsgBulkEnd` handling on `node1`
- instrument `sendBulkAck(...)`
- instrument `syncMsgBulkAck` receive on `node0`

Goal:

- distinguish:
  - no `BulkEnd`
  - no `BulkAck`
  - ack sent but not observed on the originator

### 5. Keep the stricter admission gate

Do not relax the new manual-failover safety check.

The current behavior is correct:

- a manual failover without current-generation peer bulk priming is unsafe
- the correct response is to block the move, not to revert to the old blackhole behavior

### 6. Only return to dataplane handoff work after bidirectional priming is real

Once manual failover is admitted with true current-generation bulk priming:

- rerun the exact manual `RG1 node0 -> node1` `iperf3` repro
- compare it against:
  - `/tmp/manual-rg1-jsonstream-20260327-105647`
  - `/tmp/manual-rg1-deep-20260327-105921`

Then decide whether the next remaining bug is:

- demotion drain behavior
- stale-owner redirect continuity
- post-transition fabric transport quality

## Recommended implementation order

1. Prove the missing `node0 -> node1` edge on the current connection generation.
2. Extend accept-side sender `BulkSync()` instrumentation on `node1`.
3. If needed, instrument `IterateSessions` / `IterateSessionsV6`.
4. If `BulkEnd` is reached, instrument `BulkAck` send/receive precisely.
5. Fix current-generation reverse-direction bulk priming.
6. Re-run manual `RG1` failover under load.
7. Only then continue the dataplane continuity work.

## Acceptance criteria

Before continuing dataplane handoff work, manual failover admission should satisfy all of these:

- no `peer bulk sync incomplete` admission failure once the peer connection is settled
- `syncPeerBulkPrimed=true` on the demoting node for the current connection generation
- both peers log sender-side bulk sync start and completion on the current connection
- the originator logs `cluster: session sync bulk ack received` for the current connection generation

After that, the dataplane continuity goal remains:

- no sustained zero-throughput tail under manual `RG1 node0 -> node1`
- first disruption is bounded and self-recovers
- no permanent hang of the remote `iperf3` client
- crash/rejoin remains stable

## What not to do next

Do not spend the next cycle on these before fixing bidirectional bulk priming:

- more re-announcement tuning
- more barrier retry logic
- more fabric transport micro-optimizations
- relaxing manual failover admission checks

Those are not the current blocker.
