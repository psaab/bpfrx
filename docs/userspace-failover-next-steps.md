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

The newest work did not fix the dataplane yet. It tightened the admission contract so manual failover only proceeds when the peer has a current-generation bulk sync baseline.

New behavior now:

- manual failover requires current-generation bulk priming, not just timeout-based `syncReady`
- reconnect/disconnect clears `syncBulkPrimed`
- session-sync readiness for cluster election still uses the existing timeout path
- manual failover admission now uses the stricter `syncBulkPrimed` signal
- the daemon retries sender-side bulk priming after peer connection instead of sending one burst and assuming success

This is the right safety model:

- cluster bring-up can still elect with timeout-based readiness
- manual demotion cannot proceed unless the current connection has actually completed peer bulk priming

## What is still broken

The next blocker is now narrower and more concrete than before:

- manual failover is correctly failing closed because current-generation peer bulk priming is incomplete
- there is still asymmetric bulk-sync completion across the two peers

That means the remaining problem is no longer just "manual failover is flaky." It is:

- one side can repeatedly send bulk sync
- the other side does not reliably send or complete the reverse-direction bulk prime on the current connection
- so the demoting node never gets a valid current-generation sync baseline and correctly refuses to proceed

This is progress, not regression. The old path blackholed traffic. The current path blocks the unsafe move.

## Latest evidence

Manual failover now fails with:

- `pre-failover prepare for redundancy group 1: session sync not ready before demotion: peer bulk sync incomplete`

Artifacts:

- `/tmp/manual-rg1-deep-20260327-131700`
- `/tmp/manual-rg1-deep-20260327-131855`
- `/tmp/manual-rg1-probe-20260327-132319`

Important logs on `fw0`:

- `cluster: waiting to admit manual failover ... err="session sync not ready before demotion: peer bulk sync incomplete"`
- `cluster: retrying session sync bulk prime`
- `cluster sync: bulk sync complete sessions=0 skipped=74 epoch=1`
- later retries with:
  - `cluster sync: bulk sync complete sessions=185 skipped=0 epoch=6`
  - `cluster sync: bulk sync complete sessions=185 skipped=0 epoch=7`

Important logs on `fw1`:

- `cluster sync: bulk transfer starting epoch=1`
- in earlier runs also:
  - `cluster sync: bulk transfer complete epoch=1`
  - `cluster: session sync complete, releasing VRRP hold`

What this proves:

- `fw0` is definitely sending bulk sync repeatedly on the current connection
- `fw1` definitely receives at least some of that bulk transfer
- the reverse-direction priming signal back to `fw0` is still not being completed reliably on the current connection

So the next bug is either:

- the accepting peer is not reliably starting its own sender-side `BulkSync()`
- or it starts it and stalls before completion
- or the originator is not observing the completion path correctly

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
- the bulk-complete observation path that should flip `syncBulkPrimed=true`

Until that is fixed, further dataplane work is premature because manual failover is still being blocked before the handoff runs.

## Next code steps

### 1. Instrument sender-side `BulkSync()` on the accepting peer

Add explicit sender-side logs in `pkg/cluster/sync.go` for:

- bulk sync start
- before IPv4 iteration
- after IPv4 iteration
- before IPv6 iteration
- after IPv6 iteration
- before writing bulk-end marker
- bulk sync complete

Goal:

- prove whether the accepting peer actually enters `BulkSync()`
- if it does, prove exactly where it stalls

### 2. Trace the accept-side connection path

Instrument the code around:

- `handleNewConnection()`
- any `wasDisconnected` / reconnect path
- the point where accept-side `BulkSync()` is triggered

Goal:

- prove whether the reverse-direction prime is being scheduled at all on the current connection

### 3. If `BulkSync()` starts but does not complete, instrument session iteration

If the sender-side logs show entry into `BulkSync()` but no completion, instrument:

- `dp.IterateSessions`
- `dp.IterateSessionsV6`

Goal:

- determine whether the stall is in session enumeration, v4/v6 split, or bulk-end write/flush

### 4. Keep the stricter admission gate

Do not relax the new manual-failover safety check.

The current behavior is correct:

- a manual failover without current-generation peer bulk priming is unsafe
- the correct response is to block the move, not to revert to the old blackhole behavior

### 5. Only return to dataplane handoff work after bidirectional priming is real

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

1. Add accept-side sender `BulkSync()` instrumentation.
2. Add accept-path scheduling instrumentation.
3. If needed, instrument `IterateSessions` / `IterateSessionsV6`.
4. Fix current-generation reverse-direction bulk priming.
5. Re-run manual `RG1` failover under load.
6. Only then continue the dataplane continuity work.

## Acceptance criteria

Before continuing dataplane handoff work, manual failover admission should satisfy all of these:

- no `peer bulk sync incomplete` admission failure once the peer connection is settled
- `syncBulkPrimed=true` on the demoting node for the current connection generation
- both peers log sender-side bulk sync start and completion on the current connection

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
