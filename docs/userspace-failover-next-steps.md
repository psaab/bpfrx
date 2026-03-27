# Userspace Failover Next Steps

## Goal

Get userspace HA failover to a state where both of these are true:

- manual redundancy-group moves preserve long-lived traffic without collapsing to sustained zero throughput
- crash/rejoin of the active node fails over and the returning node rejoins without destabilizing the survivor

The immediate remaining bug is the first one. Crash/rejoin is materially better on the current build, but manual `RG1 node0 -> node1` moves under established load still fail.

## What is already fixed

The current branch work materially improved control-plane admission and crash/rejoin behavior.

Working now:

- manual failover no longer fails immediately on the first transient sync-admission error
- direct-mode failover uses repeated re-announcements after primary transition
- crash/rejoin of the active node no longer reproduces the old "node returns and kills traffic again" behavior in the latest measured run
- the userspace failover validator and monitor paths now expose the counters needed to debug stale-owner forwarding

Validated artifacts:

- crash/rejoin: `/tmp/sysrqb-rejoin-20260327-105330`
- manual failover with interval stream: `/tmp/manual-rg1-jsonstream-20260327-105647`
- manual failover with per-second interface snapshots: `/tmp/manual-rg1-deep-20260327-105921`

## What is still broken

Manual `RG1 node0 -> node1` failover under established `iperf3` load still blackholes the flow after admission.

Measured in `/tmp/manual-rg1-jsonstream-20260327-105647`:

- peak throughput before the move: `21.041 Gbps`
- zero-throughput intervals after the move: `52`
- tail median throughput: `0.0 Gbps`
- retransmits: `8062`

The control plane did what it was supposed to do in that run:

- first pre-hook attempt was rejected as retryable because sync was not yet quiescent
- a later retry admitted the failover
- the CLI completed in `6.51s`
- the new owner transitioned and sent the repeated re-announcements

So the remaining bug is not manual-failover admission. It is dataplane continuity after an admitted ownership move.

## What the latest deep capture proves

The per-second interface snapshots in `/tmp/manual-rg1-deep-20260327-105921` narrow the remaining failure substantially.

In the first sampled post-move window:

- old-owner LAN ingress (`fw0 ge-0-0-1`) stayed high
- old-owner WAN egress (`fw0 ge-0-0-2`) was still dominant
- old-owner fabric transmit (`fw0 ge-0-0-0`) was only a small fraction of that traffic
- new-owner fabric receive (`fw1 ge-7-0-0`) only saw that small redirected fraction

This means the remaining manual-failover bug is:

- the old owner is still allowed to locally WAN-egress a demoting RG for too long
- the current staged handoff primes state, but it does not yet force the old owner into a true pre-demotion drain state before the cluster flip completes

That is why the first bad interval is enough to collapse the TCP flow and it never recovers.

## Working hypothesis

The code currently stages demotion in terms of:

- session republish
- reverse-session refresh
- cache invalidation
- barrier / sync admission

But it does not stage demotion in terms of forwarding behavior.

The old owner can still have one or more of these active while the RG move is being admitted or has just flipped:

- cached local forward decisions for the demoting owner RG
- live local session entries that still resolve to local WAN egress
- already-built `pending_tx_local` work targeting the old WAN binding
- already-built `pending_tx_prepared` work targeting the old WAN binding

That matches the live capture: the old owner is still pushing a large amount of local WAN traffic in the first bad post-flip window.

## Next code steps

### 1. Add a true helper-side demotion-drain state

Add a helper-visible runtime state for "owner RG is demoting" that is distinct from the normal HA active/inactive state.

Required behavior:

- as soon as demotion prep starts, the demoting owner RG is treated as not locally forwardable for new local-WAN egress decisions
- stale-owner traffic should resolve to fabric redirect during this state, not to local WAN
- this state must be local and immediate; it cannot wait for the cluster state flip to propagate back through the normal HA snapshot path

Likely files:

- [userspace-dp/src/main.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/main.rs)
- [userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs)
- [userspace-dp/src/afxdp/session_glue.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/session_glue.rs)

### 2. Make HA resolution treat a demoting RG like an inactive RG for local forwarding

Today `enforce_ha_resolution_snapshot(...)` only reasons about the HA runtime snapshot. It does not know that a local RG is in the middle of a manual demotion sequence.

The next fix should teach the forwarding path to do this for a demoting owner RG:

- disallow local WAN forwarding
- prefer fabric redirect for forward candidates and missing-neighbor cases
- invalidate or bypass cached decisions that still point to local WAN

This needs to apply to:

- new flow lookups
- flow-cache hits
- established session lookups that re-resolve forwarding

### 3. Drain and cancel old-owner queued WAN work before completing demotion

The current cancellation logic is too late or too narrow for the bad first interval.

The demotion-prep stage should explicitly flush or cancel queued old-owner WAN work for the demoting RG before the manager allows the resignation to complete.

That means cancelling all matching work for the demoting RG across:

- `pending_tx_local`
- `pending_tx_prepared`
- shared pending TX queues
- any still-live local session map entries that would drive local WAN transmit

The important difference from the current design is timing:

- do not only republish state
- also make the old owner prove that local-WAN transmit for that RG has been drained or cancelled before the move completes

### 4. Add an explicit demotion-drain acknowledgement, not just a session prep ack

The current prep ack tells the daemon that republish work ran. It does not prove that local forwarding for the demoting RG has stopped.

Add a second acknowledgement with a stricter meaning:

- all workers have applied the demoting-RG forwarding state
- all matching cached local-forward decisions are invalidated
- all matching queued local/prepared TX requests are drained or cancelled
- no worker still reports local-WAN-forwardable state for the demoting RG

Only after that acknowledgement should the manual failover pre-hook return success.

### 5. Add targeted transport-quality instrumentation for the demotion window

The current observability is good enough to prove the bug exists, but the next iteration should add counters that directly answer whether the old owner is still locally forwarding the demoting RG.

Add per-binding or per-worker counters for:

- demoting-RG local-forward attempts blocked
- demoting-RG redirects forced to fabric
- demoting-RG queued local TX cancels
- demoting-RG prepared TX cancels
- demotion-drain ack latency

That keeps the next debugging pass from relying on raw cumulative packet deltas alone.

## Recommended implementation order

1. Introduce demoting-RG helper state and thread it through worker commands.
2. Apply that state to HA resolution and flow-cache validation so new and cached traffic stop choosing local WAN.
3. Add queued-WAN drain/cancel semantics and a stronger demotion-drain ack.
4. Re-run the exact manual `RG1 node0 -> node1` json-stream repro.
5. Only after the manual move is stable, re-run crash/rejoin to make sure the stricter demotion behavior did not regress that path.

## Acceptance criteria

Manual `RG1 node0 -> node1` under established `iperf3 -P 4` load should meet all of these:

- no sustained zero-throughput tail
- no collapse to permanent `0.0 Gbps`
- first post-move disruption is bounded and recovers automatically
- old-owner WAN transmit stops quickly after demotion prep begins
- old-owner fabric transmit becomes the dominant stale-owner path during the handoff window
- new-owner WAN transmit takes over and stays healthy

Crash/rejoin should continue to meet all of these:

- short takeover disruption is acceptable
- traffic recovers without a second collapse when the rebooted node returns
- final cluster state is stable
- both nodes are takeover-ready after rejoin

## What not to chase first

These are not the first fixes to make for the current manual-failover bug:

- more re-announcement bursts
- more sync-admission retries
- more session-republish retries without changing forwarding behavior
- generic fabric throughput tuning without first eliminating old-owner local WAN forwarding during demotion

Those may still matter later, but the current evidence says the next important fix is a forwarding drain state, not another control-plane retry.
