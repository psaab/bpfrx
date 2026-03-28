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

The newer dataplane fix addressed the remaining forward-direction collapse:

- transient TCP ACK misses to WAN interface-NAT addresses are no longer cached as helper-local `LocalDelivery` sessions
- this prevents the new owner from poisoning the inherited WAN reply path during failover
- the affected path was visible as:
  - very low `session misses`
  - but rapidly increasing `Slow path packets: local` on the new-owner WAN binding

## What is still broken

The specific `node0 -> node1` manual failover collapse that dominated the
earlier investigation is now fixed on this branch.

What is still not fully proven:

- the full hardened failover validator has not yet been rerun end-to-end on this exact build
- reverse-direction manual failover should be rerun once on top of the new WAN local-session fix, even though it was already healthy before that change
- crash/rejoin is materially better, but the stricter harness should still be rerun against the current build so the remaining failover budget is explicit

## Latest evidence

Manual `RG1 node0 -> node1` is now healthy under the simplified long-lived
repro.

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

The current branch is past the original sync-admission and forward-collapse
bugs.

The remaining question is narrower:

- does the full hardened failover gate stay green on this build
- and, if not, what residual transition weakness is left once the local-session
  poisoning bug is removed

## Next code steps

### 1. Rerun the hardened failover validator on this exact build

Use the full userspace HA validation path, not only the simplified manual repro.

Goal:

- confirm whether the current branch is actually good enough for the stronger gate
- capture any remaining failures with the stricter artifacts already in the harness

### 2. Rerun reverse-direction manual failover once on top of the WAN local-session fix

The reverse direction was already healthy before the latest fix.
It still needs one confirming run on top of the current build so both RG1 move
directions are explicitly proven.

Goal:

- eliminate direction-specific uncertainty before changing more dataplane logic

### 3. Only add more dataplane changes if the hardened gate still fails

If the gate still fails after the forward-fix branch, the next step should be
driven by the new artifacts, not by re-opening the already-fixed sync-admission
path.

That means:

- preserve the stricter sync admission gate
- preserve the WAN local-session caching fix
- inspect the next remaining failure on its own merits

## Recommended implementation order

1. Run the hardened failover validator on the current branch.
2. Re-run reverse-direction manual `RG1` failover once.
3. If both pass, stop changing the failover dataplane and move to cleanup / PR polish.
4. If either fails, use the new artifacts to isolate the remaining transition bug before touching sync-admission logic again.

## Acceptance criteria

The current branch should not be considered done until all of these are true:

- manual `RG1 node0 -> node1` stays up under long-lived `iperf3`
- manual `RG1 node1 -> node0` stays up under long-lived `iperf3`
- the hardened failover validator stays green on this build
- crash/rejoin still recovers and remains stable after the rebooted node returns
- no regression reintroduces the new-owner WAN `local` slow-path explosion on transient reply misses

## What not to do next

Do not spend the next cycle re-opening the now-fixed blockers unless the stronger
gate proves they have regressed:

- removing the stricter sync admission gate
- backing out the WAN local-session caching fix
- rewriting the barrier path again
- speculating about fabric throughput without first rerunning the current gate

Those are not the current default blocker anymore.
