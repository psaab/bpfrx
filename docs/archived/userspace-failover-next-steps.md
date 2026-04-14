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

- the strengthened failover gate still needs repeated multi-cycle validation, not just one passing cycle
- retransmits are still higher than ideal during the passing failover window
- the public/WAN50 path in the lab was down on March 28, 2026, so external
  internet reachability could not be used as a failover discriminator
- after isolating that WAN outage and rerunning the gate without external
  checks, the new owner did not lose dataplane continuity, but the move still
  did not stick: the new owner VM rebooted and the old owner reclaimed `RG1`

What is still improved:

- sync admission and bulk priming are no longer the blocker
- target reachability stays up during the bad run
- crash/rejoin is still materially better than the old baseline

## March 30, 2026 checkpoint

The current failover baseline should now be treated as:

- code baseline:
  - `#295` helper bind mode follows actual XDP attach mode
  - `#296` native-to-generic fallback is per-interface instead of global
- operational baseline:
  - steady-state forwarding to `172.16.80.200` works again
  - cold-start first-probe loss still exists separately

### What we validated on March 30

Validated artifact for steady-state / XDP-mode correction:

- the helper now binds copy mode on generic interfaces and zero-copy only on
  native interfaces
- the restored steady-state forwarding fix is documented in:
  - [userspace-xdp-mode-and-cold-start-findings.md](userspace-xdp-mode-and-cold-start-findings.md)

Validated artifact for manual RG failover under load:

- `/tmp/userspace-ha-failover-rg1-20260330-092213`

Measured result:

- `1539` zero-throughput intervals
- `1368` per-stream zero-throughput intervals across `8` streams
- sender throughput `4.280 Gbps`
- sender retransmits `115`

Important counters from the first failover window:

- old-owner LAN RX delta `5865927`
- old-owner fabric TX delta `38353`
- new-owner fabric RX delta `28494`
- new-owner WAN TX delta `7`
- session miss delta `28493`

Interpretation:

- the ownership move completes
- the target stays reachable
- but the inherited `iperf3 -P 8` flow set still collapses
- the new owner receives redirected traffic but does not materialize enough
  working forward state to carry it

Validated artifact for all-RGs-on-primary crash/rejoin:

- `/tmp/sysrqb-rgall-20260330-092844`

Measured result:

- `92` sampled intervals
- `12` zero-throughput intervals
- peak `23.500 Gbps`
- tail median `23.450 Gbps`
- sender `20.0 Gbits/sec`, `49614` retransmits

Interpretation:

- hard-crash takeover with all RGs on one node is materially better than the
  manual RG failover path
- traffic resumes and stays flat by the tail of the run

Validated artifact for split-RG crash:

- `/tmp/sysrqb-split-node0-actual-20260330-093636`

Measured result:

- `88` sampled intervals
- `77` zero-throughput intervals
- peak `4.110 Gbps`
- tail median `0.000 Gbps`

Precondition during that run:

- `RG1=node1`
- `RG2=node0`
- `node1` stayed:
  - `Takeover ready: no (session sync not ready)`

Interpretation:

- split active/active crash handling is still broken
- split-RG session-sync readiness can remain stuck not-ready even after the
  cluster reaches a stable ownership split
- crashing the `RG2` owner from that split state still collapses the flow

### Updated priority

The highest-value next investigations are now:

1. Why split ownership leaves `session sync not ready` stuck on the surviving
   primary.
2. Why the manual `RG1` move still collapses immediately after ownership moves
   even after the large new-owner `session_miss` storm is removed.
3. Only after those are fixed, continue with more crash/rejoin matrix work.

## March 30, 2026 late checkpoint

The latest narrowing pass changed the failure shape again.

Code checkpoint:

- `c84c35c7` `userspace: prewarm reverse sessions for activated RGs`

Validated artifacts:

- interrupted one-cycle harness:
  - `/tmp/userspace-ha-failover-rg1-20260330-174231`
- one-way failover observe run:
  - `/tmp/manual-oneway-rg1-20260330-174744`

What changed:

- the new owner no longer shows the earlier `~28k` `session_miss` explosion on
  first failover
- the surviving `RG1` owner receives and installs the forwarded session set
  (`Sessions installed: 151`, later `216`)
- cluster ownership stays stable after the move:
  - `node0` remains `RG1 secondary`
  - `node1` remains `RG1 primary`

What is still broken:

- the inherited `iperf3 -P 8` flow set still collapses immediately after the
  move
- one-way failover `iperf3` stays near `20 Gbps` for the pre-failover window,
  drops to `3.17 Gbps` in the first bad second, then goes to sustained `0`
  starting in the next second
- the one-way artifact summary is:
  - `68` intervals
  - `51` zero-throughput intervals
  - peak `20.600 Gbps`
  - tail median `0.000 Gbps`

What the new counters prove:

- the collapse is no longer explained by a new-owner install failure
- during the bad window:
  - `fw0 Session misses` stays flat at `29`
  - `fw1 Session misses` stays flat at `27-28`
  - `Neighbor misses` stay flat
  - `Slow path local-delivery` on `fw1` grows only slightly (`22 -> 32`)
- the first post-failover snapshot already shows:
  - `fw0 rg1 active=false`
  - `fw1 rg1 active=true`
  - `fw1 Sessions installed=151`

Interpretation:

- the reverse-prewarm fix removed the original failover signature
- the remaining collapse is now more likely in the stale-owner demotion /
  redirected transport path than in the new-owner session install path
- the next code target should be the demotion-side forwarding path, not more
  session-sync bulk work

## March 30, 2026 late-night checkpoint

The latest live trace narrowed one more concrete bug in the demotion path.

Artifact:

- `/tmp/manual-oneway-rg1-20260330-180943`

What happened:

- the CLI failover did not complete
- `failover.out` reported:
  - `pre-failover prepare for redundancy group 1: read unix @->/run/xpf/userspace-dp.sock: i/o timeout`
- cluster ownership never moved:
  - `node0` stayed `RG1 primary`
  - `node1` stayed `RG1 secondary`

But the primary helper still changed behavior after the failed prepare.

Trace on `fw0` showed:

- the watched forward flow to `172.16.80.200` resolving as:
  - `disposition=FabricRedirect`
  - `owner_rg=1`
- the reverse direction from `172.16.80.200` still resolving as:
  - `disposition=ForwardCandidate`

Interpretation:

- the userspace demotion-prep request can time out at the manager/daemon layer
  after the helper has already marked the RG as demoting
- once that happens, the still-primary helper can continue treating local RG
  traffic as stale-owner fabric traffic even though cluster ownership never
  changed

This changes the immediate priority order again.

Updated priority:

1. Make helper demotion-prep self-clearing if the prepare does not complete.
2. Re-run the failed-prepare repro and prove the still-primary node stops
   self-poisoning after the demotion-prep lease expires.
3. Then re-run the real manual `RG1` move under inherited `iperf3 -P 8` load.
4. Keep the split-RG readiness work after the demotion poison is fixed, because
   the stuck not-ready state still matters for crash safety.

## March 30, 2026 end-of-night checkpoint

The remaining failure now looks like stale moved-RG session state, not failed
admission.

What changed after the latest helper fixes:

- manual CLI `RG1` failover now admits again on the clean build
- immediate and `t+6s` pings to `172.16.80.200` still fail after the move
- the same split state recovers by about `t+30s`
- once recovered, fresh TCP works again:
  - `iperf3 -P 4 -t 5` was about `2.74 Gbps`

Interpretation:

- the demotion-prep timeout bug and the stuck-demoting poison bug were both
  real and are now narrowed
- the surviving outage window lines up much more closely with stale session
  lifetime than with ownership or neighbor convergence
- helper defaults still give:
  - non-TCP / other session timeout `30s`
  - established TCP timeout `300s`

That is the current best explanation for the remaining behavior:

- fresh ICMP comes back once stale non-TCP state ages out
- established `iperf3` does not come back, because stale TCP session state
  persists far longer

Updated priority:

1. Audit and narrow which moved-RG session aliases survive the ownership edge on
   both nodes.
2. Fix stale session cleanup surgically, not with the earlier naive
   delete-everything demotion experiment that regressed new-owner install.
3. Re-run manual `RG1` failover under established `iperf3 -P 8` after that
   cleanup change.
4. Keep split-RG readiness and crash/rejoin work after the moved-session stale
   state is under control.

## March 30, 2026 demotion-alias cleanup experiment

One follow-up experiment was tried and rejected:

- `b319046b` `userspace: delete demoted session aliases immediately`
- reverted by:
  - `1a2da473`

What it changed:

- the old owner's immediate demotion cleanup deleted the full
  `USERSPACE_SESSIONS` entry set for shared demoted sessions, not just the
  canonical key

What live validation showed:

- artifact:
  - `/tmp/manual-oneway-rg1-20260330-175924`
- result:
  - `68` intervals
  - `52` zero-throughput intervals
  - peak `23.500 Gbps`
  - tail median `0.000 Gbps`
- failure signature regressed:
  - `fw1 Session misses` jumped back to `28077 -> 28086`
  - `fw1 Sessions installed` still reached `140 -> 203`
  - `fw1 TX packets` stayed effectively flat (`0 -> 57`)

Interpretation:

- immediate full alias deletion on the demoting side is too aggressive
- some of those aliases are still needed during the handoff window
- the remaining fix must preserve continuity while still preventing stale-owner
  ownership drift; a blind full alias purge is not safe

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

Latest March 28 reruns on top of merged `master` changed the failure shape again.

External preflight isolation:

- from `cluster-userspace-host`, both `1.1.1.1` and
  `2606:4700:4700::1111` were unreachable
- local `.200` reachability still worked for both IPv4 and IPv6
- the active router CLI on `fw0` could not reach:
  - `172.16.50.1`
  - `2001:559:8585:50::1`
- that isolates the blocker to the lab WAN50/public path, not the local
  userspace dataplane

To keep validating failover continuity without pretending internet coverage
passed, the harness now supports:

- `CHECK_EXTERNAL_REACHABILITY=0`

Latest two-cycle rerun with external checks disabled:

- artifact:
  - `/tmp/userspace-ha-failover-rg1-20260328-075648`
- the failover itself admitted and traffic survived the move:
  - `avg_gbps`: `10.381`
  - `peak_gbps`: `22.579`
  - `tail_median_gbps`: `21.655`
  - `collapse_detected`: `false`
- but the run still failed overall because the move did not stick:
  - `node1` became secondary for `RG1` immediately after the move
  - later `node1` logged `clearing manual failover (peer lost)` and reclaimed
    `RG1`
  - `fw0` crossed a journal boot boundary at about `2026-03-28 14:58:10 UTC`,
    proving the whole VM rebooted after becoming primary

What that proves:

- the old dataplane collapse and the earlier split-brain timeout release are no
  longer the active blocker on this rerun
- the next blocker is node stability on the new owner after primary transition
- the next debugging target is why `xpf-userspace-fw0` rebooted under the
  admitted `RG1 node1 -> node0` failover load

Immediate next code/debug steps:

1. capture the previous-boot failure cause on `fw0`
2. determine whether the reboot was:
   - kernel panic
   - watchdog reset
   - OOM / systemd-triggered reboot
   - explicit host-side reset
3. only after that rerun the same two-cycle gate again; until then, the gate is
   proving failover continuity better, but not full node survivability

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

Latest crash/rejoin validation on top of the fabric queue-selection fix:

- artifact:
  - `/tmp/sysrqb-rejoin-20260328-072503`

Measured result:

- `avg_gbps`: `12.713267304972149`
- `peak_gbps`: `14.059293600012786`
- `tail_median_gbps`: `13.514897783265418`
- `tail_peak_ratio`: `0.9612785796900298`
- `collapse_detected`: `false`
- `retransmits`: `9709`
- takeover: `ok`
- rejoin: `ok`

Interpretation:

- the active-node hard crash still causes a short disruption window
- the survivor takes over
- the rebooted node rejoins as secondary with `Takeover ready: yes`
- there is no second collapse after rejoin on this build

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

Current note:

- the first attempted two-cycle rerun after the crash/rejoin pass did not reach
  the failover phase because steady-state external IPv6 preflight failed in the
  lab
- artifact:
  - `/tmp/userspace-ha-failover-rg1-20260328-072932`
- that run does not change the current dataplane conclusion because it never
  exercised the RG move

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

## March 30-31, 2026 update

The current failure shape is narrower than the older `LocalDelivery` poison
artifacts.

### Direct re-announce still does not fully move the host neighbor

Artifacts:

- `/tmp/rg1-neighbor-watch-20260330-200731`
- `/tmp/rg1-neighbor-node1-20260330-200816`

What happened on `RG1 node0 -> node1`:

- `fw1` logged repeated direct-mode GARP/NA re-announcements
- `cluster-userspace-host` kept `10.0.61.1` pinned to the old owner MAC
- traffic later recovered while the host still used the old owner MAC

Interpretation:

- stale-owner redirect is still carrying part of the recovery
- host neighbor convergence is still weak in the hard direction
- but this is not the whole failover collapse, because redirected traffic still
  reaches the new owner

### Immediate full demotion alias deletion regressed the target

Artifact:

- `/tmp/userspace-ha-failover-rg1-20260330-201527`

Rejected experiment:

- delete the demoted owner's full alias set immediately at ownership loss

Result:

- target `Session misses`: `23323`
- target `Neighbor misses`: `185`
- target last resolution became:
  - `missing_neighbor ... flow=172.16.80.8:58574->172.16.80.200:5201`

Interpretation:

- the handoff still needs some translated alias continuity
- the remaining fix must be narrower than blind full alias deletion

### Active-owner translated shared hits should not stay transient

Local change:

- keep translated synced forward hits transient on fabric ingress only while
  the owner RG is still locally inactive
- if the owner RG is already active on the receiving node, promote the hit
  locally instead of purging it

Validation artifact:

- `/tmp/userspace-ha-failover-rg1-20260330-202612`

Observed improvement:

- target `Session misses`: `23323 -> 15424`
- target `Neighbor misses`: `185 -> 0`
- target helper made limited but real forward progress:
  - `Session hits: 21`
  - `Session creates: 2`
  - `SNAT packets: 3`
  - `DNAT packets: 3`
  - `TX packets: 54`

What is still broken:

- the hardened failover validator still failed
- sender throughput was `3.746 Gbps`
- sender retransmits were `149568`
- there were `189` zero-throughput intervals

### Remaining mismatch

In the same artifact:

- `fw1` cluster status says `RG1 primary`
- `fw1` helper HA runtime says `rg1 active=true`
- but `fw1` helper still reports:
  - `Last resolution: ha_inactive ... flow=172.16.80.8:51720->172.16.80.200:5201`
- and `cycle1-failover-fw1-sessions.txt` still shows the inherited translated
  `.200` tuples as `HA State: Backup`

That is the next concrete target:

- explain why the active new owner still treats inherited translated forward
  tuples as inactive/backup
- verify whether the remaining gap is:
  - wrong synced owner-RG metadata
  - wrong shared forward-wire publication
  - incomplete promotion after materialization

## Recommended implementation order

1. Explain why an `RG1`-primary new owner still resolves inherited translated
   `.200` tuples as `ha_inactive` / `Backup`.
2. Verify whether the remaining gap is metadata, publication, or promotion.
3. Reproduce the same hardened RG1 failover and capture the first translated
   forward tuple that still stays inactive on `fw1`.
4. Fix that exact active-owner mismatch before touching unrelated failover
   logic.

## Acceptance criteria

The current branch should not be considered done until all of these are true:

- manual `RG1 node0 -> node1` stays up under long-lived `iperf3`
- manual `RG1 node1 -> node0` stays up under long-lived `iperf3`
- the hardened failover validator stays green on this build
- crash/rejoin still recovers and remains stable after the rebooted node returns
- the new owner no longer leaves inherited translated `.200` tuples in
  `HAInactive` / `Backup` state during the failover window
- `fw1` session misses on inherited translated traffic stay low enough that the
  flow remains flat through the move

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
