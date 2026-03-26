# Userspace Fabric Failover

This document covers the userspace HA failover case where redundancy-group
ownership moves to the peer and existing traffic must cross the inter-node
fabric path during the transition.

This is the failure mode that used to look "mostly fine" in aggregate while
still being wrong in practice:

- `iperf3` eventually recovered, but there were real zero-throughput intervals
- external IPv4 or IPv6 broke only on the new owner
- traffic hit the wrong owner but did not redirect across the fabric cleanly
- stale MAC traffic died on the old owner because the standby helper was not
  armed
- failover passed a loose throughput threshold while still accumulating
  session, neighbor, or policy failures during the move

The goal of the hardened validator is to detect those cases directly.

## Current validator

Primary script:

```bash
scripts/userspace-ha-failover-validation.sh
```

Baseline command:

```bash
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
scripts/userspace-ha-failover-validation.sh --duration 90 --parallel 4
```

What it now checks:

1. steady-state `.200` reachability before failover
2. continuous `iperf3` health through RG move and failback
3. external IPv4 and IPv6 reachability immediately after each phase and after
   the post-phase observe window
4. standby helper readiness on the old owner after each move
5. evidence that the old owner actually transmitted on the fabric path during
   the phase
6. bounded failover deltas for:
   - session misses
   - neighbor misses
   - route misses
   - policy denied packets
7. post-run throughput, retransmits, and zero-throughput interval counts

## Why we hardened it this way

The old validator proved only that a long-lived `iperf3` run did not fully die.
That was not enough.

We saw real bad states that could still pass a loose end-of-run throughput
check:

- old owner stopped redirecting to the peer fabric
- new owner blackholed external IPv4 but not IPv6
- stale sessions or reverse-session reconstruction caused short but real
  throughput collapses
- the standby helper fell out of the userspace path and traffic died only
  during failback
- the test did not prove the fabric path was exercised at all

So the validator now has to answer three separate questions:

1. Did traffic stay up?
2. Did the correct node own the flow after the move?
3. Did the old owner actually use the fabric redirect path while stale-MAC
   traffic still landed there?

## Historical fixes that got failover to the current state

These are the main changes that materially improved userspace HA failover.

### 1. Fabric redirect runtime state had to be complete

Problem:

- the helper could not always reconstruct a usable fabric redirect from the
  runtime snapshot alone
- stale-MAC traffic on the old owner died instead of crossing the fabric

Fix:

- publish explicit fabric MAC state in the snapshot
- rebuild userspace fabric redirect state from those snapshot MACs

Effect:

- the old owner could actually transmit stale-MAC traffic to the peer

### 2. Reverse synced sessions could not be mirrored blindly

Problem:

- mirroring both forward and reverse cluster-synced sessions poisoned NAT
  semantics on the peer
- reply traffic re-resolved toward the SNAT VIP instead of reversing back to
  the client

Fix:

- mirror only the forward synced entry into the helper
- let the helper derive the reverse session locally from forward metadata and
  the NAT reverse index

Effect:

- failover stopped killing the established TCP flow outright

### 3. Synced sessions had to preserve `fabric_ingress`

Problem:

- session sync lost whether the original flow arrived from the peer fabric
- the new owner rebuilt synced sessions as if they were local ingress sessions

Fix:

- export and preserve `fabric_ingress` through the userspace session delta and
  sync path

Effect:

- takeover kept the same fabric-aware reverse-path semantics as the original
  session

### 4. Passive peer reverse resolution had to prefer local delivery when it owned the client-side RG

Problem:

- the passive peer kept bouncing reverse traffic back onto the fabric even when
  it already owned the client-side RG
- that created line-rate startup followed by stream collapse

Fix:

- keep `fabric_ingress` as a hint, not an unconditional redirect instruction
- resolve locally when the peer actually owns the return path

Effect:

- split-RG steady state stopped collapsing before failover even happened

### 5. Standby nodes had to stay armed

Problem:

- standby helpers were previously left disabled or unarmed when no local data
  RG was active
- traffic landing on the old owner during failback fell out of the userspace
  fabric path

Fix:

- keep the standby helper armed with bindings ready whenever userspace
  forwarding is supported and data RGs exist

Effect:

- failback no longer depended on the standby helper cold-starting under load

### 6. External reachability had to be part of the failover gate

Problem:

- `.200` traffic and even `iperf3` could look alive while external IPv4 or IPv6
  was broken on the new owner

Fix:

- add external IPv4 and IPv6 checks to the failover validator

Effect:

- node-specific WAN ownership bugs stopped hiding behind internal traffic

### 7. Neighbor ownership had to move into the helper

Problem:

- the old manager-pushed neighbor snapshot was eventually consistent and
  time-based
- cold startup and failover still showed missing-neighbor behavior even after
  several incremental fixes

Fix:

- move initial neighbor dump and RTNL subscribe into the helper
- gate startup on helper-owned neighbor readiness

Effect:

- cold `.200` / `::200` bring-up became materially cleaner

### 8. Helper HA state had to be refreshed from the live RG map

Problem:

- after RG moves, the helper could still retain stale `active=false` state on
  the new owner
- that caused `ha_inactive` behavior even though the cluster had already moved

Fix:

- refresh map-derived HA state and republish it into the helper when it
  diverges

Effect:

- failover ownership inside the helper now matches the live RG map more
  reliably

## What the hardened validator proves now

For each failover or failback phase, it captures pre-phase and post-phase
dataplane state and evaluates:

### 1. Immediate target reachability

The script verifies that the host can still reach `${IPERF_TARGET}` right after
the RG move and again after the post-phase interval.

This catches:

- redirect path failure even when `iperf3` is still retrying
- first-hit target unreachability masked by later recovery

### 2. Standby readiness

The old owner must remain:

- `Enabled: true`
- `Forwarding armed: true`
- `Ready bindings: > 0`
- `rg<id> active=false`

This catches:

- standby helper drop-out
- failback regressions caused by the old owner leaving the userspace path

### 3. Fabric-path evidence

The script sums `TXPkts` on the current fabric parent bindings and requires a
positive delta on the old owner across the phase by default.

This catches:

- failover tests that never actually exercised the fabric path
- real redirect failures where stale-MAC traffic landed on the old owner but
  was not transmitted across the fabric

Relevant tuning:

- `REQUIRE_FABRIC_ACTIVITY=1`
- `MIN_FABRIC_TX_DELTA=1`
- `FABRIC_ACTIVITY_TRIGGER_DELTA=8`

Current rule:

- require positive old-owner fabric TX only when the old owner accumulated at
  least `8` units of failover churn across:
  - session misses
  - neighbor misses
  - route misses
  - policy denied packets
- otherwise record the phase as "no stale-owner fabric activity required"

This avoids false failures on clean RG moves where traffic never needed to
traverse the stale owner during the measurement window.

### 4. Phase miss and deny deltas

The script compares pre-phase and post-phase cumulative counters across both
nodes for:

- `Session misses`
- `Neighbor misses`
- `Route misses`
- `Policy denied packets`

Default thresholds:

- `MAX_FAILOVER_SESSION_MISS_DELTA=64`
- `MAX_FAILOVER_NEIGHBOR_MISS_DELTA=20`
- `MAX_FAILOVER_ROUTE_MISS_DELTA=32`
- `MAX_FAILOVER_POLICY_DENIED_DELTA=0`

These values were tuned from live `loss` userspace-cluster artifacts:

- clean failover phases stayed around session-miss deltas of `10-28`
- clean failover phases stayed around neighbor-miss deltas of `0-16`
- route-miss and policy-deny deltas stayed at `0`

This catches:

- partial failover success with hidden dataplane churn
- redirect regressions that recover eventually but do so by missing and
  re-learning too much state
- reverse-path failures that manifest as policy deny spikes

## How to read failures

### `fabric TX delta 0`

Meaning:

- either the test did not actually exercise stale-MAC fabric traversal
- or the old owner failed to redirect traffic onto the fabric

First checks:

1. confirm the old owner stayed armed
2. inspect `Recent userspace exceptions` in the phase artifacts
3. check whether the host refreshed MAC/neighbor state too quickly for the
   phase to require fabric traversal

### `policy denied delta > 0`

Meaning:

- traffic reached a node that did not reconstruct the expected session or
  reverse-path metadata

Typical root causes:

- stale HA state
- bad reverse-session semantics
- wrong owner return-path resolution

### `session miss delta` or `neighbor miss delta` too high

Meaning:

- the failover recovered through churn rather than preserving the flow cleanly

Typical root causes:

- helper neighbor state not ready
- route or next-hop prewarm missing
- fabric-ingress continuity not preserved

### external IPv4 or IPv6 fails while `.200` survives

Meaning:

- failover ownership moved far enough for the test target, but the new WAN
  owner is still wrong or incomplete

Treat this as a real HA failure. Internal target reachability alone is not
enough.

## Operational procedure for a credible failover run

1. Refresh VF state after any reboot of the `loss` host.

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

2. Deploy the intended build.

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

3. Pin the intended RG placement before comparing results.

4. Run the failover validator with enough duration for the planned cycle count.

For multi-cycle runs, let the script choose the duration unless you have a
specific reason to override it. The hardened validator now reserves time for:

- sync wait
- pre-failover observe
- both RG moves per cycle
- failover settle time per cycle

5. Check both the summary output and the artifact directory.

6. Treat any of these as a real regression:
   - zero-throughput intervals
   - dead streams
   - external reachability failures
   - standby not armed
   - fabric TX delta not positive when old-owner churn exceeds the trigger
   - miss/deny deltas over threshold

## Artifact files worth checking first

For each phase:

- `cycle<n>-<phase>-pre-fw0-dp-stats.txt`
- `cycle<n>-<phase>-pre-fw1-dp-stats.txt`
- `cycle<n>-<phase>-post-fw0-dp-stats.txt`
- `cycle<n>-<phase>-post-fw1-dp-stats.txt`

Then:

- `iperf3.log`
- `iperf3.metrics.json`
- `external-*.txt`

Those are the first files to compare when a phase reports:

- missing fabric TX
- policy deny spikes
- unexpected session or neighbor churn
- external IPv4 or IPv6 loss
