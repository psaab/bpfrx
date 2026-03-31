# Failover Testing

This document is the operational reference for HA failover testing only.
It covers the cluster preflight, the supported failover scenarios, the
current scripts, the manual commands, the required artifacts, and the pass
criteria.

Use this document when the goal is one of:

- proving that RG ownership moves cleanly
- proving that flows survive a failover or recover quickly
- proving that a crashed node fails over to the peer
- proving that a rebooted node can rejoin without killing traffic
- proving that split-RG ownership still behaves correctly

For userspace-specific fabric-path interpretation, also use
[userspace-fabric-failover.md](userspace-fabric-failover.md). For broader HA
cluster context, use [ha-cluster.md](ha-cluster.md).

## Scope

This doc covers three failover test families:

1. Userspace HA RG-move testing on the `loss-userspace-cluster`
2. Legacy eBPF HA failover/crash testing on the local Incus HA cluster
3. Manual scenario testing when the scripted harness is not enough

It does not cover:

- standalone single-VM forwarding tests
- generic throughput benchmarking without an HA event
- native GRE specifics beyond failover invocation

## Test Environments

### Userspace HA cluster

- Env file: `test/incus/loss-userspace-cluster.env`
- Firewalls:
  - `bpfrx-userspace-fw0`
  - `bpfrx-userspace-fw1`
- Host:
  - `cluster-userspace-host`
- Main targets:
  - IPv4: `172.16.80.200`
  - IPv6: `2001:559:8585:80::200`

### Legacy eBPF HA cluster

- Firewalls:
  - `bpfrx-fw0`
  - `bpfrx-fw1`
- Host:
  - `cluster-lan-host`

## Tools And Scripts

### Userspace failover scripts

- `scripts/userspace-ha-failover-validation.sh`
  - hardened RG move validation
  - primary failover script for userspace HA continuity
- `scripts/userspace-ha-validation.sh`
  - broader userspace health suite
  - run before blaming failover if steady-state is already broken

### Legacy eBPF failover scripts

- `test/incus/test-failover.sh`
  - reboot/failback survival
- `test/incus/test-ha-crash.sh`
  - force-stop, daemon stop, and crash cycles
- `test/incus/test-double-failover.sh`
- `test/incus/test-stress-failover.sh`
- `test/incus/test-chained-crash.sh`

## Preflight

Do not start failover testing until all of these are true.

### Cluster health

On each firewall:

```bash
cli -c "show chassis cluster status"
cli -c "show chassis cluster data-plane statistics"
```

Required:

- every tested RG has one primary and one secondary
- no dual-active state
- `Takeover ready: yes` on both nodes unless the specific test is validating a
  readiness failure
- on userspace:
  - `Forwarding supported: true`
  - `Enabled: true` on the active node for the tested RG
  - ready bindings are non-zero

### Target reachability

From the test host:

```bash
ping -c 3 172.16.80.200
ping6 -c 3 2001:559:8585:80::200
```

If these fail before the failover event, stop and isolate steady-state first.

### Lab hygiene

On userspace `loss` after a remote host reboot:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

If you are deploying a fresh build:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

## Standard Artifact Collection

Every failover run should leave enough evidence to answer:

1. Did ownership move?
2. Did traffic stay up?
3. If traffic failed, where did it die?

Minimum artifacts:

- `show chassis cluster status` from both nodes
- `show chassis cluster data-plane statistics` from both nodes
- `show chassis cluster data-plane interfaces` from both nodes
- `show security flow session destination-prefix <target>` from both nodes
- host-side `iperf3` JSON or log
- any script artifact directory under `/tmp`

For userspace RG-move testing, the hardened validator already captures these.

## Userspace Failover Test Matrix

Run these in order. Do not skip ahead. A broken earlier phase invalidates the
later ones.

### 1. Steady-state userspace validation

Purpose:

- prove the active node is healthy before introducing failover

Command:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
RUNS=3 DURATION=5 PARALLEL=4 \
PREFERRED_ACTIVE_NODE=0 \
PREFERRED_ACTIVE_RGS="1 2" \
scripts/userspace-ha-validation.sh
```

Pass:

- `.200` and `::200` reachability pass
- no immediate collapse in the steady-state iperf checks
- the intended active node owns the intended RGs

### 2. Hardened RG move under load

Purpose:

- validate RG move and failback while traffic is already established

Baseline command:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
scripts/userspace-ha-failover-validation.sh --duration 90 --parallel 4
```

Useful knobs:

- `SOURCE_NODE`
- `TARGET_NODE`
- `RG`
- `TOTAL_CYCLES`
- `CYCLE_INTERVAL`
- `CHECK_EXTERNAL_REACHABILITY=0`
  - only when the public/WAN path is already down and you are isolating the
    failover dataplane itself
- `TRANSITION_SAMPLE_SECONDS`
- `REQUIRE_FABRIC_ACTIVITY`

Pass:

- RG ownership moves to the requested node
- immediate target reachability returns quickly after each phase
- no sustained zero-throughput collapse
- retransmits stay bounded
- old-owner fabric TX proves stale-owner redirect actually happened
- standby WAN TX stays flat while redirect is expected
- session/neighbor/route/policy deltas stay within threshold

Fail examples:

- `Session misses` spike on the new owner and WAN TX stays near zero
- `iperf3` shows long zero-throughput windows after the RG move
- target stays down until long after the phase timeout

### 3. Manual CLI RG move under active traffic

Purpose:

- reproduce operator-reported failover behavior exactly
- validate the manual CLI path, not just the harness

Start traffic from the host:

```bash
iperf3 -c 172.16.80.200 -P 8 -t 120
```

Move the RG from the current primary:

```bash
cli -c "request chassis cluster failover redundancy-group 1 node 1"
```

Repeat in the opposite direction:

```bash
cli -c "request chassis cluster failover redundancy-group 1 node 0"
```

Pass:

- throughput may dip, but recovers quickly and stays relatively flat
- new connections succeed immediately after the move
- the moved RG remains on the requested node

Required live checks during manual RG move:

```bash
cli -c "monitor interface <fabric-parent>"
cli -c "monitor interface <wan-parent>"
cli -c "show chassis cluster data-plane statistics"
cli -c "show security flow session destination-prefix 172.16.80.200/32"
```

### 4. Hard crash / power-cut failover

Purpose:

- validate worst-case failover when the primary does not demote cleanly

From the active primary:

```bash
echo b > /proc/sysrq-trigger
```

Run this with active host traffic already established.

Pass:

- the secondary takes over quickly
- traffic recovers and stays up
- the rebooted node rejoins as secondary
- the rejoin does not kill traffic again

After the rebooted VM comes back:

- verify `show chassis cluster status`
- verify both nodes are healthy
- verify traffic is still flowing

### 5. Rejoin and re-move

Purpose:

- prove that the cluster is still healthy after the crash and rejoin, not just
  that one takeover succeeded

After the crashed node rejoins:

1. start a fresh `iperf3 -P 8`
2. move the RG again with CLI failover
3. verify flows still recover and stay flat

Pass:

- no new collapse introduced by the rejoined node
- takeover readiness returns on both nodes

### 6. Split-RG active/active validation

Purpose:

- validate active/active ownership, not just all-RGs-on-one-node

Example target state:

- `RG1` on `node1`
- `RG2` on `node0`

Move the groups explicitly:

```bash
cli -c "request chassis cluster failover redundancy-group 1 node 1"
cli -c "request chassis cluster failover redundancy-group 2 node 0"
```

Then validate:

- both RGs stay on the intended nodes
- both nodes report healthy status
- traffic still passes

Then crash one node with:

WARNING: The following command forces an immediate kernel reboot without syncing disks. It can corrupt filesystems and should only be run in lab/test environments, never on production systems.
```bash
echo b > /proc/sysrq-trigger
```

Pass:

- the surviving node takes over the lost RGs
- traffic continues or recovers quickly
- no stuck `session sync not ready` state remains after convergence

### 7. Multi-cycle stress

Purpose:

- catch flaky handoff paths that pass once and fail later

Recommended:

- run multiple RG move cycles with `TOTAL_CYCLES > 1`
- run crash/rejoin cycles after a successful RG move cycle
- run split-RG crash in both directions

## Legacy eBPF Failover Tests

Use these when validating the non-userspace cluster.

### Reboot/failback survival

```bash
./test/incus/test-failover.sh
```

This covers:

- active `iperf3` through the primary
- reboot of `fw0`
- failover to `fw1`
- rejoin of `fw0`
- manual failback

### Crash / daemon-stop / multi-cycle

```bash
./test/incus/test-ha-crash.sh
```

This covers:

- force-stop / power-loss style failover
- daemon stop on the primary
- multi-cycle recovery

### Stress scripts

```bash
./test/incus/test-double-failover.sh
./test/incus/test-stress-failover.sh
./test/incus/test-chained-crash.sh
```

Use these after the basic reboot/crash paths pass.

## Pass Criteria

Do not call failover healthy unless all of the following are true for the
scenario being tested.

- RG ownership moves to the intended node
- no dual-active state appears
- the new owner actually forwards traffic
- the old owner uses the fabric path when stale-owner redirect is expected
- the standby WAN does not leak traffic when it should be inactive
- established flows recover and stay relatively flat
- fresh flows succeed immediately after the move
- the rebooted node rejoins without killing existing traffic
- post-test cluster status is healthy and takeover-ready

## When To Use Packet Capture

Use packet capture only when counters and session state are not enough to
distinguish where the flow died.

On the remote target `.200`, use the gRPC capture/tcpdump workflow already
documented for the lab instead of assuming local shell access. Typical capture
targets:

- host side toward the VIP/target
- primary WAN parent
- primary fabric parent
- secondary fabric parent
- `.200` endpoint

## Common Failure Shapes

### Old owner still receives, new owner never transmits

Likely areas:

- stale-owner redirect path
- helper HA active/inactive state
- synced-session promotion on the new owner

### Fabric RX rises, WAN TX stays flat, session misses spike

Likely areas:

- session import / reverse reconstruction
- wrong HA disposition on inherited sessions
- stale aliasing or wrong owner RG on the new owner

### First probe after restart fails, second succeeds

Likely areas:

- neighbor warmup / pending-neighbor retry
- cold-start helper state

### Crash takeover works, manual RG move fails

Likely areas:

- demotion prep
- barrier / sync readiness
- moved-session invalidation and re-install ordering

## Reset Between Runs

Always restore the cluster before the next scenario.

At minimum:

1. stop any stale `iperf3`
2. verify both VMs are up
3. verify `bpfrxd` is active
4. verify cluster status is stable
5. reset any stale manual failover flags if needed
6. pin RG ownership to the intended starting node

Userspace example:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
./test/incus/cluster-setup.sh restart all
```

If the goal is only to restore RG placement, use the CLI failover commands and
wait for convergence instead of doing an unnecessary redeploy.

## Recommended Execution Order For Release Validation

Use this order when validating HA/failover for a serious userspace change.

1. `scripts/userspace-ha-validation.sh`
2. one-cycle `scripts/userspace-ha-failover-validation.sh`
3. manual CLI RG move under `iperf3 -P 8`
4. hard crash of the active primary with traffic running
5. rebooted-node rejoin validation
6. another manual RG move after rejoin
7. split-RG placement validation
8. split-RG crash in both directions
9. multi-cycle failover stress

If any earlier phase fails, stop and fix that first. Later failover tests are
not trustworthy on top of a broken baseline.
