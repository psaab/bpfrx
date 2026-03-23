# HA Cluster Tests

## Overview

HA cluster tests validate failover, crash recovery, session sync, fabric forwarding, and VRRP behavior. These require a two-VM cluster (eBPF or userspace) with a test host.

## Prerequisites

```bash
# eBPF cluster
make cluster-deploy                # Build + push to bpfrx-fw0 + bpfrx-fw1

# Userspace cluster (on loss remote)
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

**IMPORTANT**: After deploying new code, ALWAYS restart the daemons on BOTH nodes. The deploy script does NOT auto-restart.

## Test 1: Basic Failover (`make test-failover`)

**What it tests**: TCP survives reboot of the primary node during active iperf3 traffic.

**Procedure**:
1. Verify fw0 is primary
2. Start iperf3 -P 8 from cluster-lan-host to WAN target
3. Reboot fw0 (SIGTERM + hard reboot)
4. Verify iperf3 continues on fw1 (failover)
5. Wait for fw0 to come back
6. Verify failback completes
7. Check iperf3 final bitrate > threshold

**Pass criteria**: iperf3 completes without error, combined bitrate above minimum.

```bash
make test-failover
```

## Test 2: Crash Recovery (`make test-ha-crash`)

**What it tests**: Daemon crash (SIGKILL), graceful stop, multi-cycle crash recovery.

**Scenarios**:
- Force-stop (SIGKILL) fw0 → verify fw1 takes over
- Daemon-stop (systemctl stop) fw0 → planned shutdown with priority-0 burst
- Multi-cycle: crash fw0, recover, crash fw1, recover

```bash
make test-ha-crash
```

## Test 3: Restart Connectivity (`make test-restart-connectivity`)

**What it tests**: Zero packet loss during daemon restart on the primary.

**Procedure**:
1. Start continuous ping from host to WAN target
2. Restart bpfrxd on primary (systemctl restart)
3. Count lost pings during restart window
4. Verify loss is within acceptable threshold

```bash
make test-restart-connectivity
```

## Test 4: Stress Failover

**What it tests**: Rapid repeated failover cycles don't break the cluster.

```bash
./test/incus/test-stress-failover.sh
```

## Test 5: Double Failover

**What it tests**: Two consecutive failovers (fw0→fw1→fw0) during active traffic.

```bash
./test/incus/test-double-failover.sh
```

## Test 6: Chained Crash

**What it tests**: Sequential crash of both nodes with recovery between each.

```bash
./test/incus/test-chained-crash.sh
```

## Test 7: Active-Active (Per-RG)

**What it tests**: Different RGs primary on different nodes simultaneously.

```bash
./test/incus/test-active-active.sh
```

## Test 8: Private RG

**What it tests**: Redundancy group with isolated failover (doesn't affect other RGs).

```bash
./test/incus/test-private-rg.sh
```

## Userspace-Specific HA Tests

### Full Validation Suite

```bash
scripts/userspace-ha-validation.sh
```

Tests: cluster status, iperf3 IPv4/IPv6, mtr (embedded ICMP), cold start after restart, neighbor resolution.

### Failover Validation

```bash
scripts/userspace-ha-failover-validation.sh
```

Tests: failover timing, session continuity, VIP migration, GARP/NA burst.

## Manual Validation Checklist

After any HA code change, verify:

- [ ] `show chassis cluster status` — all RGs have primary + secondary
- [ ] Fabric forwarding path ready on both nodes
- [ ] VIPs present on primary only
- [ ] Session sync count > 0 after establishing flows
- [ ] Ping 172.16.80.200 / 2001:559:8585:80::200 from host — 0% loss
- [ ] iperf3 -P 8 > 18 Gbps (userspace) or > 13 Gbps (eBPF)
- [ ] mtr shows intermediate hops (embedded ICMP NAT reversal)
- [ ] After `systemctl restart bpfrxd` on primary: connectivity recovers within 40s
- [ ] After failover: connectivity recovers within 500ms
