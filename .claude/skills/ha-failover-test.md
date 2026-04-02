---
name: ha-failover-test
description: Run the HA failover test matrix for the bpfrx userspace dataplane cluster
user-invocable: true
---

# HA Failover Test

Run the full HA failover test matrix from `testing-docs/failover-testing.md` against the userspace cluster on loss.

## Environment

- Env file: `test/incus/loss-userspace-cluster.env`
- Firewalls: `loss:bpfrx-userspace-fw0`, `loss:bpfrx-userspace-fw1`
- Host: `loss:cluster-userspace-host`
- Test target: **172.16.80.200** (NEVER use 172.16.50.x)
- All incus commands: `sg incus-admin -c "..."`

## Instructions

Run the test matrix IN ORDER. A broken earlier phase invalidates later ones. For each phase, report PASS/FAIL with key metrics.

### Preflight

Before any test, verify:

```bash
# Both nodes healthy and takeover ready
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- cli -c 'show chassis cluster status'"

# Target reachable
sg incus-admin -c "incus exec loss:cluster-userspace-host -- ping -c 3 -W 2 172.16.80.200"
```

Required: all RGs have one primary + one secondary, both show `Takeover ready: yes`, ping succeeds.

If preflight fails, deploy first:
```bash
ENV_FILE=test/incus/loss-userspace-cluster.env sg incus-admin -c "./test/incus/cluster-setup.sh deploy all"
```

### Test 1: Steady-state validation

Purpose: prove the active node is healthy before introducing failover.

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 -t 5 -P 4"
```

Pass: all 4 streams carry traffic, total > 5 Gbps, no zero-throughput intervals.

### Test 2: Manual CLI RG move under active traffic

Purpose: validate that established TCP flows survive an RG move.

```bash
# Start long-running iperf3
sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -t 60 -P 4 -i 1 > /tmp/failover-test.log 2>&1 &'"
sleep 10

# Capture pre-failover state
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- cli -c 'show chassis cluster data-plane statistics'" | grep -E 'SNAT|Session hits|Session miss'

# Move RG1 to node1
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- cli -c 'request chassis cluster failover redundancy-group 1 node 1'"
sleep 15

# Capture post-failover state on NEW owner
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw1 -- cli -c 'show chassis cluster status'" | grep -A2 'group: 1'
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw1 -- cli -c 'show chassis cluster data-plane statistics'" | grep -E 'SNAT|Session hits|Session miss|Sessions installed'

# Wait for iperf3 to finish, check results
sleep 40
sg incus-admin -c "incus exec loss:cluster-userspace-host -- grep 'receiver' /tmp/failover-test.log"
```

Pass criteria:
- RG1 moves to node1
- SNAT packets > 0 on new owner (proves NAT applied)
- All 4 iperf3 streams show non-zero throughput
- Session misses < 1000 on new owner

Fail indicators:
- SNAT packets = 0 on new owner (NAT not applied → streams die)
- Session misses > 100K (sessions not synced)
- iperf3 streams at 0 bits/sec after failover

### Test 3: Move RG back (failback)

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -t 60 -P 4 -i 1 > /tmp/failback-test.log 2>&1 &'"
sleep 10

# Move RG1 back to node0
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw1 -- cli -c 'request chassis cluster failover redundancy-group 1 node 0'"
sleep 15

sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- cli -c 'show chassis cluster data-plane statistics'" | grep -E 'SNAT|Session hits'
sleep 40
sg incus-admin -c "incus exec loss:cluster-userspace-host -- grep 'receiver' /tmp/failback-test.log"
```

Same pass criteria as Test 2.

### Test 4: Hardened automated RG move

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
PREFERRED_ACTIVE_NODE=0 \
sg incus-admin -c "scripts/userspace-ha-failover-validation.sh --duration 240 --parallel 4"
```

Pass: zero zero-throughput intervals, all streams carry traffic through all 3 cycles.

### Test 5: Hard crash failover

```bash
# Start traffic
sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -t 120 -P 4 -i 1 > /tmp/crash-test.log 2>&1 &'"
sleep 10

# Force-reboot the primary
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- bash -c 'echo b > /proc/sysrq-trigger'"
sleep 30

# Check secondary took over
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw1 -- cli -c 'show chassis cluster status'"

# Wait for fw0 to rejoin
sleep 90
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- cli -c 'show chassis cluster status'"
```

Pass: secondary takes over, traffic recovers, rebooted node rejoins as secondary.

## Key Diagnostic Commands

When a test fails, capture:

```bash
# Both nodes
for node in bpfrx-userspace-fw0 bpfrx-userspace-fw1; do
    echo "=== $node ==="
    sg incus-admin -c "incus exec loss:$node -- cli -c 'show chassis cluster status'"
    sg incus-admin -c "incus exec loss:$node -- cli -c 'show chassis cluster data-plane statistics'" | grep -E 'SNAT|Session|Forward|flow cache|installed'
    sg incus-admin -c "incus exec loss:$node -- cli -c 'show security flow session destination-prefix 172.16.80.200/32'" | head -10
done
```

## Known Issues

- iperf3 server must be running on the host (`iperf3 -s -D`) — restart if stale
- The automated validation script threshold (18 Gbps) may be too high for some environments — use manual tests for validation
- After hard crash, wait 60-90s for the rebooted node to fully rejoin before testing again
