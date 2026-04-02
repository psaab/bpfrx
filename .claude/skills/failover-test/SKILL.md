---
name: failover-test
description: Run iperf3 throughput through the HA cluster while cycling RG failovers. Verifies zero-drop failover with configurable iterations.
user-invocable: true
---

# HA Failover Test Skill

Run iperf3 traffic through the firewall cluster while cycling redundancy-group failovers. Every 1-second interval must maintain throughput between ~4 Gbps (split-RG fabric) and ~22 Gbps (same-node). Zero intervals at 0 Gbps.

## Arguments

- `/failover-test` — 2 cycles (default)
- `/failover-test 5` — 5 cycles
- `/failover-test 3 rg2` — 3 cycles on RG2

## Procedure

1. **Build and deploy**: build Go + Rust binaries, deploy to BOTH firewalls
2. Detect environment (loss userspace cluster preferred, local cluster fallback)
3. Wait for cluster readiness (both nodes `Takeover ready: yes`, up to 60s)
4. Pre-flight: both nodes active, helpers running, cluster healthy, iperf3 connectivity to 172.16.80.200
5. Record initial RG ownership
6. Start iperf3 with `-t $((CYCLES*20+30)) -i 1 -P 4 --forceflush`
7. Wait 10s for stabilization
8. For each cycle: failover RG to other node, wait 15s
9. Collect iperf3 output
10. Parse SUM intervals: PASS if all > 3 Gbps, FAIL if any = 0
11. Reset RGs to original owners

## Build and Deploy

ALWAYS build and deploy before running tests. Stale binaries are the #1 source of false failures.

```bash
# Build Go daemon + Rust helper + XDP shim
make build
cd userspace-dp && cargo build --release && cd ..
cp userspace-dp/target/release/bpfrx-userspace-dp .

# Deploy to both firewalls via rolling deploy
ENV_FILE=test/incus/loss-userspace-cluster.env sg incus-admin -c "./test/incus/cluster-setup.sh deploy all"

# Verify both nodes have correct binaries
for node in bpfrx-userspace-fw0 bpfrx-userspace-fw1; do
    sg incus-admin -c "incus exec loss:$node -- md5sum /usr/local/sbin/bpfrxd /usr/local/sbin/bpfrx-userspace-dp"
done
md5sum bpfrxd bpfrx-userspace-dp

# Wait for cluster readiness (both takeover ready)
for i in $(seq 1 12); do
    fw0=$(sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- cli -c 'show chassis cluster status'" 2>&1 | grep -c "Takeover ready: yes")
    fw1=$(sg incus-admin -c "incus exec loss:bpfrx-userspace-fw1 -- cli -c 'show chassis cluster status'" 2>&1 | grep -c "Takeover ready: yes")
    [ "$fw0" -ge 3 ] && [ "$fw1" -ge 3 ] && break
    sleep 5
done
```

If binary checksums don't match after deploy, force-push manually:
```bash
sg incus-admin -c "incus exec loss:$node -- systemctl stop bpfrxd"
sg incus-admin -c "incus exec loss:$node -- pkill -9 bpfrx-userspace"
sleep 1
sg incus-admin -c "incus file push bpfrxd loss:$node/usr/local/sbin/bpfrxd --mode 0755"
sg incus-admin -c "incus file push bpfrx-userspace-dp loss:$node/usr/local/sbin/bpfrx-userspace-dp --mode 0755"
sg incus-admin -c "incus exec loss:$node -- systemctl start bpfrxd"
```

## Environment

```
loss-userspace-cluster:
  FW0=loss:bpfrx-userspace-fw0  FW1=loss:bpfrx-userspace-fw1
  HOST=loss:cluster-userspace-host  TARGET=172.16.80.200
  CLI=/usr/local/sbin/cli
local-cluster:
  FW0=bpfrx-fw0  FW1=bpfrx-fw1
  HOST=cluster-lan-host  TARGET=172.16.80.200
```

All incus commands: `sg incus-admin -c "incus exec ..."`.

## Pass/Fail

- PASS: zero intervals at 0, all intervals 3-25 Gbps
- FAIL: any interval at 0 (critical), any below 3 (warning)

## Additional Tests

### Hard crash failover (`/failover-test crash`)

Start iperf3, then force-reboot the primary:
```bash
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- bash -c 'echo b > /proc/sysrq-trigger'"
```
Wait 30s, verify secondary took over, traffic recovers. Wait 90s for rejoin.

### Manual CLI RG move (`/failover-test manual`)

Start iperf3 60s, move RG mid-stream:
```bash
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- cli -c 'request chassis cluster failover redundancy-group 1 node 1'"
```
Check SNAT packets > 0 on new owner. Move back. All 4 streams must survive.

## Diagnostics

When a test fails, capture from both nodes:
```bash
for node in bpfrx-userspace-fw0 bpfrx-userspace-fw1; do
    echo "=== $node ==="
    sg incus-admin -c "incus exec loss:$node -- cli -c 'show chassis cluster status'"
    sg incus-admin -c "incus exec loss:$node -- cli -c 'show chassis cluster data-plane statistics'" | grep -E 'SNAT|Session|Forward|flow cache|installed'
    sg incus-admin -c "incus exec loss:$node -- cli -c 'show security flow session destination-prefix 172.16.80.200/32'" | head -10
done
```

## Known Issues

- iperf3 server must be running on the host (`iperf3 -s -D`) — restart if stale
- After hard crash, wait 60-90s for rebooted node to fully rejoin
- If `Takeover ready: no (session sync not ready)` persists > 60s, restart both daemons
