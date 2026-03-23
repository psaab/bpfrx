# Performance Tests

## Overview

Performance tests measure forwarding throughput, latency, and CPU efficiency. They require dedicated hardware (SR-IOV VFs or PCI passthrough NICs).

## Test 1: Baseline Throughput

**What it tests**: Maximum sustained forwarding rate through the dataplane.

```bash
# Userspace cluster (mlx5 zero-copy AF_XDP)
scripts/userspace-perf-compare.sh --runs 3 --duration 10

# Or manually:
incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 -P 8 -t 10
incus exec loss:cluster-userspace-host -- iperf3 -c 2001:559:8585:80::200 -P 8 -t 10
```

**Expected baselines**:

| Metric | eBPF (kernel) | Userspace (XSK) |
|--------|--------------|-----------------|
| IPv4 TCP 8-stream | ~13 Gbps | 20-23 Gbps |
| IPv6 TCP 8-stream | ~13 Gbps | 20-23 Gbps |
| Cold TCP connect | ~1s (TCP retransmit) | ~2ms (buffer-retry) |
| Cold iperf3 IPv4 | N/A | 20+ Gbps |
| Cold iperf3 IPv6 | N/A | 20+ Gbps |

## Test 2: CPU Profiling

**What it tests**: Hot functions and potential regressions.

```bash
scripts/userspace-perf-compare.sh --perf --runs 1 --duration 30
```

Or manual perf:
```bash
# On the firewall VM
perf record -g -p $(pgrep bpfrx-userspace) -- sleep 30
perf report --sort comm,dso,symbol
```

**Key symbols to watch**:
- `poll_binding` — main packet processing loop
- `rewrite_forwarded_frame_in_place` — frame rewrite (should be < 10% of total)
- `apply_rewrite_descriptor` — descriptor fast path
- `__htab_map_lookup_and_delete_batch` — BPF map operations (session sync)
- `napi_busy_loop` — should be 0% (SO_BUSY_POLL was reverted)

## Test 3: Flow Cache Hit Rate

**What it tests**: Percentage of established-flow packets served from the flow cache.

```bash
# During iperf3 run, check the helper's counters:
# (from daemon logs or status endpoint)
# flow_cache_hits / total_rx_packets should be > 90% for sustained TCP
```

## Test 4: A/B Comparison

**What it tests**: Throughput difference between two code versions.

```bash
# Save baseline
scripts/userspace-perf-compare.sh --runs 3 --duration 10 > baseline.txt

# Deploy new code
make cluster-deploy  # or loss-cluster-deploy

# Compare
scripts/userspace-perf-compare.sh --runs 3 --duration 10 > candidate.txt
diff baseline.txt candidate.txt
```

**Regression threshold**: > 5% drop in sustained throughput is a regression.

## Test 5: Latency Under Load

**What it tests**: Per-packet latency during sustained load.

```bash
# Start background load
incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 -P 4 -t 30 &

# Measure latency
incus exec loss:cluster-userspace-host -- ping -c 20 -i 0.1 172.16.80.200
```

**Pass criteria**: P99 latency < 5ms under load (no stalls from lock contention).
