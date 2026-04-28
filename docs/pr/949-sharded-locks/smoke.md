# #949 cluster smoke + contention evidence

Captured 2026-04-28 on `loss:xpf-userspace-fw0/fw1` userspace cluster.

- Branch: `refactor/949-rcu-locks` (commit `430928ec`).
- Deploy: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
  ./test/incus/cluster-setup.sh deploy`.
- CoS config: post-#951 7-class config, re-applied after each deploy.
- Source: cluster-userspace-host (10.0.61.102).
- Target: 172.16.80.200.

## Throughput gates (all clear)

| Test | Gate | Result |
|---|---|---|
| iperf-c P=12 | ≥ 22 Gb/s | **23.4 Gb/s, 25 retx** ✓ |
| iperf-c P=1  | ≥ 6 Gb/s  | **6.96 Gb/s, 0 retx** ✓ |
| iperf-b P=12 | ≥ 9.5 Gb/s, 0 retx | **9.58 Gb/s, 0 retx** ✓ |

## Contention measurement

The plan listed `perf c2c record cache-line bouncing must drop ≥ 50 %`
as a HARD gate. **`perf c2c` is not supported in the Incus VM**:

```
sudo perf c2c record -F 99 -p $PID -- sleep 15
failed: memory events not supported
```

Memory events (PEBS / IBS) require host-level perf access that the
nested VM environment does not provide. The plan gate as literally
specified cannot be met in this test environment. Substitute evidence
follows.

## Substitute: P=128 contention-revealing throughput

The dynamic_neighbors mutex is most heavily contended when many
concurrent flows generate flow-cache misses. The standard P=12 test
hits the flow cache after warmup and rarely touches the neighbor
mutex — by design, this is why master P=12 is already 23 Gb/s.

P=128 forces 128 concurrent TCP flows, each potentially creating
flow-cache evictions and forcing neighbor re-lookups. This makes the
mutex contention observable as a throughput bottleneck.

**BEFORE/AFTER comparison under iperf-c P=128, 10 s:**

| Metric | BEFORE (origin/master) | AFTER (#949) | Δ |
|---|---|---|---|
| Throughput | 18.3 Gb/s | **21.9 Gb/s** | **+19.7 %** |
| Retx | 254,354 | 216,788 | −14.8 % |

The +19.7 % throughput improvement under high concurrency is the
empirical signature of reduced mutex contention. At low concurrency
(P=12) the mutex isn't a bottleneck and the refactor is throughput-
neutral.

## perf stat cache events (informational)

`perf stat -e cache-references,cache-misses,instructions,cycles -p
<userspace-dp PID> -- sleep 10` while the P=128 iperf3 ran:

| Metric | BEFORE | AFTER |
|---|---|---|
| cache-references | 1.94 B | (varies by sample) |
| cache-miss rate | 74.7 % | ~72-73 % |
| IPC | 1.068 | 1.03-1.04 |

`perf stat` numbers are dominated by AF_XDP RX/TX ring activity, not
the neighbor cache lookups specifically. The 2-3 percentage-point
cache-miss improvement is consistent with reduced cache-line bouncing
on the (now-sharded) mutex line, but is not load-bearing evidence —
the throughput delta above is.

## Test suite

`cargo test --release`: **813 passed, 0 failed, 2 ignored.**
- 798 prior tests unchanged.
- 15 new unit tests for `ShardedNeighborMap`:
  - `get_returns_inserted_value`
  - `get_returns_none_for_missing_key`
  - `remove_clears_entry`
  - `remove_if_present_returns_true_when_existing_false_when_absent`
  - `insert_if_changed_returns_true_on_first_insert`
  - `insert_if_changed_returns_false_on_same_mac`
  - `insert_if_changed_returns_true_on_mac_change`
  - `len_sums_across_shards`
  - `with_all_shards_clear_via_each_shard_mut`
  - `with_all_shards_atomic_replace`
  - `padded_shard_align_at_least_64`
  - `shard_distribution_ipv4_24_constant_ifindex`
  - `shard_distribution_ipv4_16`
  - `shard_distribution_ipv6_slaac`
  - `poison_recovered_via_into_inner`

All shard-distribution tests confirm that the `key.hash() *
0x9E3779B97F4A7C15 → top 6 bits` mix produces a uniform-enough
distribution for IPv4 /24, IPv4 /16, and IPv6 SLAAC-pattern key
distributions (max bin ≤ 2× ideal in all but the smallest N=256
case where statistical variance bounds the max bin to ≤ 3× ideal).

## Test command transcripts

```
$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5203 -P 12 -t 10'"
[SUM]   0.00-10.00  sec  27.3 GBytes  23.4 Gbits/sec   25             sender
[SUM]   0.00-10.01  sec  27.3 GBytes  23.4 Gbits/sec                  receiver

$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5203 -P 1 -t 5'"
[  5]   0.00-5.00   sec  4.06 GBytes  6.96 Gbits/sec    0            sender

$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5202 -P 12 -t 10'"
[SUM]   0.00-10.00  sec  11.2 GBytes  9.58 Gbits/sec    0             sender

# P=128 BEFORE (origin/master):
[SUM]   0.00-10.02  sec  21.3 GBytes  18.3 Gbits/sec  254354             sender

# P=128 AFTER (#949):
[SUM]   0.00-10.02  sec  25.6 GBytes  21.9 Gbits/sec  216788             sender
```

## Acceptance summary

| Gate | Status |
|---|---|
| `cargo build --release` clean | ✓ |
| `cargo test --release` 813/813 | ✓ |
| iperf-c P=12 ≥ 22 Gb/s | ✓ (23.4 Gb/s) |
| iperf-c P=1 ≥ 6 Gb/s | ✓ (6.96 Gb/s) |
| iperf-b P=12 ≥ 9.5 Gb/s, 0 retx | ✓ (9.58 Gb/s, 0 retx) |
| `perf c2c` cache-line bouncing ≥ 50 % drop | **n/a — not supported in VM** |
| Contention substitute: P=128 throughput improvement | ✓ (+19.7 %) |

The `perf c2c` gate as literally specified cannot be measured in this
environment. The P=128 throughput improvement (+19.7 %) is offered
as substitute evidence that the sharding reduces real-world
contention. Reviewer judgment: is this acceptable as an alternative
to the original gate?
