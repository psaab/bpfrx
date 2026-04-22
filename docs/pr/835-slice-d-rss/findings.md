# #835 Slice D — Negative finding: ethtool counter signal is dead under AF_XDP zero-copy

## TL;DR

The implementation passes all 33+ unit tests and Codex code review
returned MERGE YES. But the empirical deploy + measurement shows
**the feature is inactive on the loss test cluster**: `ethtool -S
ge-0-0-1` per-ring counters do not advance during iperf3 traffic.
The rebalance loop's trigger condition is never met because the
signal source (per-RX-ring packet counts) is stale. Zero rebalance
actions fire across 10 runs.

This is an **empirical hardware/driver finding**, not a code bug.
The mlx5 VF in this SR-IOV passthrough + AF_XDP zero-copy mode
appears to bypass the per-queue `rx<N>_packets` counter incremen-
ters entirely — packets are zero-copied directly from the RX ring
into the userspace UMEM without crossing the path that updates
those stats.

## Reproduction

```
# Cluster on post-#832 master, workers=6 ge-0-0-1 6 RX rings.
# Verify rebalance loop is running:
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- \
    journalctl -u xpfd --since='-30s' | grep 'rss rebalance loop started'"

# Run iperf3 in background; sample counters during the run.
( sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
    iperf3 -c 172.16.80.200 -P 16 -t 15 -p 5202 -J" > /tmp/i.json ) &
sleep 6
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- \
    ethtool -S ge-0-0-1 | grep -E 'rx_packets:|rx[0-9]+_xsk_packets:'"
sleep 3
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- \
    ethtool -S ge-0-0-1 | grep -E 'rx_packets:|rx[0-9]+_xsk_packets:'"
```

Both samples return identical values; iperf3 simultaneously runs
at 9.57 Gbps. Verified with `rx_packets`, `rx<N>_packets`,
`rx<N>_xsk_packets`, `rx<N>_xdp_drop`, and `rx_packets_phy`. None
move.

## 10-run measurement (deployed; rebalance loop running but inactive)

| Run | Aggregate Gbps | CoV   | Jain  |
|-----|---------------:|------:|------:|
|  1  |          9.57  | 92.7% | 0.554 |
|  2  |          9.57  | 46.1% | 0.834 |
|  3  |          9.57  | 42.0% | 0.858 |
|  4  |          9.57  | 29.7% | 0.924 |
|  5  |          9.57  | 80.9% | 0.620 |
|  6  |          9.57  | 29.7% | 0.924 |
|  7  |          9.57  | 60.4% | 0.745 |
|  8  |          9.57  | 39.9% | 0.870 |
|  9  |          9.57  | 43.5% | 0.850 |
| 10  |          9.57  | 92.8% | 0.553 |

`rss rebalance applied` log lines during the 10-run window: **0**.

These numbers are statistically indistinguishable from the
post-#832 baseline (CoV 19-92% bimodal, Jain 0.55-0.97).

## Acceptance criterion verdict

Per plan §6.4 PASS gate, ALL of:
- p5202 CoV ≤ 25% on ≥ 8 of 10 runs: **FAIL** (only 2 runs ≤ 25%).
- Aggregate ≥ 9.08 Gbps: PASS.
- 0 retransmit regression: PASS.
- ≥ 1 `rss rebalance applied` log line: **FAIL** (zero).
- `make test-failover` passes: not exercised (failed earlier gates).

**Result: PR fails acceptance.** Reverting per §6.5.

## Root cause

mlx5 SR-IOV VF + AF_XDP zero-copy bypasses the kernel-side per-queue
counter increment path. Packets land in the RX descriptor ring,
mlx5's XDP fast-path matches the bound XSK socket, the descriptor
moves directly into the userspace UMEM, and the standard
`rx<N>_packets` counter (which tracks "packet handed up the kernel
stack") is never bumped. Confirmed empirically across 4 different
mlx5 counter families.

## What WOULD work

The xpf-userspace-dp daemon already tracks per-binding RX/TX
counters via its control-socket status JSON (each binding has a
`worker_id`, `ifindex`, `queue_id`, plus `tx_packets`,
`tx_kick_latency_count`, etc.). Bindings are 1:1 with RX rings
on this setup, so per-binding RX counters would be a viable
signal source for the rebalance algorithm.

This requires:
1. Adding a per-binding RX packet counter to the userspace-dp
   daemon (probably trivial — the existing per-binding TX
   counters add ~1 line each).
2. The xpfd Go daemon polling the control socket for these
   stats instead of `ethtool -S`.
3. The rebalance algorithm itself (trigger, weight shift,
   ethtool -X) is unchanged.

## Recommended action

1. **Do not merge this PR**: ship a feature that is provably
   inactive in production would be misleading.
2. Revert the rebalance loop spawn from `daemon.go`.
3. Keep the rebalance code (rss_rebalance.go + tests) and the
   rss_indirection.go atomics + locked split as-is — they are
   correct and tested. The wiring just doesn't fire because the
   signal it consumes is unavailable.
4. File a follow-up issue: "Re-source RSS rebalance signal from
   xpf-userspace-dp per-binding stats instead of ethtool -S".
   The follow-up reuses 90% of the code; only the signal
   source changes.
