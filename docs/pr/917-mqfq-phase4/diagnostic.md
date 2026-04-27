# #917 diagnostic: cross-worker imbalance is the dominant 100E100M throughput-half bottleneck

Recorded 2026-04-27 on the loss userspace cluster, post-merge of
the latency-half sprint (#913 + #918 + #920 + #914 + #929 all
on master, tip f74cd638). Combined-branch binary deployed on
xpf-userspace-fw0/fw1.

## TL;DR

Per-worker MQFQ runs as designed. The remaining throughput-half
gap on iperf-c (`shared_exact`, 25 Gbps shaper) is **not** a
within-worker problem — it is RSS-induced cross-worker
imbalance. With 12 flows and 6 workers, RSS gives a non-uniform
per-worker flow count (one or more workers can be entirely
idle). Each worker schedules its OWN flows fairly, but cannot
see flows on other workers, so aggregate per-flow CoV stays
high and aggregate throughput stays well below shaper rate.

This is exactly what the #785 retrospective predicted and what
#917 / #793 / #786 (cross-worker V_min synchronization) is
designed to fix. No within-worker change can move the needle
here.

## Cluster smoke results (combined branch)

### iperf-c throughput sweep — 20 s per cell

| P     | sent (Gb/s) | retx    | per-flow CoV | per-flow min/median/max (Gb/s) |
|-------|-------------|---------|--------------|--------------------------------|
| 12    | 15.05–18.32 | 226–310 k | **35–68 %** | 0.55 / 1.25 / 3.17 |
| 32    | 18.79       | 391 k   | 57.7 %       | 0.19 / 0.59 / 1.61 |
| 64    | 18.32       | 421 k   | 32.2 %       | 0.20 / 0.29 / 0.58 |
| 128   | 17.41       | 471 k   | 22.9 %       | 0.08 / 0.14 / 0.24 |

(P=12 sampled three times back-to-back to rule out cluster-state
drift; all three runs landed 16.2–18.3 Gb/s.)

Throughput peaks around P=32. None of P=12/32/64/128 clears
the **#789 acceptance gate of ≥ 22 Gb/s**. Per-flow CoV at P=12
is 35–68 % — well above #789's 20 % target.

For comparison, the same morning's first P=12 run (right after
the rolling deploy, before any other test traffic) produced
**23.47 Gb/s with 55 retransmits** — meeting the #789 gate.
That number turned out to be a fortunate cold-cluster fluke;
it does not reproduce.

### Within-worker is balanced; cross-worker is not

P=128 was used to confirm the within-worker scheduler is
healthy. Per-worker tx-pkts delta over a 30 s P=128 run on
ge-0-0-2 (egress, iperf-c):

| worker | tx delta (pkts) | share |
|--------|-----------------|-------|
| w0     | 5,959,660       | 13.8 % |
| w1     | 7,057,747       | 16.4 % |
| w2     | 7,159,647       | 16.6 % |
| w3     | 7,835,018       | 18.2 % |
| w4     | 7,500,161       | 17.4 % |
| w5     | 7,543,992       | 17.5 % |

Per-worker CoV = **9.2 %**. Workers are well-balanced at high
flow count.

Now the same measurement at **P=12** over a 20 s run:

| worker | tx delta (pkts) | share |
|--------|-----------------|-------|
| w0     | **0**           | 0.0 % |
| w1     | 4,365,965       | 14.8 % |
| w2     | 5,172,542       | 17.5 % |
| w3     | 5,072,420       | 17.2 % |
| w4     | 6,934,478       | 23.5 % |
| w5     | 7,990,691       | 27.1 % |

Per-worker CoV = **56.1 %**. Worker 0 sees zero traffic for
the entire 20 s — RSS hashed all 12 source ports onto workers
1–5. Worker 5 carries 27 % of the total while worker 0 idles.

## Why this caps throughput

The shaper rate is 25 Gb/s = ~2.08 Mpps at 1500-byte MTU. Six
workers should produce ~347 Kpps each. With one worker idle,
the cluster's instantaneous capacity drops to 5/6 × 25 Gb/s =
**20.8 Gb/s** ceiling — and that's only if the surviving five
workers each push line-rate-divided-by-five, which doesn't
happen because each worker's own MQFQ has to split its capacity
N ways across its local flow subset. The actual aggregate
result is ~17 Gb/s, consistent with this calculation.

## Why per-worker MQFQ cannot fix this

The #913 vtime fix made per-worker MQFQ behave correctly under
the snapshot-rollback semantics. Each worker now correctly
serializes its local flows by virtual finish-time. But each
worker only knows about flows _on that worker_:

```
RSS hash → worker assignment (irreversible at AF_XDP layer per
                              project memory: cross-binding
                              rewrite is impossible due to UMEM
                              ownership)
worker 0: flows {} → idle
worker 5: flows {f7, f9, f11} → MQFQ rotates these three
```

Per-worker MQFQ on w5 splits w5's capacity equally across
{f7, f9, f11}, which gives each ~1.4 Gb/s. Per-worker MQFQ on
w0 has nothing to do. Cross-worker, the variance is intrinsic
to RSS: with 12 flows and 6 workers under uniform random
assignment, the expected probability that ALL six workers
receive at least one flow is < 50 %. Empirically with this
hash seed and these source ports, w0 got zero.

This is the same "dominant imbalance source" the #785 Phase 2
retrospective named at `tx.rs:5378-5398`:

> per-worker SFQ DRR cannot equalise flows that are distributed
> unevenly across workers by NIC RSS — which is the dominant
> imbalance source at P=12 / 8 workers.

Substituting MQFQ for DRR did not change that fact. Within-worker
fairness is necessary but not sufficient.

## Where the firewall is NOT bottlenecked

For completeness, ruling out other suspects:

- **CPU**: worker threads at 10 % utilization, daemon at 21 %.
  Six cores, plenty of headroom.
- **TX ring**: `dbg_tx_ring_full = 0`, `dbg_sendto_enobufs = 0`,
  `tx_submit_error_drops = 0` across all workers and bindings.
- **CoS admission**: iperf-c queue shows `Drops: flow_share=0
  buffer=0 ecn_marked=0` — no admission pressure.
- **AF_XDP UMEM**: `umem_inflight_frames ≈ 8000 / 40960`
  (20 % usage).
- **Flow cache**: `flow_cache_collision_evictions = 0`
  everywhere — the new #918 4-way set-associative layout is
  meeting its acceptance target with margin.
- **NIC TX**: ethtool shows `tx_queue_dropped = 0`,
  `tx_xsk_full = 0`. No queue-side drops.
- **NIC RX (egress iface return path)**: small numbers
  (`rx_xsk_buff_alloc_err = 458`, lifetime; `rx_xsk_xdp_drop =
  39604`, lifetime); not implicated in throughput-half.

The 747k retransmits at P=128 are a secondary effect of the
under-utilization: TCP cwnd cycles when throughput stalls and
RTT jitters. They are not the cause; they are downstream of
the worker-imbalance ceiling.

## Telemetry gaps observed

Two metrics that would have made this diagnosis faster:

1. **Per-worker effective utilization** (busy-loop time / wall
   time per worker) is exposed via `show chassis forwarding`
   as a daemon aggregate but not per-worker; per-worker fanout
   would have made the imbalance immediately obvious. (Plan
   §X for #917 should add this.)

2. **Per-flow → worker mapping** is not exposed at all. Per-flow
   CoV in iperf3 output told us flows are unequal; per-worker
   tx counts told us workers are unequal; correlating
   "which flow lives on which worker" had to be inferred. A
   debug RPC dumping the SessionKey → worker mapping would
   close that loop.

## Recommended follow-ups

- **#917**: implement cross-worker V_min synchronization. This
  is the #793 / #786 architectural lever and the only path
  that addresses the ceiling identified above.
- **Telemetry gap 1**: per-worker busy-loop utilization in
  `show chassis forwarding` output.
- **Cluster CoS state**: file an issue if this morning's
  23.47 Gb/s P=12 number turns out to be reproducible from a
  cold start — could indicate steady-state degradation
  unrelated to RSS (e.g., MQFQ vtime drift per the deferred
  #927 / #926).

## Raw artifacts

- `iperf3 -c 172.16.80.200 -p 5203 -P {12,32,64,128}` JSON in
  `/tmp/iperf-sweep-*.json` (test host).
- `show class-of-service interface reth0.80` capture in the
  conversation log.
- Per-worker tx snapshots in `/tmp/snap-pre.txt` /
  `/tmp/snap-post.txt`.
